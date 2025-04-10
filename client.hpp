#pragma once

#include "RTSPMessage.hpp"
#include "logger.hpp"
#include <any>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/detail/errc.hpp>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace net = boost::asio;
using tcp = net::ip::tcp;
using boost::system::error_code;

namespace AirPlay {
namespace RTSP {
namespace Client {

// Forward declarations
class RTSPClient;

// --- Delegates & Callbacks (remain the same) ---

using RTSPRequestCompletionFunc =
    std::function<void(error_code ec, const RTSPMessage &response)>;

struct RTSPClientDelegate {
  virtual ~RTSPClientDelegate() = default;
  // Called when the client accepts a connection from the server
  virtual void onConnectionAccepted(RTSPClient * /*client*/,
                                    const tcp::endpoint & /*remote_endpoint*/) {
  }
  // Called when the established connection is closed or fails
  virtual void onConnectionClosed(RTSPClient * /*client*/,
                                  const error_code & /*ec*/) {}
};

struct EncryptionDelegate {
  virtual ~EncryptionDelegate() = default;
  virtual std::vector<char>
  decryptMessage(const std::vector<char> &encrypted_data,
                 std::any &connection_context, error_code &ec) = 0;
  virtual std::vector<char>
  encryptMessage(const std::vector<char> &plaintext_payload,
                 std::any &connection_context, error_code &ec) = 0;
};

struct QueuedRequest {
  RTSPMessage request;
  RTSPRequestCompletionFunc completion;
  std::chrono::steady_clock::time_point deadline;
};

// --- RTSP Client Class (Accepting Role) ---

class RTSPClient : public std::enable_shared_from_this<RTSPClient> {
  enum class State {
    Idle,         // Initial state, acceptor not open
    Listening,    // Acceptor is open and waiting for a connection
    Connected,    // Connection accepted, ready to send/receive
    Sending,      // Writing request data to socket
    ReadingHeader,// Reading RTSP response headers (or encrypted header)
    ReadingBody,  // Reading RTSP response body (or encrypted body)
    Error         // A non-recoverable error occurred
  };

public:
  // Constructor now takes the local endpoint to listen on
  RTSPClient(net::io_context &ioc, const tcp::endpoint &local_endpoint,
             RTSPClientDelegate *delegate = nullptr)
      : ioc_(ioc), strand_(net::make_strand(ioc)),
        acceptor_(strand_, local_endpoint.protocol()), // Initialize acceptor on strand
        socket_(strand_), delegate_(delegate), state_(State::Idle),
        read_buffer_(65536), response_timer_(strand_),
        local_endpoint_(local_endpoint) // Store local endpoint if needed later
  {
    error_code ec;
    // Configure and bind the acceptor (error handling needed)
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) { /* Handle error */
      LOG_ERROR("Failed to set reuse_address: {}", ec.message());
      throw std::runtime_error("Failed to set reuse_address: " + ec.message());
    }
    if (local_endpoint.address().is_v6()) {
      acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
      if (ec) { throw std::runtime_error("Failed to set v6_only option: " + ec.message()); }
    }
    acceptor_.bind(local_endpoint_, ec);
    if (ec) { /* Handle error */
      LOG_ERROR("Failed to bind acceptor to {}:{}: {}",
                local_endpoint.address().to_string(), local_endpoint.port(),
                ec.message());
      throw std::runtime_error("Failed to bind acceptor: " + ec.message());
    }
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) { /* Handle error */
      LOG_ERROR("Failed to listen on acceptor: {}", ec.message());
      throw std::runtime_error("Failed to listen on acceptor: " + ec.message());
    }
    LOG_INFO("RTSPClient acceptor listening on {}:{}",
             acceptor_.local_endpoint().address().to_string(),
             acceptor_.local_endpoint().port());
  }

  ~RTSPClient() {
    LOG_DEBUG("RTSPClient (accepting role) destructor called.");
    if (state_ != State::Idle && state_ != State::Error) {
      error_code ignored_ec;
      stop_internal(ignored_ec);
    }
  }

  // Start listening for the incoming connection from the server
  void startAccepting() {
    // Post to strand to ensure state change and accept happens safely
    net::post(strand_, [self = shared_from_this()]() {
      if (self->state_ == State::Idle && self->acceptor_.is_open()) {
        self->state_ = State::Listening;
        self->doAccept();
      } else {
        LOG_WARN("Cannot start accepting, state is {} or acceptor not open.",
                 static_cast<int>(self->state_));
      }
    });
  }

  // Configure timeouts (in seconds)
  void setResponseTimeout(std::chrono::seconds timeout) {
    // Ensure this happens safely if called concurrently
    net::post(strand_, [self = shared_from_this(), timeout]() {
      self->response_timeout_ = timeout;
    });
  }

  // Enable encryption (must be called before connection is accepted)
  void enableEncryption(EncryptionDelegate *enc_delegate, std::any context) {
    net::post(strand_, [self = shared_from_this(), enc_delegate,
                        ctx = std::move(context)]() mutable {
      if (self->state_ == State::Idle || self->state_ == State::Listening) {
        self->encryption_delegate_ = enc_delegate;
        self->encryption_context_ = std::move(ctx);
        LOG_INFO("Encryption enabled for next accepted connection.");
      } else {
        LOG_WARN("Cannot change encryption settings after connection.");
      }
    });
  }

  // Send an RTSP request asynchronously (only works after connection)
  void sendMessage(RTSPMessage request, RTSPRequestCompletionFunc completion) {
    net::post(strand_, [self = shared_from_this(), req = std::move(request),
                        comp = std::move(completion)]() mutable {
      self->queueRequest(std::move(req), std::move(comp));
    });
  }

  // Stop the client, close acceptor and socket, cancel operations
  void stop() {
    net::post(strand_, [self = shared_from_this()]() {
      self->stop_internal(
          boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
    });
  }

  uint16_t getLocalPort() const {
      // Access acceptor directly as it should be initialized
      // No strand needed for read-only access to endpoint after bind
      error_code ec;
      auto ep = acceptor_.local_endpoint(ec);
      return ec ? 0 : ep.port();
  }


private:
  // --- Accept Logic ---
  void doAccept() {
    if (state_ != State::Listening) {
      LOG_WARN("doAccept called but not in Listening state.");
      return;
    }

    LOG_INFO("Waiting for incoming RTSP connection...");
    // Acceptor is already on the strand, but handler runs on strand too
    acceptor_.async_accept(
        socket_, // Accept into the client's main socket
        net::bind_executor(
            strand_,
            [self = shared_from_this()](error_code ec) { self->handleAccept(ec); }));
  }

  void handleAccept(error_code ec) {
    if (state_ != State::Listening) {
      // Could happen if stop() was called concurrently
      LOG_INFO("Accept handler called but state is no longer Listening.");
      return;
    }

    if (!acceptor_.is_open()) {
        LOG_INFO("Accept handler called but acceptor is closed.");
        return; // Acceptor was closed, likely during stop()
    }


    if (!ec) {
      // --- Connection Accepted Successfully ---
      tcp::endpoint remote_ep;
      error_code ep_ec;
      remote_ep = socket_.remote_endpoint(ep_ec);
      if(ep_ec) {
          LOG_ERROR("Failed to get remote endpoint after accept: {}", ep_ec.message());
          // Close the socket we just accepted
          error_code ignored_ec;
          socket_.close(ignored_ec);
          // Optionally, go back to listening? Or enter error state?
          // For now, let's try accepting again.
          doAccept();
          return;
      }


      LOG_INFO("Connection accepted from {}", remote_ep.address().to_string());
      state_ = State::Connected;

      // Stop accepting further connections (we only handle one)
      error_code close_ec;
      acceptor_.close(close_ec);
      if(close_ec) LOG_WARN("Error closing acceptor: {}", close_ec.message());
      // Notify delegate
      if (delegate_) {
        delegate_->onConnectionAccepted(this, remote_ep);
      }

      // Start processing the queue if messages were added before connection
      runStateMachine();

    } else {
      LOG_ERROR("Accept failed: {}", ec.message());
      // Don't enter general error state unless accept error is fatal
      // Keep listening if possible (e.g., if error was connection_aborted)
      if (ec != net::error::operation_aborted && acceptor_.is_open()) {
        // Try accepting again
        doAccept();
      } else {
          // Acceptor closed or fatal error, enter error state
          enterErrorState(ec);
      }
    }
  }

  // --- State Management and Core Logic ---
  void queueRequest(RTSPMessage request, RTSPRequestCompletionFunc completion) {
    if (state_ == State::Error) {
      LOG_ERROR("Client is in error state, cannot send message.");
      net::post(strand_, [comp = std::move(completion)]() {
        comp(boost::system::errc::make_error_code(
                 boost::system::errc::operation_not_permitted),
             {});
      });
      return;
    }
    if (state_ != State::Connected && state_ != State::Sending &&
        state_ != State::ReadingHeader && state_ != State::ReadingBody) {
      // Allow queuing even if busy sending/reading previous message
      LOG_WARN("Queueing request while not connected (state: {}). "
               "Will send after connection.",
               static_cast<int>(state_));
      // Don't reject, just queue it. runStateMachine will handle it later.
    }

    LOG_DEBUG("Queueing request: {} {}", request.method, request.uri);
    outgoing_queue_.emplace_back(QueuedRequest{
        std::move(request), std::move(completion),
        std::chrono::steady_clock::now() + response_timeout_});

    // If connected and not busy, start sending immediately
    if (state_ == State::Connected) {
      runStateMachine();
    }
  }

  void runStateMachine(error_code ec = {}) {
    if (ec && state_ != State::Listening) { // Don't error out on accept errors handled in handleAccept
      LOG_ERROR("State machine received error: {}", ec.message());
      enterErrorState(ec);
      return;
    }

    switch (state_) {
    case State::Idle:
      // Waiting for startAccepting()
      break;
    case State::Listening:
      // Waiting for handleAccept()
      break;
    case State::Connected:
      if (!outgoing_queue_.empty()) {
        startSend();
      } else {
        LOG_VERBOSE("Connected and idle.");
        // If connected and idle, should we start reading for unsolicited
        // messages? Or only read after sending a request?
        // Current design only reads in response to a sent request.
        // To handle unsolicited messages, we'd need to start reading here.
      }
      break;
    case State::Sending:
      // Waiting for async_write to complete
      break;
    case State::ReadingHeader:
    case State::ReadingBody:
      // Waiting for async_read to complete
      break;
    case State::Error:
      // Do nothing
      break;
    }
  }

  void enterErrorState(error_code ec) {
    if (state_ == State::Error)
      return;

    LOG_WARN("Entering error state: {}", ec.message());
    State previous_state = state_;
    state_ = State::Error;

    // Cancel timers
    response_timer_.cancel();

    // Close acceptor
    if (acceptor_.is_open()) {
        error_code ignored_ec;
        acceptor_.close(ignored_ec);
    }

    // Close socket
    if (socket_.is_open()) {
      error_code ignored_ec;
      socket_.shutdown(tcp::socket::shutdown_both, ignored_ec);
      socket_.close(ignored_ec);
    }

    // Notify delegate about disconnection
    if (delegate_ && (previous_state == State::Connected ||
                      previous_state == State::Sending ||
                      previous_state == State::ReadingHeader ||
                      previous_state == State::ReadingBody)) {
      delegate_->onConnectionClosed(this, ec);
    }

    // Fail any pending requests
    failPendingRequests(ec);
  }

  void failPendingRequests(error_code ec) {
    std::deque<QueuedRequest> failed_queue;
    failed_queue.swap(outgoing_queue_);

    for (auto &queued : failed_queue) {
      if (queued.completion) {
        net::post(strand_, [comp = std::move(queued.completion), ec]() {
          comp(ec, {});
        });
      }
    }
  }

  void stop_internal(error_code reason) {
    LOG_INFO("Stopping RTSPClient (accepting role): {}", reason.message());
    // Use error state logic for cleanup, ensuring acceptor is closed too
    if (acceptor_.is_open()) {
        error_code ignored_ec;
        // Cancel pending accept operations before closing
        acceptor_.cancel(ignored_ec);
        acceptor_.close(ignored_ec); // Close acceptor added here
    }
    // enterErrorState will handle socket, timer, and pending requests
    enterErrorState(reason);
  }

  // --- Send Logic (mostly unchanged) ---
  void startSend() {
    if (outgoing_queue_.empty()) {
      LOG_WARN("startSend called with empty queue.");
      state_ = State::Connected;
      runStateMachine();
      return;
    }
     if (state_ != State::Connected) {
        LOG_ERROR("Cannot send, not connected (state: {})", static_cast<int>(state_));
        // Should not happen if runStateMachine logic is correct
        return;
    }

    state_ = State::Sending;
    current_response_.clear();

    QueuedRequest &current = outgoing_queue_.front();
    LOG_DEBUG("Sending request: {} {}", current.request.method,
              current.request.uri);

    std::vector<char> serialized_request = current.request.constructRequest();

    if (encryption_delegate_) {
      LOG_VERBOSE("Encrypting request ({} bytes plaintext)",
                  serialized_request.size());
      error_code encrypt_ec;
      write_buffer_ = encryption_delegate_->encryptMessage(
          serialized_request, encryption_context_, encrypt_ec);
      if (encrypt_ec) {
        LOG_ERROR("Encryption failed: {}", encrypt_ec.message());
        failCurrentRequest(encrypt_ec);
        enterErrorState(encrypt_ec);
        return;
      }
      LOG_VERBOSE("Encryption successful ({} bytes ciphertext)",
                  write_buffer_.size());
    } else {
      write_buffer_ = std::move(serialized_request);
    }

    if (write_buffer_.empty()) {
      LOG_ERROR("Attempting to write empty buffer.");
      failCurrentRequest(boost::system::errc::make_error_code(
          boost::system::errc::invalid_argument));
      state_ = State::Connected;
      runStateMachine();
      return;
    }

    startResponseTimer(response_timeout_);

    net::async_write(
        socket_, net::buffer(write_buffer_),
        net::bind_executor(
            strand_, [self = shared_from_this()](error_code ec,
                                                 std::size_t bytes_written) {
              if (self->state_ != State::Sending)
                return;

              if (ec) {
                LOG_ERROR("Send failed: {}", ec.message());
                self->response_timer_.cancel();
                self->enterErrorState(ec);
                return;
              }

              LOG_VERBOSE("Send successful.");
              self->startRead(); // Move to reading the response
          }));
  }

  // --- Read Logic ---
  void startRead() {
    if (encryption_delegate_) {
      state_ = State::ReadingHeader;
      do_read_encrypted_header();
    } else {
      state_ = State::ReadingHeader;
      do_read_headers();
    }
  }
  void do_read_encrypted_header();
  void do_read_encrypted_body(uint16_t payload_length);
  void do_read_headers();
  void do_read_body(size_t needed_bytes);

  // --- Response Handling ---
  void queueNextRequest(error_code ec);
  void failCurrentRequest(error_code ec);

  // --- Timer Logic ---
  void startResponseTimer(std::chrono::seconds timeout);

  // --- Member Variables ---
  net::io_context &ioc_;
  net::strand<net::io_context::executor_type> strand_;
  tcp::acceptor acceptor_; // Acceptor for incoming connection
  tcp::socket socket_;     // Socket for the accepted connection
  RTSPClientDelegate *delegate_;
  EncryptionDelegate *encryption_delegate_{nullptr};
  std::any encryption_context_;

  tcp::endpoint local_endpoint_; // Store the endpoint we are listening on
  std::chrono::seconds response_timeout_{std::chrono::seconds(30)};

  State state_;
  std::deque<QueuedRequest> outgoing_queue_;

  net::streambuf read_buffer_;
  std::vector<char> write_buffer_;
  std::vector<char> encrypted_header_buf_;
  RTSPMessage current_response_;

  net::steady_timer response_timer_;
};

} // namespace Client
} // namespace RTSP
} // namespace AirPlay