#pragma once
#include "RTSPMessage.hpp"
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/detail/errc.hpp>
#include <memory>
#include <any>
#include "logger.hpp"

// Forward declarations
class RTSPConnection;
class RTSPServer;

namespace net = boost::asio;
using tcp = net::ip::tcp;
// --- Delegates ---

struct RTSPServerDelegate {
  virtual ~RTSPServerDelegate() = default;
  virtual void initializeServer(RTSPServer *) {}
  virtual void finalizeServer(RTSPServer *) {}
  virtual void handleConnection(std::shared_ptr<RTSPConnection>,
                                std::any server_context) {}
  // Operates on parsed messages
  virtual void handleMessage(const RTSPMessage &request, RTSPMessage &response,
                             std::shared_ptr<RTSPConnection> connection,
                              std::any connection_context) {
      // Default: Respond with 501 Not Implemented for RTSP
    std::cerr << "Unhandled RTSP message: " << request.method << " "
              << request.uri << std::endl;
    response.statusCode = 501;
    response.reasonPhrase = "Not Implemented";
    response.headers["Content-Length"] = "0";
    response.headers["Server"] = "ThingyThing/1.0"; // Example
  }
  virtual void handleWriteComplete(std::shared_ptr<RTSPConnection> connection,
                             std::any connection_context,
                             const boost::system::error_code& ec) {}
  virtual void handleConnectionClosed(std::shared_ptr<RTSPConnection> connection,
                                const boost::system::error_code& ec) {}
};

struct EncryptionDelegate {
    virtual ~EncryptionDelegate() = default;
    // Decrypts data in place or returns new vector. Needs context (keys).
    // Input: Raw bytes received (header + encrypted payload + tag)
    // Output: Decrypted payload (or empty on error)
    virtual std::vector<char> decryptMessage(const std::vector<char>& encrypted_data,
                                             std::any connection_context,
                                             boost::system::error_code& ec) = 0;

    // Encrypts data. Needs context (keys).
    // Input: Plaintext payload
    // Output: Encrypted message (header + encrypted payload + tag) (or empty on error)
    virtual std::vector<char> encryptMessage(const std::vector<char>& plaintext_payload,
                                             std::any connection_context,
                                             boost::system::error_code& ec) = 0;
};

// --- Connection Class ---

class RTSPConnection : public std::enable_shared_from_this<RTSPConnection> {
  enum class State { Idle, ReadingEncryptedHeader, ReadingEncryptedBody, ReadingHeaders, ReadingBody, Processing, Writing };

public:
  RTSPConnection(tcp::socket socket, RTSPServerDelegate &delegate)
      : socket_(std::move(socket)),
        delegate_(delegate),
        read_buffer_(65536),
        state_(State::Idle),
        read_timer_(socket_.get_executor()), // <<< Initialize timer with socket's executor
        read_timeout_(30)         // <<< Store timeout duration
         {}

  void start() {
      // Determine initial state (usually unencrypted)
      state_ = State::ReadingHeaders;
      do_read_headers();
  }

  void close() {
    close_connection(boost::system::error_code(boost::system::errc::success, boost::system::generic_category()));
  }

  void setEncryptionContext(std::any context) { encryption_context_ = std::move(context); }
  std::any& getEncryptionContext() { return encryption_context_; }

  void setConnectionContext(std::any context) { connection_context_ = std::move(context); }
  std::any& getConnectionContext() { return connection_context_; }

  // Enable encryption by providing the delegate
  void enableEncryption(EncryptionDelegate &enc_delegate, bool next_message_plain = false) {
    encryption_delegate_ = &enc_delegate;
    next_message_plain_ = next_message_plain;
    // Next read should expect encrypted format unlesss directed otherwise by next_message_plain
    if (state_ == State::Idle || state_ == State::ReadingHeaders || state_ == State::ReadingBody) {
        state_ = State::ReadingEncryptedHeader;
    }
     LOG_INFO("Encryption enabled for connection.");
  }

  void sendRequest(const RTSPMessage& request) {
    if (response_ready_) {
      current_request_ = request;
      state_ = State::Processing;
      do_write(current_request_);
    } else {
      LOG_ERROR("Response not ready to send another request.");
    }
  }

  tcp::socket& socket() { return socket_; }

private:
  void close_connection(const boost::system::error_code& reason_ec);
  void cancel_read_timer();


  // --- Read Logic ---

  void do_read_encrypted_header();

  void do_read_encrypted_body(uint16_t payload_length);

  void do_read_headers();

  void do_read_body(size_t needed_bytes);

  // --- Processing and Writing ---

  void do_process_request();

  void do_write(RTSPMessage& response_message);


  tcp::socket socket_;
  RTSPServerDelegate &delegate_;
  net::streambuf read_buffer_;
  std::vector<char> write_buffer_;
  std::vector<char> encrypted_header_buf_;
  RTSPMessage current_request_; // Holds the currently parsed request
  std::any connection_context_; // Per-connection context
  std::any encryption_context_; // Per-connection encryption context
  EncryptionDelegate *encryption_delegate_{nullptr};
  bool next_message_plain_{false};
  State state_;
  net::steady_timer read_timer_; // <<< Timer for read operations
  std::chrono::seconds read_timeout_; // <<< Timeout duration
  bool response_ready_{true};
};

// --- Server Class ---
class RTSPServer : public std::enable_shared_from_this<RTSPServer> {
public:
  RTSPServer(net::io_context &ioc, const tcp::endpoint &endpoint,
             RTSPServerDelegate &delegate)
      : ioc_(ioc), acceptor_(ioc), delegate_(delegate), server_context_(nullptr), strand_(net::make_strand(ioc)) { // Initialize server_context_
    LOG_INFO("Starting RTSP server on {} : {}", endpoint.address().to_string(), endpoint.port());
    boost::system::error_code ec;

    acceptor_.open(endpoint.protocol(), ec);
    if (ec) { throw std::runtime_error("Failed to open acceptor: " + ec.message()); }
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) { throw std::runtime_error("Failed to set reuse_address option: " + ec.message()); }
    if (endpoint.address().is_v6()) {
      acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
      if (ec) { throw std::runtime_error("Failed to set v6_only option: " + ec.message()); }
    }
    acceptor_.bind(endpoint, ec);
    if (ec) { throw std::runtime_error("Failed to bind to port: " + ec.message()); }
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) { throw std::runtime_error("Failed to start listening: " + ec.message()); }
    local_port_ = acceptor_.local_endpoint().port();
  }

  void run() {
    delegate_.initializeServer(this);
    do_accept();
  }

  void stop() {
    delegate_.finalizeServer(this);
    boost::system::error_code ec;
    acceptor_.close(ec);
    if (ec) {
      LOG_ERROR("Error closing acceptor: {}", ec.message());
    }
    LOG_INFO("RTSP server stopped.");
  }

  void setServerContext(std::any context) { server_context_ = std::move(context); }
  std::any& getServerContext() { return server_context_; }

  uint16_t getLocalPort() { return local_port_; }
private:
  void do_accept();

  net::strand<net::io_context::executor_type> strand_;
  net::io_context &ioc_;
  tcp::acceptor acceptor_;
  RTSPServerDelegate &delegate_;
  std::any server_context_;
  uint16_t local_port_;
};