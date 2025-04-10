#include "client.hpp"
#include <boost/endian/conversion.hpp>

namespace AirPlay {
namespace RTSP {
namespace Client {

void RTSPClient::do_read_encrypted_header() {
  if (state_ != State::ReadingHeader)
    return;
  LOG_VERBOSE("Reading encrypted header (2 bytes)...");
  encrypted_header_buf_.resize(2);

  net::async_read(
      socket_, net::buffer(encrypted_header_buf_), net::transfer_exactly(2),
      net::bind_executor(strand_, [self = shared_from_this()](
                                      error_code ec, std::size_t /*bytes*/) {
        if (self->state_ != State::ReadingHeader)
          return; // Check state again
        if (!ec) {
          uint16_t payload_length = boost::endian::load_little_u16((uint8_t *)self->encrypted_header_buf_.data());
          LOG_VERBOSE("Encrypted header read, payload length: {}",
                      payload_length);
          self->state_ = State::ReadingBody; // Now read encrypted body
          self->do_read_encrypted_body(payload_length);
        } else {
          LOG_ERROR("Error reading encrypted header: {}", ec.message());
          self->response_timer_.cancel();
          self->enterErrorState(ec);
        }
      }));
}

void RTSPClient::do_read_encrypted_body(uint16_t payload_length) {
  if (state_ != State::ReadingBody)
    return;
  size_t total_length_to_read =
      static_cast<size_t>(payload_length) + 16; // Payload + Poly1305 Tag
  LOG_VERBOSE("Reading encrypted body ({} bytes)...", total_length_to_read);

  net::async_read(
      socket_, read_buffer_, net::transfer_exactly(total_length_to_read),
      net::bind_executor(strand_, [self = shared_from_this(), payload_length](
                                      error_code ec, std::size_t bytes_read) {
        if (self->state_ != State::ReadingBody)
          return;                       // Check state
        self->response_timer_.cancel(); // Got the full encrypted message

        if (!ec) {
          LOG_VERBOSE("Encrypted body read ({} bytes).", bytes_read);
          std::vector<char> full_encrypted_message =
              self->encrypted_header_buf_;
          const char *data_ptr =
              static_cast<const char *>(self->read_buffer_.data().data());
          full_encrypted_message.insert(full_encrypted_message.end(), data_ptr,
                                        data_ptr + bytes_read);
          self->read_buffer_.consume(bytes_read);

          error_code decrypt_ec;
          std::vector<char> decrypted_payload =
              self->encryption_delegate_->decryptMessage(
                  full_encrypted_message, self->encryption_context_,
                  decrypt_ec);

          if (!decrypt_ec) {
            LOG_VERBOSE("Decryption successful ({} bytes).",
                        decrypted_payload.size());
            if (self->current_response_.parseResponse(decrypted_payload)) {
              LOG_VERBOSE("Parsed decrypted RTSP response.");
              self->queueNextRequest(
                  ec); // Pass original read ec (should be success)
            } else {
              LOG_ERROR("Failed to parse decrypted RTSP response.");
              self->enterErrorState(boost::system::errc::make_error_code(
                  boost::system::errc::bad_message));
            }
          } else {
            LOG_ERROR("Decryption failed: {}", decrypt_ec.message());
            self->enterErrorState(decrypt_ec);
          }
        } else {
          LOG_ERROR("Error reading encrypted body: {}", ec.message());
          self->enterErrorState(ec);
        }
      }));
}

void RTSPClient::do_read_headers() {
  if (state_ != State::ReadingHeader)
    return;
  LOG_VERBOSE("Reading plain RTSP headers...");

  net::async_read_until(
      socket_, read_buffer_, "\r\n\r\n",
      net::bind_executor(strand_, [self = shared_from_this()](
                                      error_code ec, std::size_t bytes_read) {
        if (self->state_ != State::ReadingHeader)
          return;
        // Timer potentially still running for body read

        if (!ec) {
          LOG_VERBOSE("Headers read ({} bytes).", bytes_read);
          std::vector<char> header_data(bytes_read);
          buffer_copy(net::buffer(header_data), self->read_buffer_.data(),
                      bytes_read);
          self->read_buffer_.consume(bytes_read);

          if (self->current_response_.parseRequestHeader(
                  std::string(header_data.begin(), header_data.end()))) {
            auto it = self->current_response_.headers.find("Content-Length");
            size_t content_length = 0;
            if (it != self->current_response_.headers.end()) {
              try {
                content_length = std::stoul(it->second);
              } catch (const std::exception &e) {
                LOG_ERROR("Invalid Content-Length: {}", it->second);
                self->response_timer_.cancel();
                self->enterErrorState(boost::system::errc::make_error_code(
                    boost::system::errc::bad_message));
                return;
              }
            }
            LOG_VERBOSE("Parsed headers, Content-Length: {}", content_length);
            if (content_length > 0) {
              self->state_ = State::ReadingBody;
              self->do_read_body(content_length);
            } else {
              self->response_timer_.cancel();
              self->queueNextRequest(
                  ec); // Pass original read ec (success)
            }
          } else {
            LOG_ERROR("Failed to parse RTSP headers.");
            self->response_timer_.cancel();
            self->enterErrorState(boost::system::errc::make_error_code(
                boost::system::errc::bad_message));
          }
        } else {
          LOG_ERROR("Error reading headers: {}", ec.message());
          self->response_timer_.cancel();
          self->enterErrorState(ec);
        }
      }));
}

void RTSPClient::do_read_body(size_t needed_bytes) {
  if (state_ != State::ReadingBody)
    return;
  LOG_VERBOSE("Reading plain RTSP body ({} bytes needed)...", needed_bytes);

  size_t available = read_buffer_.size();
  size_t to_read = (available < needed_bytes) ? (needed_bytes - available) : 0;

  if (to_read == 0) {
    LOG_VERBOSE("Body already in buffer ({}), processing.", available);
    std::vector<char> body_data(needed_bytes);
    buffer_copy(net::buffer(body_data), read_buffer_.data(), needed_bytes);
    read_buffer_.consume(needed_bytes);

    if (current_response_.parseBody(body_data)) {
      response_timer_.cancel();
      queueNextRequest({}); // Success
    } else {
      LOG_ERROR("Failed to parse RTSP body.");
      response_timer_.cancel();
      enterErrorState(boost::system::errc::make_error_code(
          boost::system::errc::bad_message));
    }
    return;
  }

  LOG_VERBOSE("Need to read {} more bytes for body.", to_read);
  net::async_read(
      socket_, read_buffer_, net::transfer_exactly(to_read),
      net::bind_executor(
          strand_, [self = shared_from_this(),
                    needed_bytes](error_code ec, std::size_t /*bytes_read*/) {
            if (self->state_ != State::ReadingBody)
              return;
            self->response_timer_.cancel();

            if (!ec) {
              LOG_VERBOSE("Body read completely ({} bytes now in buffer).",
                          self->read_buffer_.size());
              if (self->read_buffer_.size() >= needed_bytes) {
                std::vector<char> body_data(needed_bytes);
                buffer_copy(net::buffer(body_data), self->read_buffer_.data(),
                            needed_bytes);
                self->read_buffer_.consume(needed_bytes);

                if (self->current_response_.parseBody(body_data)) {
                  self->queueNextRequest(
                      ec); // Pass original read ec (success)
                } else {
                  LOG_ERROR("Failed to parse RTSP body.");
                  self->enterErrorState(boost::system::errc::make_error_code(
                      boost::system::errc::bad_message));
                }
              } else {
                LOG_ERROR("Logic error: Read less body than expected.");
                self->enterErrorState(boost::system::errc::make_error_code(
                    boost::system::errc::io_error));
              }
            } else {
              LOG_ERROR("Error reading body: {}", ec.message());
              self->enterErrorState(ec);
            }
          }));
}

void RTSPClient::queueNextRequest(error_code ec) {
  if (outgoing_queue_.empty()) {
    LOG_ERROR("queueNextRequest called but queue is empty!");
    state_ = State::Connected;
    runStateMachine();
    return;
  }

  QueuedRequest completed = std::move(outgoing_queue_.front());
  outgoing_queue_.pop_front();

  if (completed.completion) {
    // Post completion to avoid long processing in strand handler
    net::post(strand_, [comp = std::move(completed.completion), ec,
                        resp = current_response_]() { comp(ec, resp); });
  }

  // If the socket is still open, transition back to connected.
  // If ec indicates a connection closure (e.g., EOF), enterErrorState should
  // have been called already.
  if (socket_.is_open() && state_ != State::Error) {
    state_ = State::Connected;
    LOG_VERBOSE("Response processed, returning to Connected state.");
    runStateMachine(); // Check queue for next request
  } else if (state_ != State::Error) {
    LOG_WARN(
        "Socket closed after response completion, but not in error state yet.");
    enterErrorState(
        ec ? ec
           : boost::system::errc::make_error_code(
                 boost::system::errc::connection_reset));
  }
}

void RTSPClient::failCurrentRequest(error_code ec) {
  if (!outgoing_queue_.empty()) {
    QueuedRequest &current = outgoing_queue_.front();
    if (current.completion) {
      net::post(strand_,
                [comp = std::move(current.completion), ec]() { comp(ec, {}); });
    }
    outgoing_queue_.pop_front();
  }
}

void RTSPClient::startResponseTimer(std::chrono::seconds timeout) {
  if (timeout == std::chrono::seconds::zero()) {
    return;
  }

  response_timer_.expires_after(timeout);
  response_timer_.async_wait(
      net::bind_executor(strand_, [self = shared_from_this()](error_code ec) {
        if (!ec) {
          LOG_WARN("Operation timed out.");
          error_code cancel_ec;
          // Cancel socket operations first
          if (self->socket_.is_open())
            self->socket_.cancel(cancel_ec);
          // Also cancel accept if listening
          if (self->acceptor_.is_open())
            self->acceptor_.cancel(cancel_ec);

          self->enterErrorState(boost::system::errc::make_error_code(
              boost::system::errc::timed_out));
        } else if (ec == net::error::operation_aborted) {
          LOG_VERBOSE("Response timer cancelled.");
        } else {
          LOG_ERROR("Response timer error: {}", ec.message());
        }
      }));
}

} // namespace Client
} // namespace RTSP
} // namespace AirPlay
