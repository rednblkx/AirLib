#include "server.hpp"
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>

void RTSPConnection::close_connection(
    const boost::system::error_code &reason_ec) {
  if (socket_.is_open()) {
    boost::system::error_code ignored_ec;
    socket_.shutdown(tcp::socket::shutdown_both, ignored_ec);
    socket_.close(ignored_ec);
    LOG_INFO("Connection closed: {}", reason_ec.message());
    delegate_.handleConnectionClosed(shared_from_this(), reason_ec);
    // Ensure no more operations are started by changing state
    state_ = State::Idle;
  }
}

void RTSPConnection::cancel_read_timer() {
  try {
    if (read_timer_.expiry() > std::chrono::steady_clock::now()) {
      read_timer_.cancel();
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Error canceling read timer: {}", e.what());
  }
}

void RTSPConnection::do_read_encrypted_header() {
  if (state_ != State::ReadingEncryptedHeader) {
    LOG_ERROR("Logic error: do_read_encrypted_header called in state {}",
              static_cast<int>(state_));
    return;
  }
  encrypted_header_buf_.resize(2); // Buffer for the 2-byte length
  auto self = shared_from_this();
  LOG_VERBOSE(
      "Entering do_read_encrypted_header. State: {}. Setting read timer ({}s).",
      static_cast<int>(state_), read_timeout_.count());

  // --- Timer Logic Start ---
  read_timer_.expires_after(read_timeout_);
  read_timer_.async_wait([self, this](const boost::system::error_code &ec) {
    if (!ec) { // Timer expired naturally
      LOG_WARN("Read encrypted header timeout expired. Closing connection");
      close_connection(boost::asio::error::make_error_code(boost::asio::error::basic_errors::connection_aborted));
    } else if (ec == net::error::operation_aborted) {
      LOG_VERBOSE(
          "Read encrypted header timer cancelled.");
    } else {
      LOG_ERROR("Read encrypted header timer error: {}", ec.message());
    }
  });
  // --- Timer Logic End ---
  net::async_read(
      socket_, net::buffer(encrypted_header_buf_), net::transfer_exactly(2),
      [self, this](boost::system::error_code ec,
                   std::size_t /*bytes_transferred*/) {
        // --- Cancel Timer ---
        cancel_read_timer();
        LOG_DEBUG("do_read_encrypted_header completed. Error: {}",
                  ec.message());
        if (!ec) {
          response_ready_ = true;
          uint16_t payload_length = boost::endian::load_little_u16(
              (uint8_t *)encrypted_header_buf_.data());
          LOG_DEBUG("Encrypted header read, payload length: {}",
                    payload_length);
          state_ = State::ReadingEncryptedBody;
          do_read_encrypted_body(payload_length);
        } else {
          LOG_ERROR("Error reading encrypted header: {}", ec.message());
          close_connection(ec);
        }
      });
}

void RTSPConnection::do_read_encrypted_body(uint16_t payload_length) {
  if (state_ != State::ReadingEncryptedBody) {
    LOG_ERROR("Logic error: do_read_encrypted_body called in state {}",
              static_cast<int>(state_));
    return;
  }
  LOG_DEBUG(
      "Entering do_read_encrypted_body. State: {}. Setting read timer ({}s).",
      static_cast<int>(state_), read_timeout_.count());
  size_t total_length_to_read =
      static_cast<size_t>(payload_length) + 16; // Payload + Poly1305 Tag
  auto self = shared_from_this();

  // --- Timer Logic Start ---
  read_timer_.expires_after(read_timeout_);
  read_timer_.async_wait([self, this](const boost::system::error_code &ec) {
    if (!ec) {
      LOG_WARN("Read encrypted body timeout expired. Closing connection");
			close_connection(boost::asio::error::make_error_code(boost::asio::error::basic_errors::connection_aborted));
    } else if (ec == net::error::operation_aborted) {
      LOG_VERBOSE("Read encrypted body timer cancelled.");
    } else {
      LOG_ERROR("Read encrypted body timer error: {}", ec.message());
    }
  });
  // --- Timer Logic End ---
  net::async_read(
      socket_, read_buffer_, net::transfer_exactly(total_length_to_read),
      [self, this, payload_length](boost::system::error_code ec,
                                   std::size_t bytes_transferred) {
        // --- Cancel Timer ---
        cancel_read_timer();
        LOG_DEBUG("do_read_encrypted_body completed. Error: {}", ec.message());
        if (!ec) {
          LOG_DEBUG("Encrypted body read ({}) bytes.", bytes_transferred);
          // Combine header and body for decryption context
          std::vector<char> full_encrypted_message = encrypted_header_buf_;
          const char *data_ptr =
              static_cast<const char *>(read_buffer_.data().data());
          full_encrypted_message.insert(full_encrypted_message.end(), data_ptr,
                                        data_ptr + bytes_transferred);
          read_buffer_.consume(bytes_transferred);

          boost::system::error_code decrypt_ec;
          std::vector<char> decrypted_payload =
              encryption_delegate_->decryptMessage(
                  full_encrypted_message, encryption_context_, decrypt_ec);

          if (!decrypt_ec) {
            LOG_DEBUG("Decryption successful ({}) bytes.",
                      decrypted_payload.size());
            current_request_.clear();
            LOG_DEBUG("Parsing decrypted RTSP message.");
            if (current_request_.parseRequest(decrypted_payload)) {
              LOG_DEBUG("Parsing successful. Proceeding to processing.");
              state_ = State::Processing;
              do_process_request();
            } else {
              LOG_ERROR("Failed to parse decrypted RTSP message.");
              close_connection(boost::system::errc::make_error_code(
                  boost::system::errc::bad_message));
            }
          } else {
            LOG_ERROR("Decryption failed: {}", decrypt_ec.message());
            close_connection(decrypt_ec);
          }
        } else {
          LOG_ERROR("Error reading encrypted body: {}", ec.message());
          close_connection(ec);
        }
      });
}

void RTSPConnection::do_read_headers() {
  if (state_ != State::ReadingHeaders) {
    LOG_ERROR("Logic error: do_read_headers called in state {}",
              static_cast<int>(state_));
    return;
  }
  auto self = shared_from_this();
  LOG_DEBUG("Entering do_read_headers. State: {}. Setting read timer ({}s).",
            static_cast<int>(state_), read_timeout_.count());

  // --- Timer Logic Start ---
  read_timer_.expires_after(read_timeout_);
  read_timer_.async_wait([self, this](const boost::system::error_code &ec) {
    if (!ec) { // Timer expired naturally
      LOG_WARN("Read headers timeout expired. Closing connection");
			close_connection(boost::asio::error::make_error_code(boost::asio::error::basic_errors::connection_aborted));
    } else if (ec == net::error::operation_aborted) {
      LOG_DEBUG("Read headers timer cancelled.");
    } else {
      LOG_ERROR("Read headers timer error: {}", ec.message());
    }
  });
  // --- Timer Logic End ---

  // Read until the double CRLF that marks the end of headers
  net::async_read_until(
      socket_, read_buffer_, "\r\n\r\n",
      [self, this](boost::system::error_code ec,
                   std::size_t bytes_transferred) {
        // --- Cancel Timer ---
        cancel_read_timer();
        LOG_DEBUG("do_read_headers completed. Error: {}", ec.message());
        if (!ec) {
          response_ready_ = true;
          LOG_DEBUG("Headers read ({}) bytes.", bytes_transferred);
          std::istream is(&read_buffer_);
          std::string headers_part(bytes_transferred, '\0');
          is.read(headers_part.data(), bytes_transferred);

          current_request_.clear();
          if (current_request_.parseRequestHeader(headers_part)) {
            auto it = current_request_.headers.find("Content-Length");
            size_t content_length = 0;
            if (it != current_request_.headers.end()) {
              try {
                content_length = std::stoul(it->second);
              } catch (const std::exception &e) {
                LOG_ERROR("Invalid Content-Length: {}", it->second);
                close_connection(boost::system::errc::make_error_code(
                    boost::system::errc::bad_message));
                return;
              }
            }

            LOG_DEBUG("Parsed headers, Content-Length: {}", content_length);

            if (content_length > 0) {
              state_ = State::ReadingBody;
              do_read_body(content_length);
            } else {
              LOG_DEBUG("No body, processing immediately");
              state_ = State::Processing;
              do_process_request();
            }
          } else {
            LOG_ERROR("Failed to parse RTSP headers.");
            close_connection(boost::system::errc::make_error_code(
                boost::system::errc::bad_message));
          }
        } else {
          LOG_ERROR("Error reading headers: {}", ec.message());
          close_connection(ec);
        }
      });
}

void RTSPConnection::do_read_body(size_t needed_bytes) {
  LOG_DEBUG(
      "Entering do_read_body. State: {}, Needed Bytes: {}, Buffer size: {}",
      static_cast<int>(state_), needed_bytes, read_buffer_.size());
  if (state_ != State::ReadingBody) {
    LOG_ERROR("Logic error: do_read_body called in state {}",
              static_cast<int>(state_));
    return;
  }

  // Calculate how many bytes are still needed
  size_t bytes_to_read = 0;
  if (read_buffer_.size() < needed_bytes) {
    bytes_to_read = needed_bytes - read_buffer_.size();
  } else {
    // Body is already fully in the buffer, process immediately
    LOG_DEBUG("Body already in buffer ({}), processing.", read_buffer_.size());
    // Extract exactly needed_bytes
    std::vector<char> body_data(needed_bytes);
    buffer_copy(net::buffer(body_data), read_buffer_.data(), needed_bytes);
    read_buffer_.consume(needed_bytes);

    if (current_request_.parseBody(body_data)) {
      state_ = State::Processing;
      do_process_request();
    } else {
      LOG_ERROR("Failed to parse RTSP body.");
      close_connection(boost::system::errc::make_error_code(
          boost::system::errc::bad_message));
    }
    return; // Don't proceed to async_read
  }

  if (bytes_to_read > 0) {
    LOG_DEBUG("Reading body ({}) bytes needed. Setting read timer ({}s).",
              bytes_to_read, read_timeout_.count());
    auto self = shared_from_this();

    // --- Timer Logic Start ---
    read_timer_.expires_after(read_timeout_);
    read_timer_.async_wait([self, this](const boost::system::error_code &ec) {
      if (!ec) {
        LOG_WARN("Read body timeout expired. Closing connection");
				close_connection(boost::asio::error::make_error_code(boost::asio::error::basic_errors::connection_aborted));
      } else if (ec == net::error::operation_aborted) {
        LOG_DEBUG("Read body timer cancelled.");
      } else {
        LOG_ERROR("Read body timer error: {}", ec.message());
      }
    });
    // --- Timer Logic End ---

    net::async_read(
        socket_, read_buffer_, net::transfer_exactly(bytes_to_read),
        [self, this, needed_bytes](boost::system::error_code ec,
                                   std::size_t /*bytes_transferred*/) {
          // --- Cancel Timer ---
          cancel_read_timer();
          // --- Handle Read Result ---
          LOG_DEBUG("do_read_body completed. Error: {}", ec.message());
          if (!ec) {
            LOG_DEBUG("Body read completely ({}) bytes now in buffer.",
                      read_buffer_.size());
            if (read_buffer_.size() >= needed_bytes) {
              // Extract exactly needed_bytes
              std::vector<char> body_data(needed_bytes);
              buffer_copy(net::buffer(body_data), read_buffer_.data(),
                          needed_bytes);
              read_buffer_.consume(needed_bytes);

              if (current_request_.parseBody(body_data)) {
                state_ = State::Processing;
                do_process_request();
              } else {
                LOG_ERROR("Failed to parse RTSP body.");
                close_connection(boost::system::errc::make_error_code(
                    boost::system::errc::bad_message));
              }
            } else {
              // Should not happen with transfer_exactly if calculation is right
              LOG_ERROR("Logic error: Read less body than expected.");
              close_connection(boost::system::errc::make_error_code(
                  boost::system::errc::io_error));
            }
          } else if (ec == net::error::operation_aborted) {
            LOG_WARN("Read body cancelled (likely timeout).");
            close_connection(ec);
          } else {
            LOG_ERROR("Error reading body: {}", ec.message());
            close_connection(ec);
          }
        });
  }
}

void RTSPConnection::do_process_request() {
  if (state_ != State::Processing) {
    LOG_ERROR("Logic error: do_process_request called in state {}",
              static_cast<int>(state_));
    return;
  }
  LOG_DEBUG("Processing request: {} {}", current_request_.method,
            current_request_.uri);
  RTSPMessage response_message;
  delegate_.handleMessage(current_request_, response_message,
                          shared_from_this(), encryption_context_);
  do_write(response_message);
}

void RTSPConnection::do_write(RTSPMessage &response_message) {
  if (state_ != State::Processing) {
    LOG_ERROR("Logic error: do_write called in state {}",
              static_cast<int>(state_));
    return;
  }
  state_ = State::Writing;
  response_ready_ = false;

  std::vector<char> serialized_response = response_message.constructResponse();

  if (encryption_delegate_ && encryption_context_.has_value() &&
      !next_message_plain_) {
    LOG_DEBUG("Encrypting response ({}) bytes plaintext.",
              serialized_response.size());
    boost::system::error_code encrypt_ec;
    write_buffer_ = encryption_delegate_->encryptMessage(
        serialized_response, encryption_context_, encrypt_ec);
    if (encrypt_ec) {
      LOG_ERROR("Encryption failed: {}", encrypt_ec.message());
      close_connection(encrypt_ec);
      return;
    }
    LOG_DEBUG("Encryption successful ({}) bytes ciphertext.",
              write_buffer_.size());
  } else {
    if (next_message_plain_) {
      LOG_DEBUG("Next message will be plaintext.");
      next_message_plain_ = false;
    }
    write_buffer_ = std::move(serialized_response);
  }

  if (write_buffer_.empty()) {
    LOG_ERROR("Error: Attempting to write empty buffer.");
    // Decide next state based on encryption status
    state_ = encryption_delegate_ ? State::ReadingEncryptedHeader
                                  : State::ReadingHeaders;
    if (state_ == State::ReadingEncryptedHeader)
      do_read_encrypted_header();
    else
      do_read_headers();
    return;
  }

  auto self = shared_from_this();
  net::async_write(
      socket_, net::buffer(write_buffer_),
      [self, this](boost::system::error_code ec, std::size_t bytes_written) {
        LOG_DEBUG("Write complete ({}) bytes, error: {}", bytes_written,
                  ec.message());
        delegate_.handleWriteComplete(self, self->encryption_context_,
                                      ec); // Notify delegate

        if (!ec) {
          // Decide next state based on encryption status
          state_ = encryption_delegate_ ? State::ReadingEncryptedHeader
                                        : State::ReadingHeaders;
          // Start reading the next request
          if (state_ == State::ReadingEncryptedHeader)
            do_read_encrypted_header();
          else
            do_read_headers();
        } else {
          close_connection(ec);
        }
      });
}

void RTSPServer::do_accept() {
  acceptor_.async_accept(net::bind_executor(
      strand_, [&](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
          LOG_INFO("Accepting new connection from {}",
                   socket.remote_endpoint().address().to_string());
          auto connection =
              std::make_shared<RTSPConnection>(std::move(socket), delegate_);
          delegate_.handleConnection(connection, server_context_);
          connection->start(); // Start reading the first request
        } else {
          // Don't stop accepting on recoverable errors if possible
          LOG_ERROR("Accept error: {}", ec.message());
          if (ec == net::error::operation_aborted) {
            return; // Server stopping
          }
        }

        // Continue accepting connections unless the acceptor was closed
        if (acceptor_.is_open()) {
          do_accept();
        }
      }));
}