#include "keepAliveManager.hpp"
#include "logger.hpp"
#include <boost/asio/ip/address.hpp>
#include <boost/asio/socket_base.hpp>

namespace AirPlay {
namespace Session {
// --- Constructor / Destructor ---

KeepAliveManager::KeepAliveManager(boost::asio::io_context &io_context,
                                   const udp::endpoint &peer_endpoint,
                                   SessionDiedDelegate session_died_delegate)
    : io_context_(io_context), keep_alive_socket_(io_context),
      timeout_timer_(io_context),
      peer_endpoint_(peer_endpoint), // Store peer address info if needed later
      local_port_(0), session_died_delegate_(std::move(session_died_delegate)) {
  LOG_INFO("KeepAliveManager created");
  if (!session_died_delegate_) {
    LOG_WARN("Session Died Delegate is not set!");
  }
}

KeepAliveManager::~KeepAliveManager() {
  LOG_INFO("Destructor called.");
  if (is_running_.load()) {
    try {
      stop();
    } catch (const std::exception &e) {
      LOG_ERROR("Exception during stop in destructor: {}", e.what());
    } catch (...) {
      LOG_ERROR("Unknown exception during stop in destructor.");
    }
  }
  LOG_INFO("Object destroyed.");
}

// --- Public Methods ---

void KeepAliveManager::initialize() {
  LOG_INFO("Initializing...");
  if (keep_alive_socket_.is_open()) {
    LOG_WARN("Already initialized.");
    return;
  }

  error_code ec;
  udp::endpoint local_endpoint(peer_endpoint_.protocol(),
                               kDefaultKeepAlivePort);

  keep_alive_socket_.open(local_endpoint.protocol(), ec);
  if (ec) {
    LOG_ERROR("Failed to open socket: {}", ec.message());
    throw boost::system::system_error(ec, "KeepAlive: Socket Open");
  }
  LOG_INFO("Socket opened successfully.");

  if (kSocketBufferSizeDontSet != -1) {
    boost::asio::socket_base::receive_buffer_size option(
        kSocketBufferSizeDontSet);
    keep_alive_socket_.set_option(option, ec);
    if (ec) {
      LOG_WARN("Failed to set socket receive buffer size: {}", ec.message());
    }
  }

  try {
    keep_alive_socket_.set_option(
        boost::asio::detail::socket_option::integer<IPPROTO_IP, IP_TOS>(0x20),
        ec);
    if (ec) {
      LOG_WARN("Failed to set socket QoS (TOS): {}", ec.message());
    } else {
      LOG_INFO("Socket QoS (TOS=32/CS1) set.");
    }
  } catch (const boost::system::system_error &e) {
    LOG_WARN("Setting socket QoS (TOS) failed: {}", e.what());
  }

  keep_alive_socket_.bind(local_endpoint, ec);
  if (ec) {
    LOG_ERROR("Failed to bind socket: {}", ec.message());
    keep_alive_socket_.close(); // Clean up
    throw boost::system::system_error(ec, "KeepAlive: Socket Bind");
  }

  local_port_ = keep_alive_socket_.local_endpoint().port();
  LOG_INFO("KeepAlive initialized. Listening on port {}", local_port_);
}

void KeepAliveManager::start() {
  LOG_INFO("Starting keep-alive monitoring...");
  if (is_running_.load()) {
    LOG_WARN("Already running.");
    return;
  }
  if (!keep_alive_socket_.is_open()) {
    LOG_ERROR("Cannot start, not initialized.");
    throw std::runtime_error("KeepAlive: Start called before initialize");
  }

  is_running_.store(true);
  start_receive_beacon();
  start_timeout_timer();
  LOG_INFO("KeepAlive monitoring started.");
}

void KeepAliveManager::stop() {
  LOG_INFO("Stopping keep-alive monitoring...");
  if (!is_running_.exchange(false)) {
    LOG_INFO("Already stopped.");
    return;
  }
  try {
    timeout_timer_.cancel();
  } catch (const std::exception &e) {
    LOG_ERROR("Error cancelling timer: {}", e.what());
  }

  error_code ec_close;
  if (keep_alive_socket_.is_open()) {
    keep_alive_socket_.close(ec_close);
    if (ec_close) {
      LOG_WARN("Error closing keep-alive socket: {}", ec_close.message());
    } else {
      LOG_INFO("Keep-alive socket closed.");
    }
  }

  LOG_INFO("KeepAlive monitoring stopped.");
}

unsigned short KeepAliveManager::get_local_port() const { return local_port_; }

// --- Private Methods ---

void KeepAliveManager::start_receive_beacon() {
  remote_endpoint_ = udp::endpoint();
  auto self = shared_from_this();
  keep_alive_socket_.async_receive_from(
      boost::asio::buffer(receive_buffer_), remote_endpoint_,
      [this, self](const error_code &ec, std::size_t bytes_recvd) {
        handle_receive_beacon(ec, bytes_recvd);
      });
  LOG_DEBUG("Asynchronous receive started.");
}

void KeepAliveManager::handle_receive_beacon(const error_code &ec,
                                             std::size_t bytes_recvd) {
  if (!is_running_.load()) {
    LOG_DEBUG("Received beacon handler called after stop. Ignoring.");
    return;
  }

  if (ec) {
    if (ec == boost::asio::error::operation_aborted) {
      LOG_INFO("Receive operation cancelled (likely stopping).");
    } else {
      LOG_ERROR("Socket receive error: {}", ec.message());
    }
    // Only restart receive if not aborted
    if (ec != boost::asio::error::operation_aborted) {
      start_receive_beacon();
    }
    return;
  }

  LOG_DEBUG("Received {} bytes from {}:{}", bytes_recvd,
            remote_endpoint_.address().to_string(), remote_endpoint_.port());

  process_beacon(receive_buffer_.data(), bytes_recvd);

  LOG_DEBUG("Resetting timeout timer due to received beacon.");
  start_timeout_timer();
  start_receive_beacon();
}

void KeepAliveManager::process_beacon(const char *data, size_t len) {
  std::string bytes_str;
  for (size_t i = 0; i < std::min(len, (size_t)4); ++i) {
    // Format each byte as 2-digit hex
    bytes_str += std::format(" {:02x}", static_cast<unsigned char>(data[i]));
  }
  LOG_INFO("Processing beacon (len={}):{}", len, bytes_str);

  if (len > 0) {
    uint8_t header_byte = static_cast<uint8_t>(data[0]);
    uint8_t version = extract_version(header_byte);
    bool sleep_flag = extract_sleep(header_byte);

    LOG_DEBUG("Beacon Version: {}, Sleep Flag: {}", version, sleep_flag);

    if (version == kLowPowerKeepAliveVersion && sleep_flag) {
      LOG_INFO("Received Low Power Keep Alive beacon with Sleep flag set.");
    }
  } else {
    LOG_WARN("Received empty UDP packet.");
  }
}

void KeepAliveManager::start_timeout_timer() {
  try {
    timeout_timer_.cancel();
  } catch (const std::exception &e) {
    LOG_ERROR("Error cancelling timer: {}", e.what());
  }

  timeout_timer_.expires_after(std::chrono::seconds(kAirPlayDataTimeoutSecs));

  LOG_DEBUG("Timeout timer set for {} seconds.", kAirPlayDataTimeoutSecs);

  auto self = shared_from_this();
  timeout_timer_.async_wait(
      [this, self](const error_code &ec) { handle_timeout(ec); });
}

void KeepAliveManager::handle_timeout(const error_code &ec) {
  if (ec == boost::asio::error::operation_aborted) {
    LOG_INFO("Keep-alive timer cancelled.");
    return;
  }

  if (ec) {
    LOG_ERROR("Keep-alive timer error: {}", ec.message());
  } else {
    LOG_ERROR("Keep alive timeout! No beacon received within {} seconds.",
              kAirPlayDataTimeoutSecs);
  }

  if (is_running_.load()) {
    LOG_INFO("Invoking Session Died delegate due to timeout/error.");
    try {
      session_died_delegate_();
    } catch (const std::exception &e) {
      LOG_ERROR("Exception in Session Died delegate: {}", e.what());
    } catch (...) {
      LOG_ERROR("Unknown exception in Session Died delegate.");
    }

    // Post stop to the io_context for safe handling
    boost::asio::post(io_context_, [this, self = shared_from_this()]() {
      if (is_running_.load()) {
        stop();
      }
    });
  } else {
    LOG_INFO("Timeout/timer error occurred but manager was already stopping.");
  }
}
} // namespace Session
} // namespace AirPlay