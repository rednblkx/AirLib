#include "APSessionScreen.hpp"
#include "logger.hpp"
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind/bind.hpp> // For boost::bind / placeholders
#include <chrono>
#include <cstring> // For memcpy
#include <memory>  // For std::move
#include <openssl/err.h> // For OpenSSL error reporting
#include <sodium.h>
#include <stdexcept>
#include <vector>

// Define constants
constexpr size_t AES_KEY_SIZE = 16;
constexpr size_t AES_IV_SIZE = 16;
constexpr size_t MAX_FRAME_SIZE = 10 * 1024 * 1024; // 10 MiB sanity limit

namespace AirPlay {
namespace Session {
namespace Stream {

namespace net = boost::asio;
using tcp = net::ip::tcp;
using boost::placeholders::_1;
using boost::placeholders::_2;
using namespace std::chrono_literals; // For ms, s suffixes

// --- Constructor and Destructor ---

APScreenSession::APScreenSession(
    net::io_context &io_context,
    std::shared_ptr<APTimeSync> time_synchronizer,
    int dataTimeoutSecs)
    : m_io_context(io_context),
      m_time_synchronizer(std::move(time_synchronizer)),
      m_acceptor(io_context),
      m_data_socket(io_context),
      m_timeout_timer(io_context),
      m_aes_ctx(Utils::EvpCipherCtxPtr(EVP_CIPHER_CTX_new())), // Use RAII wrapper
      m_data_timeout_duration(dataTimeoutSecs > 0 ? std::chrono::seconds(dataTimeoutSecs) : 60s),
      m_chacha_cryptor(true) // incrementNonce = true
{
  if (!m_time_synchronizer) {
    throw std::invalid_argument("TimeSynchronizer cannot be null");
  }
  if (!m_aes_ctx) {
    // Should not happen if EVP_CIPHER_CTX_new succeeds
    throw std::runtime_error("Failed to allocate EVP_CIPHER_CTX");
  }

  // Ensure libsodium is initialized (ideally call once globally)
  if (sodium_init() < 0) {
    // sodium_init() returns 0 on success, 1 if already initialized, -1 on error
    // errno is not typically set by sodium_init
    throw std::runtime_error("Failed to initialize libsodium");
  }

  setupTimeSynchronizer();

  // Setup TCP acceptor
  boost::system::error_code ec;
  tcp::endpoint endpoint(tcp::v6(), 0); // Listen on IPv4, OS chooses port

  m_acceptor.open(endpoint.protocol(), ec);
  if (ec) {
    throw std::runtime_error("Failed to open acceptor: " + ec.message());
  }

  // Set socket options on the acceptor (these often influence accepted sockets)
  m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
  if (ec) {
    LOG_WARN("Failed to set reuse_address on acceptor: {}", ec.message());
    // Non-fatal, continue
  }

  if (endpoint.address().is_v6()) {
    m_acceptor.set_option(boost::asio::ip::v6_only(false), ec);
    if (ec) { throw std::runtime_error("Failed to set v6_only option: " + ec.message()); }
  }  // Set QoS/TOS - This might require specific privileges
  m_acceptor.set_option(
      boost::asio::detail::socket_option::integer<IPPROTO_IP, IP_TOS>(0x80), ec);
  if (ec) {
    LOG_WARN("Failed to set socket QoS (TOS=0x80/CS4): {}. Check privileges.",
             ec.message());
  } else {
    LOG_DEBUG("Acceptor QoS (TOS=0x80/CS4) set.");
  }

  m_acceptor.bind(endpoint, ec);
  if (ec) {
    m_acceptor.close(); // Clean up on failure
    throw std::runtime_error("Failed to bind acceptor: " + ec.message());
  }

  m_acceptor.listen(net::socket_base::max_listen_connections, ec);
  if (ec) {
    m_acceptor.close(); // Clean up on failure
    throw std::runtime_error("Failed to listen on acceptor: " + ec.message());
  }

  m_data_port = m_acceptor.local_endpoint().port();
  LOG_INFO("APScreenSession created. Listening for data on port {}", m_data_port);
}

APScreenSession::~APScreenSession() noexcept {
  LOG_INFO("APScreenSession destroying (port {})...", m_data_port);
  // Cleanup should ideally be triggered by stopSession before destruction.
  // Calling cleanup() here ensures resources are released if stopSession wasn't
  // called or completed. It's designed to be idempotent.
  cleanup();
  // Securely zero keys (RAII for crypto contexts handles their cleanup)
  std::memset(m_aes_key.data(), 0, m_aes_key.size());
  std::memset(m_aes_iv.data(), 0, m_aes_iv.size());
  // m_chacha_cryptor handles its key zeroing in its destructor if implemented
  LOG_INFO("APScreenSession destroyed (port {}).", m_data_port);
}

// --- Configuration ---

void APScreenSession::setDelegate(IScreenStreamDelegate *delegate) {
  // Ensure this is called before the session starts processing data
  if (m_running) {
      LOG_WARN("Attempted to set delegate while session is running.");
      // Decide if this should be an error or just a warning
  }
  m_delegate = delegate;
}

void APScreenSession::setup(const ScreenSessionConfig &config) {
  LOG_INFO("Configuring screen session. Latency: {} ms", config.latencyMs);
  m_video_latency_ms = config.latencyMs;
  // Apply other config parameters from the struct here
  // e.g., m_respect_timestamps = config.respectTimestamps;
}

void APScreenSession::setChaChaSecurityKey(
    const std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_KEYBYTES>
        &key) {
  LOG_INFO("Setting security mode to ChaCha20-Poly1305");
  m_security_mode = SecurityMode::CHACHA_POLY;
  m_chacha_cryptor.initReadKey(key.data());
  // Reset AES context if it was active (to avoid accidental use)
  if (m_aes_ctx) {
    EVP_CIPHER_CTX_reset(m_aes_ctx.get());
  }
  // Securely clear AES keys if they were previously set
  std::memset(m_aes_key.data(), 0, m_aes_key.size());
  std::memset(m_aes_iv.data(), 0, m_aes_iv.size());
}

void APScreenSession::setAES_CTR_SecurityInfo(
    const std::array<uint8_t, AES_KEY_SIZE> &key,
    const std::array<uint8_t, AES_IV_SIZE> &iv) {
  LOG_INFO("Setting security mode to AES-128-CTR");
  m_security_mode = SecurityMode::AES_CTR;
  m_aes_key = key; // Store for potential re-init if needed (e.g., context reset)
  m_aes_iv = iv;

  if (!m_aes_ctx) {
    // This should not happen due to constructor check, but defensively...
    throw std::runtime_error("AES context is null during security info setup");
  }

  // Initialize OpenSSL EVP context for AES-128-CTR decryption
  // Note: EVP_Decrypt* functions are used for CTR decryption as well.
  // We re-initialize context here.
  if (EVP_DecryptInit_ex(m_aes_ctx.get(), EVP_aes_128_ctr(), nullptr,
                         key.data(), iv.data()) != 1) {
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    LOG_ERROR("Failed to initialize AES-128-CTR context: {}", err_buf);
    throw std::runtime_error(
        "Failed to initialize AES-128-CTR context (EVP_DecryptInit_ex)");
  }
  // No padding needed for CTR mode (usually default)
  // EVP_CIPHER_CTX_set_padding(m_aes_ctx.get(), 0);

  // Invalidate ChaCha key state if it was active
  m_chacha_cryptor.keyPresent = false;
}

// --- Time Synchronizer Setup ---

void APScreenSession::setupTimeSynchronizer() {
  // Store the raw pointer to the synchronizer object.
  // The shared_ptr member ensures the object itself stays alive.
  m_screen_time_synchronizer.context = m_time_synchronizer.get();

  // Lambda to get NTP time
  m_screen_time_synchronizer.getSynchronizedNTPTime =
      [](void *context) -> std::optional<uint64_t> {
    if (!context) return std::nullopt;
    auto *ts = static_cast<APTimeSync *>(context);
    // Add checks if ts might not be ready/negotiated if applicable
    // if (!ts->isReady()) return std::nullopt;
    return ts->getSynchronizedNtpTime();
  };

  // Lambda to convert NTP to steady_clock time_point
  m_screen_time_synchronizer.getSteadyTimeNearSynchronizedNTPTime =
      [](void *context,
         uint64_t ntpTime) -> std::chrono::steady_clock::time_point {
    if (!context) return std::chrono::steady_clock::time_point::min();
    auto *ts = static_cast<APTimeSync *>(context);
    // Add checks if ts might not be ready/negotiated if applicable
    // if (!ts->isReady()) return std::chrono::steady_clock::time_point::min();
    return std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(
            ts->getTicksNearSynchronizedNtpTime(ntpTime)));
  };
}

// --- Session Control ---

bool APScreenSession::isRunning() const { return m_running.load(); }

uint16_t APScreenSession::getDataPort() const { return m_data_port; }

void APScreenSession::startAccepting() {
  // Check if already running or acceptor closed prematurely
  if (m_running || !m_acceptor.is_open()) {
    LOG_WARN("Session already running or acceptor not open (port {}). Cannot "
             "start accepting.", m_data_port);
    return;
  }

  LOG_INFO("Waiting for screen data connection on port {}...", m_data_port);
  m_acceptor.async_accept(
      // Capture shared_from_this to keep session alive during async op
      [this, self = shared_from_this()](const boost::system::error_code &ec,
                                        tcp::socket socket) {
        handleAccept(ec, std::move(socket));
      });
}

void APScreenSession::handleAccept(const boost::system::error_code &ec,
                                   tcp::socket socket) {
  // If acceptor is closed, it means stopSession was called concurrently.
  if (!m_acceptor.is_open()) {
    LOG_INFO("Accept handler called but acceptor is closed (session likely "
             "stopped).");
    // Close the newly accepted socket if it's open
    if (socket.is_open()) {
        boost::system::error_code ignored_ec;
        socket.close(ignored_ec);
    }
    return;
  }

  // Close the acceptor now, we only expect one data connection.
  boost::system::error_code close_ec;
  m_acceptor.close(close_ec);
  if (close_ec) {
    LOG_WARN("Failed to close acceptor: {}", close_ec.message());
  }

  if (!ec) {
    try {
      auto remote_ep = socket.remote_endpoint();
      LOG_INFO("Screen data connection accepted from {}:{}",
               remote_ep.address().to_string(), remote_ep.port());

      // Move the accepted socket to be the data socket for this session
      m_data_socket = std::move(socket);

      // Start the internal processing (reading data, timer)
      startProcessing();

    } catch (const boost::system::system_error &e) {
        // Catch potential exceptions from remote_endpoint() if socket closes unexpectedly
        LOG_ERROR("Error getting remote endpoint after accept: {}", e.what());
        boost::system::error_code ignored_ec;
        if (m_data_socket.is_open()) m_data_socket.close(ignored_ec);
        stopSession(); // Stop the session logic (will notify delegate)
    } catch (const std::exception &e) {
      LOG_ERROR("Error starting processing after accept: {}", e.what());
      boost::system::error_code ignored_ec;
      if (m_data_socket.is_open()) m_data_socket.close(ignored_ec);
      stopSession(); // Stop the session logic (will notify delegate)
    }
  } else {
    // Accept failed (e.g., connection reset before accept, resource exhaustion)
    LOG_ERROR("Screen data accept error: {}", ec.message());
    // Don't call stopSession here directly, as the session never fully started.
    // Let the owner know via delegate if appropriate, or just log.
    // If a delegate is set, maybe notify it? Depends on desired behavior.
    // For now, just log. The session remains in a non-running state.
    // Ensure socket is closed if somehow opened before error.
    if (socket.is_open()) {
        boost::system::error_code ignored_ec;
        socket.close(ignored_ec);
    }
  }
}

void APScreenSession::startProcessing() {
  if (m_running) {
    LOG_WARN("Session processing already started (port {})", m_data_port);
    return;
  }

  LOG_INFO("Starting screen session processing (port {})...", m_data_port);

  // Reset state variables
  m_late_frames = 0;
  m_negative_ahead_frames = 0;
  m_frame_errors = 0;
  m_display_delta_ms = 0;

  // Post the actual start logic to the io_context to ensure
  // it runs on the correct strand if strands are used later.
  net::post(m_io_context, [this, self = shared_from_this()]() {
    if (!m_data_socket.is_open()) {
        LOG_ERROR("Cannot start processing, data socket is not open.");
        // Don't set m_running to true
        return;
    }
    m_running = true; // Set running state *before* starting async ops

    // Start reading the first header
    startDataReadHeader();

    // Start the inactivity timer
    m_timeout_timer.expires_after(m_data_timeout_duration);
    m_timeout_timer.async_wait(
        [this, self](const boost::system::error_code &ec) {
          // We only care if the timer expires naturally, not if cancelled.
          if (ec != net::error::operation_aborted) {
            handleTimeout(ec);
          }
        });
  });
}

void APScreenSession::stopSession() {
  // Use post to ensure thread safety and run on the io_context thread.
  net::post(m_io_context, [this, self = shared_from_this()]() {
    // Use exchange to atomically check and set m_running to false.
    // If it was already false, we are already stopping or stopped.
    if (!m_running.exchange(false)) {
      // If acceptor is still open (e.g., stop called before connection)
      if (m_acceptor.is_open()) {
        boost::system::error_code ec;
        m_acceptor.cancel(ec);
        m_acceptor.close(ec);
      }
      return; // Already stopped or stopping
    }

    LOG_INFO("Stopping screen session (port {})...", m_data_port);
    cleanup(); // Perform cleanup on the io_context thread

    // Notify delegate *after* cleanup is complete
    if (m_delegate) {
      m_delegate->onSessionStopped();
    }
    LOG_INFO("Screen session stopped (port {}).", m_data_port);
  });
}

void APScreenSession::cleanup() {
  // This function must be idempotent and safe to call multiple times.
  // It should run on the io_context thread (called from stopSession or destructor).
  LOG_DEBUG("Cleaning up screen session resources (port {})...", m_data_port);

  boost::system::error_code ec;

  // Cancel the timeout timer
  m_timeout_timer.cancel();
  if (ec) {
    // Log error but continue cleanup
    LOG_WARN("Error cancelling timeout timer: {}", ec.message());
  }

  // Cancel and close acceptor if it's somehow still open
  if (m_acceptor.is_open()) {
    m_acceptor.cancel(ec); // Cancel pending async_accept
    if (ec) LOG_WARN("Error cancelling acceptor: {}", ec.message());
    m_acceptor.close(ec);
    if (ec) LOG_WARN("Error closing acceptor: {}", ec.message());
  }

  // Shutdown and close the data socket
  if (m_data_socket.is_open()) {
    // Shutdown may fail if socket is not connected, ignore error
    m_data_socket.shutdown(tcp::socket::shutdown_both, ec);
    // Close the socket
    m_data_socket.close(ec);
    if (ec) {
      LOG_WARN("Error closing data socket: {}", ec.message());
    }
  }

  // Reset crypto contexts (RAII handles actual cleanup)
  if (m_aes_ctx) {
    EVP_CIPHER_CTX_reset(m_aes_ctx.get());
  }
  m_security_mode = SecurityMode::NONE;
  // m_chacha_cryptor state might need explicit reset if it holds state

  LOG_DEBUG("Screen session resource cleanup complete (port {}).", m_data_port);
}

// --- Data Handling ---

void APScreenSession::startDataReadHeader() {
  if (!m_running || !m_data_socket.is_open()) return;

  // Reset timer before starting async read
  m_timeout_timer.expires_after(m_data_timeout_duration);
  m_timeout_timer.async_wait(
      [this, self = shared_from_this()](const boost::system::error_code &ec) {
        if (ec != net::error::operation_aborted) {
          handleTimeout(ec);
        }
      });

  // Read exactly the size of the header struct
  net::async_read(
      m_data_socket,
      net::buffer(&m_read_screen_header, sizeof(m_read_screen_header)),
      // Use boost::bind for member function handler
      boost::bind(&APScreenSession::handleDataReadHeader, shared_from_this(),
                  _1, // placeholder for error_code
                  _2  // placeholder for bytes_transferred
                  ));
}

void APScreenSession::handleDataReadHeader(const boost::system::error_code &ec,
                                           size_t bytes_transferred) {
  // If session stopped while read was pending, do nothing.
  if (!m_running) return;

  // Cancel the timer regardless of read success or failure
  m_timeout_timer.cancel();

  if (ec) {
    if (ec == net::error::eof) {
      LOG_INFO("Data socket closed by peer (EOF). Stopping session.");
    } else if (ec != net::error::operation_aborted) {
      // Log real errors, ignore operation_aborted caused by stopSession
      LOG_ERROR("Data socket read header error: {}", ec.message());
    }
    // Stop session on any error/EOF unless it was aborted by stopSession itself
    if (ec != net::error::operation_aborted) {
      stopSession();
    }
    return;
  }

  // async_read guarantees bytes_transferred == sizeof(header) if ec is not set
  // No need to check bytes_transferred explicitly here.

  // TODO: Validate header contents if necessary (e.g., magic numbers, flags)
  // if (!isValidHeader(m_read_screen_header)) { ... stopSession(); return; }

  size_t bodySize = m_read_screen_header.bodySize;

  // Proceed to read the body
  startDataReadBody(bodySize);
}

void APScreenSession::startDataReadBody(size_t bodySize) {
  if (!m_running || !m_data_socket.is_open()) return;

  // Reset timer
  m_timeout_timer.expires_after(m_data_timeout_duration);
  m_timeout_timer.async_wait(
      [this, self = shared_from_this()](const boost::system::error_code &ec) {
        if (ec != net::error::operation_aborted) {
          handleTimeout(ec);
        }
      });

  // Handle zero-size body (e.g., heartbeat or config frame with no payload)
  if (bodySize == 0) {
    std::vector<uint8_t> emptyBody;
    // Process frame immediately. Pass header by value (copy) as the member
    // m_read_screen_header might be overwritten by the next header read
    // before this processing finishes if delegate is slow.
    APSHeader headerCopy = m_read_screen_header;
    processFrame(headerCopy, emptyBody);

    // If still running, start reading the next header
    if (m_running) {
      startDataReadHeader();
    }
    return;
  }

  // Validate body size against a reasonable maximum
  if (bodySize > MAX_FRAME_SIZE) {
    LOG_ERROR("Requested frame body size too large: {} bytes (max: {})",
              bodySize, MAX_FRAME_SIZE);
    m_timeout_timer.cancel(); // Cancel timer before stopping
    stopSession();
    return;
  }

  // Resize buffer for the body
  try {
    m_read_frame_buffer.resize(bodySize);
  } catch (const std::bad_alloc &) {
    LOG_ERROR("Failed to allocate frame buffer ({} bytes)", bodySize);
    m_timeout_timer.cancel();
    stopSession();
    return;
  } catch (const std::length_error &) {
    LOG_ERROR("Failed to resize frame buffer ({} bytes) - likely too large",
              bodySize);
    m_timeout_timer.cancel();
    stopSession();
    return;
  }

  // Read exactly bodySize bytes into the buffer
  net::async_read(
      m_data_socket, net::buffer(m_read_frame_buffer.data(), bodySize),
      boost::bind(&APScreenSession::handleDataReadBody, shared_from_this(), _1,
                  _2));
}

void APScreenSession::handleDataReadBody(const boost::system::error_code &ec,
                                         size_t bytes_transferred) {
  if (!m_running) return;

  m_timeout_timer.cancel();

  if (ec) {
    if (ec == net::error::eof) {
      LOG_INFO("Data socket closed by peer (EOF) while reading body. Stopping "
               "session.");
    } else if (ec != net::error::operation_aborted) {
      LOG_ERROR("Data socket read body error: {}", ec.message());
    }
    if (ec != net::error::operation_aborted) {
      stopSession();
    }
    return;
  }

  // async_read guarantees bytes_transferred == bodySize if no error.

  // Process the complete frame (header + body).
  // Pass header by value (copy) for safety, as explained in startDataReadBody.
  APSHeader headerCopy = m_read_screen_header;
  processFrame(headerCopy, m_read_frame_buffer); // Pass buffer by reference

  // If still running, start reading the next header
  if (m_running) {
    startDataReadHeader();
  }
}

void APScreenSession::handleTimeout(const boost::system::error_code &ec) {
  // This handler is called only if the timer expires naturally or if there's
  // a timer error. It's not called if the timer is cancelled.
  if (!m_running) return; // Session already stopped

  if (ec) {
    // An unexpected error occurred with the timer itself
    LOG_ERROR("Timeout timer error: {}", ec.message());
  } else {
    // Timer expired - no data received in time
    LOG_WARN("Data socket timeout after {} seconds. Stopping session.",
             m_data_timeout_duration.count());
  }
  stopSession(); // Stop the session due to timeout or timer error
}

// --- Frame Processing Logic ---

std::chrono::steady_clock::time_point APScreenSession::calculateDisplayTime(
    const APSHeader &header, const std::chrono::steady_clock::time_point &now) {
  using namespace std::chrono;

  // Default to now + latency if timestamps are not used or unavailable
  steady_clock::time_point displayTime = now + milliseconds(m_video_latency_ms);

  if (m_respect_timestamps &&
      m_screen_time_synchronizer.getSteadyTimeNearSynchronizedNTPTime) {
    // Attempt to convert NTP timestamp from header (param[0].u64) to local steady_clock
    steady_clock::time_point ntpBasedTime =
        m_screen_time_synchronizer.getSteadyTimeNearSynchronizedNTPTime(
            m_screen_time_synchronizer.context, header.params[0].u64);

    // Check if conversion was successful
    if (ntpBasedTime != steady_clock::time_point::min()) {
      // Apply latency offset to the synchronized time
      displayTime = ntpBasedTime + milliseconds(m_video_latency_ms);
    } else {
      LOG_WARN("Failed to get valid display time from NTP {}, using fallback.",
               header.params[0].u64);
      // Fallback already set above
    }
  }

  // --- Calculate Diagnostics (Lateness/Aheadness) ---
  auto timeDiff = displayTime - now;
  int64_t currentDeltaMs = duration_cast<milliseconds>(timeDiff).count();

  if (currentDeltaMs < 0) {
      // Frame's calculated display time is in the past
      m_display_delta_ms = currentDeltaMs; // Negative value indicates lateness
      m_negative_ahead_frames++;
      // Log less frequently or adjust level to avoid spamming
      if (m_negative_ahead_frames % 100 == 1) { // Log every 100 late frames
          LOG_WARN("Frame display time is {} ms in the past ({} total past frames)",
                   -m_display_delta_ms, m_negative_ahead_frames.load());
      }
  } else {
      // Frame's display time is in the future (or now)
      // Calculate lateness relative to the *ideal* arrival time (now + latency)
      // This definition seems slightly off in the original code.
      // Let's redefine m_display_delta_ms as the difference between actual arrival
      // and the *ideal* arrival time based on the timestamp.
      // ideal_arrival = displayTime - latency
      // lateness = now - ideal_arrival = now - (displayTime - latency)
      // This seems complex. Let's stick to the original intent:
      // How late is the frame relative to its *scheduled* display time?
      // If displayTime < now, it's late by (now - displayTime).
      // Let's keep m_display_delta_ms as the time difference relative to now.
      m_display_delta_ms = currentDeltaMs; // Positive value indicates time until display

      // Check if frame arrived significantly later than expected (relative to latency target)
      // This check seems more about jitter/delay variation.
      // If currentDeltaMs is much smaller than m_video_latency_ms, it arrived late.
      int64_t arrival_lateness = m_video_latency_ms - currentDeltaMs;
      if (arrival_lateness > 50) { // Example threshold: >50ms later than ideal arrival
          m_late_frames++;
          if (m_late_frames % 100 == 1) { // Log periodically
              LOG_INFO("Frame arrived ~{} ms late relative to target latency ({} total late)",
                       arrival_lateness, m_late_frames.load());
          }
      }
  }

  return displayTime;
}

bool APScreenSession::decryptFrame(const APSHeader &header,
                                   std::vector<uint8_t> &frameData,
                                   size_t &decryptedSize) {
  decryptedSize = frameData.size(); // Default if no decryption

  if (m_security_mode == SecurityMode::CHACHA_POLY) {
    if (!m_chacha_cryptor.keyPresent) {
      LOG_ERROR("ChaChaPoly decryption failed: Key not initialized");
      return false;
    }
    bool success = m_chacha_cryptor.decrypt(
        reinterpret_cast<const uint8_t *>(&header), sizeof(header), // AAD
        frameData.data(), frameData.size(), // Input ciphertext
        frameData.data(),                   // Output buffer (in-place)
        decryptedSize, // Output: actual decrypted size
        false          // Don't increment nonce here if header contains it
    );
    if (!success) {
      LOG_ERROR("ChaChaPoly decryption failed (MAC check failed?)");
      return false;
    }
    // Resize vector to actual decrypted size (important for Poly1305 tag removal)
    if (decryptedSize != frameData.size()) {
        try {
            frameData.resize(decryptedSize);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to resize frame buffer after ChaChaPoly decryption: {}", e.what());
            return false;
        }
    }

  } else if (m_security_mode == SecurityMode::AES_CTR) {
    if (!frameData.empty()) { // No decryption needed for empty body
      if (!m_aes_ctx) {
        LOG_ERROR("AES-CTR decryption failed: Context not initialized");
        return false;
      }
      int outLen = 0;
      // EVP_DecryptUpdate can decrypt in-place if out == in
      if (EVP_DecryptUpdate(m_aes_ctx.get(),
                            frameData.data(), // Output buffer
                            &outLen,          // Output length
                            frameData.data(), // Input buffer
                            frameData.size()  // Input length
                            ) != 1) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        LOG_ERROR("AES-CTR decryption failed (EVP_DecryptUpdate): {}", err_buf);
        return false;
      }
      // For CTR mode, outLen should equal input length. No finalization needed
      // per packet unless handling partial blocks across calls (unlikely here).
      if (static_cast<size_t>(outLen) != frameData.size()) {
        LOG_WARN("AES-CTR output size ({}) differs from input size ({})", outLen,
                 frameData.size());
        return false;
      }
      decryptedSize = outLen; // Should be same as input size
    } else {
      decryptedSize = 0; // Empty input -> empty output
    }
  }
  // If security mode is NONE, decryptedSize remains frameData.size()

  return true; // Decryption successful (or not needed)
}

void APScreenSession::processFrame(APSHeader header,
                                   std::vector<uint8_t> &frameData) {
  using namespace std::chrono;
  steady_clock::time_point nowTime = steady_clock::now();

  try {
    switch (header.opcode) {
    case 0: { // Video data frame
      // Calculate Display Time
      steady_clock::time_point displayTime = calculateDisplayTime(header, nowTime);

      // Decrypt Frame Data (in-place)
      size_t decryptedSize = 0; // Will be updated by decryptFrame
      if (!decryptFrame(header, frameData, decryptedSize)) {
        // Decryption failed, error already logged by decryptFrame
        m_frame_errors++;
        LOG_ERROR("Dropping frame due to decryption error ({} total errors)",
                  m_frame_errors.load());
        return; // Skip processing this frame
      }
      // frameData vector might have been resized by decryptFrame

      // Pass data to delegate
      if (m_delegate) {
        // Pass the calculated display time point's epoch count
        m_delegate->onVideoData(header, frameData,
                                displayTime.time_since_epoch().count());
      } else {
        LOG_WARN("No delegate set, dropping video frame.");
      }
      break;
    }

    case 1: { // Video config frame (e.g., SPS/PPS)
      // Config frames are typically not encrypted.
      m_respect_timestamps = (header.smallParam[1] & 2) != 0;
      float width = header.params[1].f32[0];
      float height = header.params[1].f32[1];
      LOG_INFO("Received video config frame. Respect Timestamps: {}, Res: {}x{}",
               m_respect_timestamps, static_cast<int>(width), static_cast<int>(height));

      if (m_delegate) {
        m_delegate->onVideoConfig(header, width, height, frameData);
      } else {
        LOG_WARN("No delegate set, dropping config frame.");
      }
      break;
    }

    case 2: // Heartbeat?
    case 4: // Unknown/Reserved?
    case 5: // Unknown/Reserved?
      LOG_DEBUG("Ignoring screen opcode: {}", header.opcode);
      // No action needed for these known-ignorable opcodes
      break;

    default:
      LOG_WARN("Unknown screen opcode received: {}", header.opcode);
      break;
    }

  } catch (const std::exception &e) {
    m_frame_errors++;
    LOG_ERROR("Exception processing frame (opcode {}, {} total errors): {}",
              header.opcode, m_frame_errors.load(), e.what());
    // Decide if error is fatal. For now, log and continue.
  }
}

} // namespace Stream
} // namespace Session
} // namespace AirPlay