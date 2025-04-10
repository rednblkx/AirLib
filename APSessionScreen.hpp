#ifndef AP_SESSION_SCREEN_HPP
#define AP_SESSION_SCREEN_HPP
#pragma once

#include "APUtils.hpp"
#include "APTimeSync.hpp"
#include "IScreenStreamDelegate.hpp"
#include <array>
#include <atomic>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <sodium.h>
#include <vector>

namespace AirPlay {
namespace Session {
namespace Stream {

namespace net = boost::asio;
using tcp = net::ip::tcp;

// Configuration structure for the screen session
struct ScreenSessionConfig {
  int64_t latencyMs = 70; // Default latency
};

// Time Synchronizer structure (remains the same)
struct ScreenTimeSynchronizer {
  void *context = nullptr;
  std::function<std::optional<uint64_t>(void *)> getSynchronizedNTPTime;
  std::function<std::chrono::steady_clock::time_point(void *, uint64_t)>
      getSteadyTimeNearSynchronizedNTPTime;
};

class APScreenSession : public std::enable_shared_from_this<APScreenSession> {
public:
  /**
   * @brief Constructor. Sets up listening acceptor.
   * @param io_context The Boost.Asio io_context.
   * @param time_synchronizer Shared pointer to the time synchronizer.
   * @param dataTimeoutSecs Timeout in seconds for data socket inactivity.
   * @throws std::runtime_error if acceptor setup fails or crypto init fails.
   * @throws std::invalid_argument if time_synchronizer is null.
   */
  APScreenSession(net::io_context &io_context,
                  std::shared_ptr<APTimeSync> time_synchronizer,
                  int dataTimeoutSecs = 10);

  ~APScreenSession() noexcept;

  // Delete copy/move operations
  APScreenSession(const APScreenSession &) = delete;
  APScreenSession &operator=(const APScreenSession &) = delete;
  APScreenSession(APScreenSession &&) = delete;
  APScreenSession &operator=(APScreenSession &&) = delete;

  // --- Configuration (Call before startAccepting) ---

  /**
   * @brief Sets the delegate to receive screen events.
   * @param delegate Raw pointer to the delegate. The caller MUST ensure the
   * delegate outlives this session object.
   */
  void setDelegate(IScreenStreamDelegate *delegate);

  /**
   * @brief Configures the session based on stream description parameters.
   * @param config Configuration parameters.
   */
  void setup(const ScreenSessionConfig &config);

  /**
   * @brief Sets the security key for ChaCha20-Poly1305 decryption.
   * @param key The ChaCha20 key.
   */
  void setChaChaSecurityKey(
      const std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_KEYBYTES>
          &key);

  /**
   * @brief Sets the security key and IV for AES-128-CTR decryption.
   * @param key The AES key.
   * @param iv The AES initialization vector.
   * @throws std::runtime_error if OpenSSL context initialization fails.
   */
  void setAES_CTR_SecurityInfo(const std::array<uint8_t, 16> &key,
                               const std::array<uint8_t, 16> &iv);

  // --- Session Control ---

  /**
   * @brief Checks if the session is actively processing data.
   * @return True if running, false otherwise.
   */
  bool isRunning() const;

  /**
   * @brief Gets the TCP port number the session is listening on.
   * @return The data port number.
   */
  uint16_t getDataPort() const;

  /**
   * @brief Starts accepting the incoming data connection.
   */
  void startAccepting();

  /**
   * @brief Stops the session asynchronously. Closes sockets, cancels timers.
   *        Posts the stop logic to the io_context. Notifies delegate.
   */
  void stopSession();

private:
  // --- Asynchronous Handlers ---
  void handleAccept(const boost::system::error_code &ec, tcp::socket socket);
  void startDataReadHeader();
  void handleDataReadHeader(const boost::system::error_code &ec,
                            size_t bytes_transferred);
  void startDataReadBody(size_t bodySize);
  void handleDataReadBody(const boost::system::error_code &ec,
                          size_t bytes_transferred);
  void handleTimeout(const boost::system::error_code &ec);

  // --- Internal Logic ---
  void startProcessing(); // Called after successful accept
  void setupTimeSynchronizer();
  void cleanup(); // Idempotent cleanup function

  // --- Frame Processing ---
  void processFrame(APSHeader header, std::vector<uint8_t> &frameData);
  std::chrono::steady_clock::time_point
  calculateDisplayTime(const APSHeader &header,
                       const std::chrono::steady_clock::time_point &now);
  bool decryptFrame(const APSHeader &header, std::vector<uint8_t> &frameData,
                    size_t &decryptedSize);

  // --- Member Variables ---

  // Core Asio & Delegate
  net::io_context &m_io_context;
  IScreenStreamDelegate *m_delegate = nullptr; // Raw pointer: Owner manages lifetime!

  // Time Synchronization
  std::shared_ptr<APTimeSync> m_time_synchronizer;
  ScreenTimeSynchronizer m_screen_time_synchronizer; // Internal struct for callbacks

  // Networking
  tcp::acceptor m_acceptor;
  tcp::socket m_data_socket;
  uint16_t m_data_port = 0;
  net::steady_timer m_timeout_timer;
  std::chrono::seconds m_data_timeout_duration;

  // Session State
  std::atomic<bool> m_running{false};
  int64_t m_video_latency_ms = 70;
  bool m_respect_timestamps = false;

  // Statistics / Diagnostics
  std::atomic<uint32_t> m_frame_errors{0};
  std::atomic<uint32_t> m_negative_ahead_frames{0};
  std::atomic<uint32_t> m_late_frames{0};
  int64_t m_display_delta_ms = 0; // Debug: Lateness relative to ideal latency

  // Buffers
  APSHeader m_read_screen_header; // Buffer for incoming header
  std::vector<uint8_t> m_read_frame_buffer; // Buffer for incoming frame body

  // Security
  enum class SecurityMode { NONE, AES_CTR, CHACHA_POLY };
  SecurityMode m_security_mode = SecurityMode::NONE;

  // AES-CTR (OpenSSL)
  Utils::EvpCipherCtxPtr m_aes_ctx; // RAII wrapper for EVP_CIPHER_CTX
  std::array<uint8_t, 16> m_aes_key;
  std::array<uint8_t, 16> m_aes_iv;

  // ChaChaPoly (libsodium)
  Utils::StreamCryptor m_chacha_cryptor;
};

} // namespace Stream
} // namespace Session
} // namespace AirPlay

#endif // AP_SESSION_SCREEN_HPP