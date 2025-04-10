#ifndef KEEP_ALIVE_MANAGER_H
#define KEEP_ALIVE_MANAGER_H

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <atomic>
#include <functional>
#include <memory>
using udp = boost::asio::ip::udp;
using boost::system::error_code;

namespace AirPlay {
namespace Session {
// Delegate type for session died notification
using SessionDiedDelegate = std::function<void()>;

class KeepAliveManager : public std::enable_shared_from_this<KeepAliveManager> {
  public:
    // Constants (can be configured)
    static constexpr short kDefaultKeepAlivePort = 0; // Bind to any available port
    static constexpr int kSocketBufferSizeDontSet = -1;
    static constexpr int kAirPlayDataTimeoutSecs = 30;
    static constexpr size_t kMaxBeaconPacketSize = 32;

    // Constructor: Takes the io_context, peer endpoint, and the delegate
    KeepAliveManager(boost::asio::io_context &io_context,
                     const udp::endpoint &peer_endpoint,
                     SessionDiedDelegate session_died_delegate = []() { /* Default empty delegate */ });

    ~KeepAliveManager();

    // Prevent copy/move semantics for simplicity managing resources
    KeepAliveManager(const KeepAliveManager &) = delete;
    KeepAliveManager &operator=(const KeepAliveManager &) = delete;
    KeepAliveManager(KeepAliveManager &&) = delete;
    KeepAliveManager &operator=(KeepAliveManager &&) = delete;

    // Initializes resources (socket) - throws on failure
    void initialize();

    // Starts the keep-alive monitoring thread and operations
    void start();

    // Stops the keep-alive monitoring thread and operations
    void stop();

    // Returns the local port used by the keep-alive socket
    unsigned short get_local_port() const;

  private:
    // Asynchronous operations
    void start_receive_beacon();
    void handle_receive_beacon(const error_code &ec, std::size_t bytes_recvd);
    void process_beacon(const char *data, size_t len);

    void start_timeout_timer();
    void handle_timeout(const error_code &ec);

    // Core components
    boost::asio::io_context &io_context_; // Use external io_context
    udp::socket keep_alive_socket_;
    boost::asio::steady_timer timeout_timer_;
    udp::endpoint peer_endpoint_; // Keep track of the peer we expect beacons from
    udp::endpoint remote_endpoint_; // Endpoint of the actual sender
    std::array<char, kMaxBeaconPacketSize> receive_buffer_;

    // State
    unsigned short local_port_;
    std::atomic<bool> is_running_{false};
    SessionDiedDelegate session_died_delegate_;

    // Constants for beacon processing
    static constexpr uint8_t kLowPowerKeepAliveVersion = 0;
    static uint8_t extract_version(uint8_t fields) {
        return (fields >> 6) & 0x03;
    }
    static bool extract_sleep(uint8_t fields) {
        return ((fields >> 5) & 0x01) != 0;
    }
};

} // namespace Session
} // namespace AirPlay

#endif // KEEP_ALIVE_MANAGER_H