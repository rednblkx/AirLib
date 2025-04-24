#ifndef EVENT_CONNECTION_BOOST_HPP
#define EVENT_CONNECTION_BOOST_HPP

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <memory>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <array>
#include "PairingUtils.hpp"
#include "client.hpp"

namespace AirPlay {
namespace Server {
class APServer;
} // namespace Server
} // namespace AirPlay

namespace AirPlay {
  namespace Session {
    // Forward declarations
    class APSession;

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using boost::system::error_code;

    const char kAirPlayPairingEventsKeySaltPtr[] = "Events-Salt";
    const size_t kAirPlayPairingEventsKeySaltLen = sizeof(kAirPlayPairingEventsKeySaltPtr) -1;
    const char kAirPlayPairingEventsKeyReadInfoPtr[] = "Events-Read-Encryption-Key";
    const size_t kAirPlayPairingEventsKeyReadInfoLen = sizeof(kAirPlayPairingEventsKeyReadInfoPtr) - 1;
    const char kAirPlayPairingEventsKeyWriteInfoPtr[] = "Events-Write-Encryption-Key";
    const size_t kAirPlayPairingEventsKeyWriteInfoLen = sizeof(kAirPlayPairingEventsKeyWriteInfoPtr) - 1;
    const size_t kEventKeySize = 32; // ChaCha20 key size
    const size_t kEventNonceSize = 12; // ChaCha20-Poly1305 nonce size (96 bits)
    const size_t kEventTagSize = 16; // Poly1305 tag size

    class EventConnectionBoost : public RTSP::Client::RTSPClientDelegate, public RTSP::Client::EncryptionDelegate, public std::enable_shared_from_this<EventConnectionBoost> {
    public:
        // Callback for received data (likely a plist body)
        using ReceiveHandler = std::function<void(const std::vector<char>& data)>;

        EventConnectionBoost(net::io_context& io_context);
        ~EventConnectionBoost();

        // Disable copy/move
        EventConnectionBoost(const EventConnectionBoost&) = delete;
        EventConnectionBoost& operator=(const EventConnectionBoost&) = delete;

        void onConnectionAccepted(RTSP::Client::RTSPClient* server, const tcp::endpoint& remote_endpoint) override;
        void onConnectionClosed(RTSP::Client::RTSPClient* server, const error_code& ec) override;

        // Start accepting the single incoming connection
        void start();
        void stop();
        // Configure encryption keys based on a verified pairing session
        bool configure_encryption(PairingSession* pairing_session);
        // Send a command (plist data) asynchronously
        void send_command_async(const std::vector<char>& plist_data);

        uint16_t get_local_port() { return local_port_; }

    private:
        void handle_write(const error_code& ec, std::size_t bytes_transferred, std::shared_ptr<std::vector<uint8_t>> send_buffer);

        std::vector<char> decryptMessage(const std::vector<char>& encrypted_data, std::any &connection_context, boost::system::error_code& ec) override;
        std::vector<char> encryptMessage(const std::vector<char>& plaintext_data, std::any &connection_context, boost::system::error_code& ec) override;

        // --- Encryption Helpers ---
        bool encrypt(const uint8_t* plaintext, size_t plaintext_len,
                    const uint8_t* aad, size_t aad_len,
                    std::vector<uint8_t>& ciphertext_out); // Appends ciphertext + tag

        bool decrypt(const uint8_t* ciphertext, size_t ciphertext_len, // Includes tag
                    const uint8_t* aad, size_t aad_len,
                    std::vector<uint8_t>& plaintext_out);

        net::io_context& io_context_;
        std::shared_ptr<RTSP::Client::RTSPClient> server_;
        uint16_t local_port_;
        ReceiveHandler receive_handler_; // Callback for incoming data/events

        std::atomic<bool> running_;
        std::atomic<bool> encryption_enabled_;

        // Encryption state
        std::vector<uint8_t> read_key_;
        std::vector<uint8_t> write_key_;
        std::array<uint8_t, kEventNonceSize> read_nonce_;
        std::array<uint8_t, kEventNonceSize> write_nonce_;
    };
  } // namespace Session
} // namespace AirPlay

#endif // EVENT_CONNECTION_BOOST_HPP