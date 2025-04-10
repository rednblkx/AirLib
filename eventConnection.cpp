#include "eventConnection.hpp"
#include <boost/endian/conversion.hpp>
#include <sodium/crypto_aead_chacha20poly1305.h>

namespace AirPlay {
  namespace Session {
    struct TransportContext {
    std::vector<uint8_t> inputKey;
    std::vector<uint8_t> outputKey;
    uint8_t inputNonce[12];
    uint8_t outputNonce[12];
    };
    EventConnectionBoost::EventConnectionBoost(net::io_context& io_context) :
        io_context_(io_context),
        local_port_(0),
        running_(false),
        encryption_enabled_(false)
    {
        // Initialize nonces to zero (or random if required by protocol)
        read_nonce_.fill(0);
        write_nonce_.fill(0);
        LOG_INFO("EventConnectionBoost created.");
        server_ = std::make_shared<RTSP::Client::RTSPClient>(io_context_, tcp::endpoint(tcp::v6(), 0), this);
        local_port_ = server_->getLocalPort();
    }

    EventConnectionBoost::~EventConnectionBoost() {
        server_->stop();
    }

    void EventConnectionBoost::start() {
        server_->startAccepting();
    }

    void EventConnectionBoost::stop() {
        server_->stop();
    }

    void EventConnectionBoost::onConnectionAccepted(RTSP::Client::RTSPClient* server, const tcp::endpoint& remote_endpoint) {
        LOG_INFO("EventConnectionBoost::onConnectionAccepted");
    }

    void EventConnectionBoost::onConnectionClosed(RTSP::Client::RTSPClient* server, const error_code& ec) {
        LOG_INFO("EventConnectionBoost::onConnectionClosed");
    }

    bool EventConnectionBoost::configure_encryption(PairingSession* pairing_session) {
        if (!pairing_session) {
              LOG_ERROR("Event Encryption: Invalid pairing session provided.");
              return false;
        }
        if (encryption_enabled_) {
              LOG_INFO("Event Encryption: Already configured.");
              return true;
        }

        LOG_INFO("Configuring Event Connection encryption...");

        TransportContext *transportCtx = new TransportContext; // Use unique_ptr

        // Derive Read Key (Accessory Reads -> Sender Writes)
        transportCtx->outputKey.resize(32);
        int err = pairing_session->deriveKey(
            std::string_view(kAirPlayPairingEventsKeySaltPtr, kAirPlayPairingEventsKeySaltLen),
            std::string_view(kAirPlayPairingEventsKeyReadInfoPtr, kAirPlayPairingEventsKeyReadInfoLen),
            32,
            transportCtx->outputKey);
        if (err != 0) {
            LOG_ERROR("Event Encryption: Failed to derive read key: {}", err);
            transportCtx->outputKey.clear();
            return false;
        }

        // Derive Write Key (Accessory Writes -> Sender Reads)
        transportCtx->inputKey.resize(32);
        err = pairing_session->deriveKey(
            std::string_view(kAirPlayPairingEventsKeySaltPtr, kAirPlayPairingEventsKeySaltLen),
            std::string_view(kAirPlayPairingEventsKeyWriteInfoPtr, kAirPlayPairingEventsKeyWriteInfoLen),
            32,
            transportCtx->inputKey);
        if (err != 0) {
            LOG_ERROR("Event Encryption: Failed to derive write key: {}", err);
            transportCtx->outputKey.clear();
            transportCtx->inputKey.clear();
            return false;
        }

        read_nonce_.fill(0);
        write_nonce_.fill(0);
        memset(transportCtx->inputNonce, 0, sizeof(transportCtx->inputNonce));
        memset(transportCtx->outputNonce, 0, sizeof(transportCtx->outputNonce));

        // Tell the connection to use this APServer instance for encryption
        server_->enableEncryption(this, transportCtx);

        encryption_enabled_ = true;
        LOG_INFO("Event Connection encryption configured successfully.");
        return true;
    }

    void EventConnectionBoost::send_command_async(const std::vector<char>& plist_data) {
        // Post the actual send operation to the strand
        net::post(io_context_, [this, plist_data]() mutable {
            RTSPMessage message;
            message.method = "POST";
            message.uri = "/command";
            message.version = "RTSP/1.0";
            message.statusCode = 200;
            message.reasonPhrase = "OK";
            message.headers["Content-Type"] = "application/x-apple-binary-plist";
            message.payload = plist_data;
            message.print();
            server_->sendMessage(message, [this](error_code ec, const RTSPMessage& response) {
                if (ec) {
                    LOG_ERROR("Event Write: Error: {}", ec.message());
                } else {
                    LOG_DEBUG("Event Response: Successfully received");
                    response.print();
                }
            });
        });
    }

    void EventConnectionBoost::handle_write(const error_code& ec, std::size_t bytes_transferred, std::shared_ptr<std::vector<uint8_t>> /*send_buffer*/) {

        if (!running_) return; // Stopped

        if (ec) {
            LOG_ERROR("Event Write: Error: {}", ec.message());
        } else {
            LOG_INFO("Event Write: Successfully sent {} bytes.", bytes_transferred);
            // Write successful. Now we wait for the response in handle_read.
            // The pending_command_handler_ remains set until a response is received or timeout.
        }
    }

    std::vector<char> EventConnectionBoost::decryptMessage(const std::vector<char>& encrypted_data, std::any &connection_context, boost::system::error_code& ec) {
        LOG_DEBUG("---------------BEGIN READ & DECRYPTION---------------\n");
        ec.clear(); // Start with no error
        TransportContext *transportContext = nullptr;
        try {
            // Safely get the context for this connection
            auto ctx_ptr = std::any_cast<TransportContext *>(connection_context);
            transportContext = ctx_ptr;
        } catch (const std::bad_any_cast &e) {
            LOG_ERROR("Failed to cast connection context to TransportContext*: {}",
                    e.what());
            ec = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            return {};
        }
        if (!transportContext) {
            LOG_ERROR("TransportContext is null during decryption.");
            ec = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            return {};
        }

        if (encrypted_data.size() < (2 + 16)) { // Header + Tag
            LOG_ERROR("Encrypted data too short.");
            ec =
                boost::system::errc::make_error_code(boost::system::errc::message_size);
            return {};
        }

        // Extract header (AAD) and payload
        uint8_t header[2];
        header[0] = encrypted_data[0];
        header[1] = encrypted_data[1];
        size_t expected_plaintext_length = boost::endian::load_little_u16(header);
        const uint8_t *encrypted_payload_ptr =
            reinterpret_cast<const uint8_t *>(encrypted_data.data() + 2);
        size_t encrypted_payload_size = encrypted_data.size() - 2;

        LOG_DEBUG("Header: {:02x}{:02x}", header[0], header[1]);
        LOG_DEBUG("Encrypted Payload Size: {}", encrypted_payload_size);
        LOG_DEBUG("Expected Plaintext Size: {}", expected_plaintext_length);

        std::vector<uint8_t> decryptedPayload(expected_plaintext_length);
        int err = crypto_aead_chacha20poly1305_ietf_decrypt(
            decryptedPayload.data(), NULL, NULL, encrypted_payload_ptr,
            encrypted_payload_size, // Pass only payload+tag
            header, 2,              // Pass header as AAD
            transportContext
                ->outputNonce, // Use OUTPUT nonce for DECRYPTING data FROM client
            transportContext->outputKey
                .data()); // Use OUTPUT key for DECRYPTING data FROM client

        if (err != 0) {
            LOG_ERROR("Decryption failed (crypto_aead_chacha20poly1305_ietf_decrypt "
                    "returned {})",
                    err);
            ERR_print_errors_fp(stderr); // Print OpenSSL errors if any
            ec = boost::system::errc::make_error_code(
                boost::system::errc::illegal_byte_sequence); // Or similar
            return {};
        }

        LOG_VERBOSE("Decrypted payload({:d}): \n{:x}", decryptedPayload.size(),
                    decryptedPayload);

        // Increment the NONCE used for this operation
        transportContext->outputNonce[4]++;
        if (transportContext->outputNonce[4] == 0)
            transportContext->outputNonce[5]++;

        LOG_DEBUG("---------------END READ & DECRYPTION---------------\n");
        return std::vector<char>(decryptedPayload.begin(), decryptedPayload.end());
    }

    std::vector<char> EventConnectionBoost::encryptMessage(const std::vector<char>& plaintext_data, std::any &connection_context, boost::system::error_code& ec) {
        LOG_DEBUG("---------------BEGIN WRITE & ENCRYPTION---------------\n");
        ec.clear();
        TransportContext *transportContext = nullptr;
        try {
            auto ctx_ptr = std::any_cast<TransportContext *>(connection_context);
            transportContext = ctx_ptr;
        } catch (const std::bad_any_cast &e) {
            LOG_ERROR("Failed to cast connection context to TransportContext*: {}",
                    e.what());
            ec = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            return {};
        }
        if (!transportContext) {
            LOG_ERROR("TransportContext is null during encryption.");
            ec = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            return {};
        }

        if (plaintext_data.size() > 0xFFFF) { // Check size limit for header
            LOG_ERROR("Plaintext payload too large for 16-bit length header.");
            ec = boost::system::errc::make_error_code(
                boost::system::errc::value_too_large);
            return {};
        }

        uint8_t header[2];
        boost::endian::store_little_u16(header, plaintext_data.size());
        LOG_DEBUG("Header: {:02x}{:02x}", header[0], header[1]);

        std::vector<uint8_t> encryptedResponse(plaintext_data.size() +
                                                16);   // Space for tag
        unsigned long long encrypted_len_written = 0; // Needed by libsodium

        int err = crypto_aead_chacha20poly1305_ietf_encrypt(
            encryptedResponse.data(), &encrypted_len_written,
            reinterpret_cast<const uint8_t *>(plaintext_data.data()),
            plaintext_data.size(), header, 2, // Pass header as AAD
            NULL,                                // nsec is not used
            transportContext
                ->inputNonce, // Use INPUT nonce for ENCRYPTING data TO client
            transportContext->inputKey
                .data()); // Use INPUT key for ENCRYPTING data TO client

        if (err != 0) {
            LOG_ERROR("Encryption failed (crypto_aead_chacha20poly1305_ietf_encrypt "
                    "returned {})",
                    err);
            ERR_print_errors_fp(stderr);
            ec = boost::system::errc::make_error_code(
                boost::system::errc::permission_denied); // Or similar
            return {};
        }

        // Ensure the length written matches expected size
        if (encrypted_len_written != encryptedResponse.size()) {
            LOG_ERROR("Error: Encrypted length mismatch. Expected {}, got {}",
                    encryptedResponse.size(), encrypted_len_written);
            ec = boost::system::errc::make_error_code(
                boost::system::errc::protocol_error);
            return {};
        }

        // Increment the NONCE used for this operation
        transportContext->inputNonce[4]++;
        if (transportContext->inputNonce[4] == 0)
            transportContext->inputNonce[5]++;

        // Prepend the header to the encrypted data + tag
        std::vector<char> final_message;
        final_message.reserve(2 + encryptedResponse.size());
        final_message.insert(final_message.end(), header, header + 2);
        final_message.insert(final_message.end(), encryptedResponse.begin(),
                            encryptedResponse.end());

        LOG_VERBOSE("Encrypted response ({}): \n{}", final_message.size(),
                    final_message);
        LOG_DEBUG("---------------END WRITE & ENCRYPTION---------------\n");
        return final_message;
    }
  } // namespace Session
} // namespace AirPlay
