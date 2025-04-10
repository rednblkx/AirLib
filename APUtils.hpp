#ifndef AIRPLAY_UTILS_HPP
#define AIRPLAY_UTILS_HPP

#include "logger.hpp"
#include <boost/any.hpp>
#include <cstdint>
#include <limits>
#include <map>
#include <openssl/evp.h>
#include <sodium/core.h>
#include <sodium/utils.h>
#include <string>
#include <array>
#include <sodium/crypto_aead_chacha20poly1305.h>

namespace AirPlay {
namespace Utils {

// Stream Types
enum class StreamType { Invalid = 0, CPMainHighAudio = 102, CPMainAudio = 100, CPAltAudio = 101, Screen = 110, APAudio = 96 };

struct StreamCryptor {
    unsigned char readkey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char writekey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]; // Libsodium's IETF implementation uses 12 bytes
    bool keyPresent = false;
    bool incrementNonce = false;

    StreamCryptor(bool incrementNonce = false) : incrementNonce(incrementNonce) {
        // Ensure sodium is initialized
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        memset(readkey, 0, sizeof(readkey));
        memset(nonce, 0, sizeof(nonce)); // Start nonce at 0? AirPlay spec needed.
    }

     void initReadKey(const uint8_t* newKey) {
        memcpy(readkey, newKey, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        keyPresent = true;
         LOG_DEBUG("StreamCryptor read key initialized.");
    }

    void initWriteKey(const uint8_t* newKey) {
        memcpy(writekey, newKey, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        keyPresent = true;
        LOG_DEBUG("StreamCryptor write key initialized.");
    }

    // Decrypt using standard IETF ChaCha20-Poly1305 AEAD
    // Input: ciphertext including nonce (last 8 bytes LE) and tag (16 bytes before nonce LE)
    // Output: plaintext
    // AAD: Additional Authenticated Data
    // Returns true on success, false on verification failure.
    bool decrypt(const uint8_t* aad, size_t aadLen,
                 const uint8_t* ciphertext, size_t ciphertextLen,
                 uint8_t* plaintext, size_t& plaintextLen, bool nonceAtEnd = false)
    {
        if (!keyPresent) {
            LOG_ERROR("Cryptor key not valid for decryption.");
            return false;
        }
        if (ciphertextLen < 24) { // Need at least tag + nonce
             LOG_ERROR("Ciphertext too short ({} bytes)", ciphertextLen);
             return false;
        }

        // Extract tag and nonce(if expected) from the end of the ciphertext
        // Libsodium expects a 12-byte nonce. AirPlay uses an 8-byte nonce LE.
        std::unique_ptr<unsigned char[]> embeddedNonce; // 12 bytes for libsodium
        if (nonceAtEnd) {
          // Copy the 8 LE bytes from the end of ciphertext into the start of our 12-byte nonce
          embeddedNonce = std::unique_ptr<unsigned char[]>(new unsigned char[12]);
          memset(embeddedNonce.get(), 0, 4);
          memcpy(embeddedNonce.get() + 4, ciphertext + ciphertextLen - 8, 8);
        }

        const unsigned char* tag = ciphertext + ciphertextLen - (nonceAtEnd ? 24 : 16);
        size_t actualCiphertextLen = ciphertextLen - (nonceAtEnd ? 24 : 16);
        unsigned long long decryptedLen_ull = 0;

        // LOG_VERBOSE("Decrypting {} bytes (ciphertext {})", actualCiphertextLen, ciphertextLen);

        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                plaintext, &decryptedLen_ull,
                nullptr, // nsec is not used
                ciphertext, actualCiphertextLen + 16,
                aad, aadLen,
                nonceAtEnd ? embeddedNonce.get() : nonce, readkey) != 0)
        {
            // Verification failed!
            LOG_WARN("AEAD decryption verification FAILED!");
            plaintextLen = 0;
            return false;
        }

        plaintextLen = static_cast<size_t>(decryptedLen_ull);
        if (incrementNonce) {
          sodium_increment(nonceAtEnd ? embeddedNonce.get() : nonce + 4, crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 4);
        }
        // LOG_VERBOSE("Decryption successful, plaintext length: {}", plaintextLen);
        return true;
    }

     // Encrypt using standard IETF ChaCha20-Poly1305 AEAD
     // Input: plaintext
     // Output: ciphertext (will include tag automatically)
     // AAD: Additional Authenticated Data
     // Returns true on success.
     bool encrypt(const uint8_t* aad, size_t aadLen,
                  const uint8_t* plaintext, size_t plaintextLen,
                  uint8_t* ciphertext, size_t& ciphertextLen) // Output buffer, updated length
     {
         if (!keyPresent) {
             LOG_ERROR("Cryptor key not valid for encryption.");
             return false;
         }

         unsigned long long encryptedLen_ull = 0;

         if (crypto_aead_chacha20poly1305_ietf_encrypt(
                 ciphertext, &encryptedLen_ull,
                 plaintext, plaintextLen,
                 aad, aadLen,
                 nullptr, // nsec is not used in combined mode
                 nonce, writekey) != 0)
         {
             LOG_ERROR("AEAD encryption failed!");
             ciphertextLen = 0;
             return false;
         }

         if (incrementNonce) {
          sodium_increment(nonce + 4, crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 4);
         }

         ciphertextLen = static_cast<size_t>(encryptedLen_ull); // Includes tag
         LOG_VERBOSE("Encryption successful, ciphertext length: {}", ciphertextLen);
         return true;
     }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const { EVP_MD_CTX_free(ctx); }
  };
  using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

// Define Deleters for OpenSSL EVP contexts
struct EvpCipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX *ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

std::array<uint8_t, 6> getPrimaryMacAddress();
} // namespace Utils
} // namespace AirPlay

#endif // AIRPLAY_UTILS_HPP