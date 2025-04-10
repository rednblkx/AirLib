#pragma once
#include <vector>
#include <string>
#include <stdexcept>
#include <optional>
#include <cstring>
#include <algorithm>
#include <span>
#include <format>
#include "logger.hpp"

// OpenSSL headers
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include "BigNum.hpp"
// --- Forward Declarations ---
class BnCtx;
class ModAccel;
class BigNum;
class Hasher;
struct SRPParameters;

// --- Hasher Class ---

class Hasher {
    EVP_MD_CTX* md_ctx_ = nullptr;
    const EVP_MD* md_ = nullptr; // Store the algorithm type
  
   public:
    explicit Hasher(const EVP_MD* md);
    ~Hasher();
  
    // Delete copy operations
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;
    // Allow move operations
    Hasher(Hasher&& other) noexcept;
    Hasher& operator=(Hasher&& other) noexcept;
  
    void reset();
    void update(std::span<const unsigned char> data);
    void update(const std::string& str);
    void update(const char* c_str);
    std::vector<unsigned char> finalize();
    size_t digest_size() const;
    size_t key_size() const;
    const EVP_MD* get_md() const;
};

// --- SRP Definitions ---

enum class SRPVersion {
    SRP6,
    SRP6a
};

struct SRPParameters {
    BigNum N; // Modulus
    BigNum g; // Generator
    const EVP_MD* hash_algo; // Hashing algorithm (e.g., EVP_sha512())
    std::string identifier;

    // Basic validation
    bool is_valid(int min_bits = 512) const {
        if (N.is_zero() || g.is_zero() || !hash_algo) return false;
        if (N.num_bits() < min_bits) {
             LOG_ERROR("Modulus N is too small ({}) bits, required {}", N.num_bits(), min_bits);
             return false;
        }
        if (g <= 1 || g >= N) {
             LOG_ERROR("Generator g is invalid (g={})", g.to_hex());
             return false;
        }
        return true;
    }
};

// Predefined Parameters (RFC 5054, 3072-bit Group, SHA-512)
namespace SRPPredefinedParameters {
    const SRPParameters& RFC5054_3072_SHA512();
} // namespace SRPPredefinedParameters


// --- SRPServer Class ---
class SRPServer {
public:
    SRPServer(SRPVersion version, const SRPParameters& params,
            bool use_mod_accel = true);

    // Set user credentials (either password or pre-computed verifier)
    void set_user_password(const std::string& username,
                        const std::string& password, size_t salt_len = 16);
    void set_user_verifier(const std::string& username,
                        std::vector<unsigned char> salt, BigNum verifier);

    // Generate server public key B
    std::vector<unsigned char> generate_public_key();

    // Compute session key K after receiving client public key A
    std::vector<unsigned char> compute_session_key(
        std::span<const unsigned char> client_A_bytes);

    // Verify client proof M1
    bool verify_client_proof(std::span<const unsigned char> client_M1_bytes);

    // Generate server proof M2 (call after successful verify_client_proof)
    std::vector<unsigned char> generate_server_proof() const;

    // --- Getters for protocol values (use with caution) ---
    const std::vector<unsigned char>& get_salt() const;
    const BigNum& get_verifier() const;
    const std::vector<unsigned char>& get_session_key() const;

private:
    enum class State {
    INITIALIZED,
    CREDENTIALS_SET,
    PUBLIC_KEY_GENERATED,
    KEY_COMPUTED,
    CLIENT_VERIFIED
    };

    SRPVersion version_;
    SRPParameters params_;
    BnCtx ctx_;
    ModAccel accel_;
    Hasher hasher_;
    bool use_mod_accel_;
    size_t N_len_bytes_;  // Cache N's byte length for padding

    // Precomputed values
    BigNum k_;  // SRP-6 or SRP-6a multiplier
    std::vector<unsigned char> H_N_xor_H_g_;

    // User specific
    std::optional<std::string> username_;
    std::optional<std::vector<unsigned char>> salt_;
    std::optional<BigNum> v_;  // Verifier v = g^x mod N

    // Ephemeral values
    std::optional<BigNum> b_;  // Server secret exponent
    std::optional<BigNum> B_;  // Server public key B = (kv + g^b) mod N

    // Interaction values
    std::optional<BigNum> A_;  // Client public key
    std::optional<BigNum> u_;  // H(A, B)

    // Session values
    std::optional<std::vector<unsigned char>> K_;  // Session key K = H(S)
    std::optional<std::vector<unsigned char>> M1_;  // Client proof M1 = H(...,
                                                    // A, B, K)
    std::optional<std::vector<unsigned char>> M2_;  // Server proof M2 = H(A, M1,
                                                    // K)

    State state_ = State::INITIALIZED;
};


// --- SRPClient Class ---
class SRPClient {
public:
    SRPClient(SRPVersion version, const SRPParameters& params,
            bool use_mod_accel = true);

    // Set user credentials
    void set_credentials(const std::string& username, const std::string& password);

    // Generate client public key A
    std::vector<unsigned char> generate_public_key();

    // Compute session key K after receiving salt and server public key B
    std::vector<unsigned char> compute_session_key(
        std::span<const unsigned char> salt_bytes,
        std::span<const unsigned char> server_B_bytes);

    // Generate client proof M1
    std::vector<unsigned char> generate_client_proof();

    // Verify server proof M2
    bool verify_server_proof(std::span<const unsigned char> server_M2_bytes);

    const std::vector<unsigned char>& get_session_key() const;

private:
    enum class State {
    INITIALIZED,
    CREDENTIALS_SET,
    PUBLIC_KEY_GENERATED,
    KEY_COMPUTED,
    CLIENT_PROOF_GENERATED,
    SERVER_VERIFIED
    };

    SRPVersion version_;
    SRPParameters params_;
    BnCtx ctx_;
    ModAccel accel_;
    Hasher hasher_;
    bool use_mod_accel_;
    size_t N_len_bytes_;

    // Precomputed values
    BigNum k_;
    std::vector<unsigned char> H_N_xor_H_g_;

    // User specific
    std::optional<std::string> username_;
    std::optional<std::string> password_;  // Temporarily held
    std::optional<BigNum> x_;  // H(s, H(U,':',P))

    // Ephemeral values
    std::optional<BigNum> a_;  // Client secret exponent
    std::optional<BigNum> A_;  // Client public key A = g^a mod N

    // Interaction values
    std::optional<std::vector<unsigned char>> salt_;
    std::optional<BigNum> B_;  // Server public key
    std::optional<BigNum> u_;  // H(A, B)

    // Session values
    std::optional<std::vector<unsigned char>> K_;  // Session key K = H(S)
    std::optional<std::vector<unsigned char>> M1_;  // Client proof M1 = H(...,
                                                    // A, B, K)
    // M2 is only verified, not stored long-term typically

    State state_ = State::INITIALIZED;
};


// --- Global Initialization ---
inline void initialize_srp_library() {
    // Initialize OpenSSL library functions
    OpenSSL_add_all_algorithms(); // Deprecated in OpenSSL 3.0, but often needed for < 3.0 compatibility
    ERR_load_crypto_strings();
    LOG_DEBUG("SRP Library Initialized (OpenSSL).");
}

// Should be called once at application end
inline void finalize_srp_library() {
    LOG_DEBUG("SRP Library Finalized (OpenSSL cleanup may be partial).");
}