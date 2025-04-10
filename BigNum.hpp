#pragma once

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include "logger.hpp"

// --- Forward Declarations ---
class BnCtx;
class ModAccel;
class BigNum;
class Hasher;
struct SRPParameters;

// Helper to get OpenSSL error string
inline std::string get_openssl_error() {
    unsigned long err_code = ERR_get_error();
    if (err_code == 0) {
        return "No OpenSSL error";
    }
    char err_buf[256];
    ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
    return std::string(err_buf);
}

class BnCtx {
    BN_CTX* ctx_ = nullptr;
public:
    BnCtx() : ctx_(BN_CTX_new()) {
        if (!ctx_) throw std::runtime_error("Failed to create BN_CTX: " + get_openssl_error());
        LOG_DEBUG("BnCtx created.");
    }
    ~BnCtx() {
        if (ctx_) {
            BN_CTX_free(ctx_);
            LOG_DEBUG("BnCtx destroyed.");
        }
    }
    // Delete copy constructor and assignment operator
    BnCtx(const BnCtx&) = delete;
    BnCtx& operator=(const BnCtx&) = delete;
    // Allow move constructor and assignment operator
    BnCtx(BnCtx&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }
    BnCtx& operator=(BnCtx&& other) noexcept {
        if (this != &other) {
            if (ctx_) BN_CTX_free(ctx_);
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    BN_CTX* get() const noexcept { return ctx_; }
};

// BN_MONT_CTX wrapper (Modular Exponentiation Accelerator)
class ModAccel {
    BN_MONT_CTX* mont_ctx_ = nullptr;
public:
    ModAccel() = default; // Default constructor for optional usage

    ModAccel(const BigNum& modulus, BnCtx& bn_ctx); // Forward declared

    ~ModAccel() {
        if (mont_ctx_) {
            BN_MONT_CTX_free(mont_ctx_);
            LOG_DEBUG("ModAccel destroyed.");
        }
    }
    // Delete copy constructor and assignment operator
    ModAccel(const ModAccel&) = delete;
    ModAccel& operator=(const ModAccel&) = delete;
    // Allow move constructor and assignment operator
    ModAccel(ModAccel&& other) noexcept : mont_ctx_(other.mont_ctx_) {
        other.mont_ctx_ = nullptr;
    }
    ModAccel& operator=(ModAccel&& other) noexcept {
        if (this != &other) {
            if (mont_ctx_) BN_MONT_CTX_free(mont_ctx_);
            mont_ctx_ = other.mont_ctx_;
            other.mont_ctx_ = nullptr;
        }
        return *this;
    }

    BN_MONT_CTX* get() const noexcept { return mont_ctx_; }
    bool is_valid() const noexcept { return mont_ctx_ != nullptr; }
};

class BigNum {
    BIGNUM* bn_ = nullptr;

    // Private constructor for internal use
    explicit BigNum(BIGNUM* bn) noexcept : bn_(bn) {}

public:
    // Default constructor (creates 0)
    BigNum() : bn_(BN_new()) {
        if (!bn_) throw std::runtime_error("Failed to create BIGNUM: " + get_openssl_error());
        BN_zero(bn_);
        // LOG_DEBUG << "BigNum default created (0)." << std::endl;
    }

    // Constructor from unsigned int
    explicit BigNum(unsigned int val) : bn_(BN_new()) {
        if (!bn_) throw std::runtime_error("Failed to create BIGNUM: " + get_openssl_error());
        if (!BN_set_word(bn_, static_cast<BN_ULONG>(val))) {
            BN_free(bn_);
            throw std::runtime_error("Failed to set BIGNUM from word: " + get_openssl_error());
        }
        // LOG_DEBUG << "BigNum created from uint: " << val << std::endl;
    }

    // Destructor
    ~BigNum() {
        if (bn_) {
            BN_clear_free(bn_); // Use clear_free for security
            // LOG_DEBUG << "BigNum destroyed." << std::endl;
        }
    }

    // Copy constructor
    BigNum(const BigNum& other) : bn_(BN_dup(other.bn_)) {
        if (!bn_) throw std::runtime_error("Failed to duplicate BIGNUM: " + get_openssl_error());
        // LOG_DEBUG << "BigNum copied." << std::endl;
    }

    // Copy assignment
    BigNum& operator=(const BigNum& other) {
        if (this != &other) {
            BIGNUM* new_bn = BN_dup(other.bn_);
            if (!new_bn) throw std::runtime_error("Failed to duplicate BIGNUM: " + get_openssl_error());
            BN_clear_free(bn_);
            bn_ = new_bn;
            // LOG_DEBUG << "BigNum assigned." << std::endl;
        }
        return *this;
    }

    // Move constructor
    BigNum(BigNum&& other) noexcept : bn_(other.bn_) {
        other.bn_ = nullptr; // Prevent double free
        // LOG_DEBUG << "BigNum moved." << std::endl;
    }

    // Move assignment
    BigNum& operator=(BigNum&& other) noexcept {
        if (this != &other) {
            BN_clear_free(bn_);
            bn_ = other.bn_;
            other.bn_ = nullptr;
            // LOG_DEBUG << "BigNum move assigned." << std::endl;
        }
        return *this;
    }

    // Factory from bytes (big-endian)
    static BigNum from_bytes(std::span<const unsigned char> bytes) {
        BIGNUM* bn = BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
        if (!bn) throw std::runtime_error("Failed to create BIGNUM from bytes: " + get_openssl_error());
        // LOG_DEBUG << "BigNum created from bytes (len=" << bytes.size() << ")" << std::endl;
        return BigNum(bn);
    }

    // Convert to bytes (big-endian)
    std::vector<unsigned char> to_bytes() const {
        int len = BN_num_bytes(bn_);
        if (len < 0) len = 0; // Handle BN_zero case
        std::vector<unsigned char> bytes(len);
        if (len > 0) {
             if (BN_bn2bin(bn_, bytes.data()) != len) {
                 throw std::runtime_error("Failed to convert BIGNUM to bytes: " + get_openssl_error());
             }
        }
        // LOG_DEBUG << "BigNum converted to bytes (len=" << bytes.size() << ")" << std::endl;
        return bytes;
    }

    // Convert to bytes (big-endian, padded to specific length)
    std::vector<unsigned char> to_bytes_padded(size_t target_len) const {
        std::vector<unsigned char> bytes(target_len);
        int actual_len = BN_bn2bin(bn_, bytes.data() + (target_len - BN_num_bytes(bn_)));
         if (actual_len < 0) {
             throw std::runtime_error("Failed to convert BIGNUM to padded bytes: " + get_openssl_error());
         }
         // Zero-pad the beginning if necessary (BN_bn2bin handles the actual data placement)
         // Note: BN_bn2bin pads with leading zeros if the buffer is larger, but we want explicit control
         // for cases where BN_num_bytes is less than target_len.
         size_t current_bytes = BN_num_bytes(bn_);
         if (current_bytes < target_len) {
             std::fill(bytes.begin(), bytes.begin() + (target_len - current_bytes), 0);
             BN_bn2bin(bn_, bytes.data() + (target_len - current_bytes));
         } else {
             // If BN_num_bytes >= target_len, BN_bn2bin might truncate or error if buffer too small.
             // We ensure buffer is target_len, so it should write exactly target_len bytes if BN fits.
             // If BN is larger, this will effectively truncate (undesirable). Let's check.
             if (current_bytes > target_len) {
                 // This case shouldn't happen if target_len is based on modulus, but good to check.
                 throw std::runtime_error("BIGNUM too large for target padding length");
             }
             BN_bn2bin(bn_, bytes.data()); // Write directly if size matches or BN is smaller
         }

        // LOG_DEBUG << "BigNum converted to padded bytes (len=" << target_len << ")" << std::endl;
        return bytes;
    }


    // Get BIGNUM pointer (use with caution)
    BIGNUM* get() const noexcept { return bn_; }

    // --- Arithmetic Operations ---
    BigNum operator+(const BigNum& rhs) const;
    BigNum operator-(const BigNum& rhs) const;
    BigNum operator*(const BigNum& rhs) const;
    BigNum operator/(const BigNum& rhs) const; // Requires context
    BigNum operator%(const BigNum& rhs) const; // Requires context

    BigNum& operator+=(const BigNum& rhs);
    BigNum& operator-=(const BigNum& rhs);
    BigNum& operator*=(const BigNum& rhs);
    BigNum& operator/=(const BigNum& rhs); // Requires context
    BigNum& operator%=(const BigNum& rhs); // Requires context

    // Modular Arithmetic
    BigNum mod_mul(const BigNum& rhs, const BigNum& modulus, BnCtx& ctx) const;
    BigNum mod_exp(const BigNum& exponent, const BigNum& modulus, BnCtx& ctx, ModAccel* accel = nullptr) const;

    // --- Comparison Operations ---
    int compare(const BigNum& rhs) const noexcept { return BN_cmp(bn_, rhs.bn_); }

    int compare_int(unsigned int rhs) const {
        BigNum rhs_bn(rhs); // Create a temporary BigNum from the integer
        return BN_cmp(bn_, rhs_bn.get()); // Compare using BN_cmp
    }

    bool operator==(const BigNum& rhs) const noexcept { return compare(rhs) == 0; }
    bool operator!=(const BigNum& rhs) const noexcept { return compare(rhs) != 0; }
    bool operator<(const BigNum& rhs) const noexcept { return compare(rhs) < 0; }
    bool operator>(const BigNum& rhs) const noexcept { return compare(rhs) > 0; }
    bool operator<=(const BigNum& rhs) const noexcept { return compare(rhs) <= 0; }
    bool operator>=(const BigNum& rhs) const noexcept { return compare(rhs) >= 0; }

    // Comparison with an integer
    bool operator==(unsigned int rhs) const { return compare_int(rhs) == 0; }
    bool operator!=(unsigned int rhs) const { return compare_int(rhs) != 0; }
    bool operator<(unsigned int rhs) const { return compare_int(rhs) < 0; }
    bool operator>(unsigned int rhs) const { return compare_int(rhs) > 0; }
    bool operator<=(unsigned int rhs) const { return compare_int(rhs) <= 0; }
    bool operator>=(unsigned int rhs) const { return compare_int(rhs) >= 0; }


    // --- Utility Methods ---
    int num_bits() const noexcept { return BN_num_bits(bn_); }
    int num_bytes() const noexcept { return BN_num_bytes(bn_); }
    bool is_zero() const noexcept { return BN_is_zero(bn_); }
    bool is_one() const noexcept { return BN_is_one(bn_); }
    bool is_odd() const noexcept { return BN_is_odd(bn_); }

    // For debugging
    std::string to_hex() const {
        char* hex_str = BN_bn2hex(bn_);
        if (!hex_str) return "[Error converting to hex]";
        std::string result(hex_str);
        OPENSSL_free(hex_str);
        return result;
    }
};