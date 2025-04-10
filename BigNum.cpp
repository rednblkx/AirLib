#include "BigNum.hpp"

BigNum BigNum::operator+(const BigNum& rhs) const {
    BigNum result;
    if (!BN_add(result.bn_, bn_, rhs.bn_)) {
        throw std::runtime_error("BN_add failed: " + get_openssl_error());
    }
    return result;
}
BigNum BigNum::operator-(const BigNum& rhs) const {
    BigNum result;
    if (!BN_sub(result.bn_, bn_, rhs.bn_)) {
        throw std::runtime_error("BN_sub failed: " + get_openssl_error());
    }
    return result;
}

// Multiplication needs a context
BigNum BigNum::operator*(const BigNum& rhs) const {
    BnCtx ctx; // Create a temporary context
    BigNum result;
    if (!BN_mul(result.bn_, bn_, rhs.bn_, ctx.get())) {
        throw std::runtime_error("BN_mul failed: " + get_openssl_error());
    }
    return result;
}

// Division needs a context
BigNum BigNum::operator/(const BigNum& rhs) const {
     BnCtx ctx; // Create a temporary context
     BigNum result;
     if (!BN_div(result.bn_, nullptr, bn_, rhs.bn_, ctx.get())) { // quotient only
         throw std::runtime_error("BN_div failed: " + get_openssl_error());
     }
     return result;
}

// Modulo needs a context
BigNum BigNum::operator%(const BigNum& rhs) const {
     BnCtx ctx; // Create a temporary context
     BigNum result;
     if (!BN_mod(result.bn_, bn_, rhs.bn_, ctx.get())) {
         throw std::runtime_error("BN_mod failed: " + get_openssl_error());
     }
     return result;
}


// In-place operators
BigNum& BigNum::operator+=(const BigNum& rhs) {
    if (!BN_add(bn_, bn_, rhs.bn_)) {
        throw std::runtime_error("BN_add (in-place) failed: " + get_openssl_error());
    }
    return *this;
}
BigNum& BigNum::operator-=(const BigNum& rhs) {
     if (!BN_sub(bn_, bn_, rhs.bn_)) {
        throw std::runtime_error("BN_sub (in-place) failed: " + get_openssl_error());
    }
    return *this;
}
BigNum& BigNum::operator*=(const BigNum& rhs) {
    BnCtx ctx;
    if (!BN_mul(bn_, bn_, rhs.bn_, ctx.get())) {
        throw std::runtime_error("BN_mul (in-place) failed: " + get_openssl_error());
    }
    return *this;
}
BigNum& BigNum::operator/=(const BigNum& rhs) {
    BnCtx ctx;
    if (!BN_div(bn_, nullptr, bn_, rhs.bn_, ctx.get())) {
        throw std::runtime_error("BN_div (in-place) failed: " + get_openssl_error());
    }
    return *this;
}
BigNum& BigNum::operator%=(const BigNum& rhs) {
    BnCtx ctx;
    if (!BN_mod(bn_, bn_, rhs.bn_, ctx.get())) {
        throw std::runtime_error("BN_mod (in-place) failed: " + get_openssl_error());
    }
    return *this;
}


// Modular Multiplication
BigNum BigNum::mod_mul(const BigNum& rhs, const BigNum& modulus, BnCtx& ctx) const {
    BigNum result;
    if (!BN_mod_mul(result.bn_, bn_, rhs.bn_, modulus.bn_, ctx.get())) {
        throw std::runtime_error("BN_mod_mul failed: " + get_openssl_error());
    }
    return result;
}

// Modular Exponentiation
BigNum BigNum::mod_exp(const BigNum& exponent, const BigNum& modulus, BnCtx& ctx, ModAccel* accel) const {
    BigNum result;
    BN_MONT_CTX* mont_ctx = accel ? accel->get() : nullptr;

    // Original code had logic for BN_mod_exp_mont_word if base was small.
    // Modern OpenSSL handles this reasonably well internally, but we could add it.
    // For simplicity, we use the general functions first.
    if (mont_ctx) {
        if (!BN_mod_exp_mont(result.bn_, bn_, exponent.bn_, modulus.bn_, ctx.get(), mont_ctx)) {
             throw std::runtime_error("BN_mod_exp_mont failed: " + get_openssl_error());
        }
    } else {
        if (!BN_mod_exp(result.bn_, bn_, exponent.bn_, modulus.bn_, ctx.get())) {
             throw std::runtime_error("BN_mod_exp failed: " + get_openssl_error());
        }
    }
    return result;
}

ModAccel::ModAccel(const BigNum& modulus, BnCtx& bn_ctx)
    : mont_ctx_(BN_MONT_CTX_new()) {
    if (!mont_ctx_) {
        throw std::runtime_error("Failed to create BN_MONT_CTX: " + get_openssl_error());
    }
    if (!BN_MONT_CTX_set(mont_ctx_, modulus.get(), bn_ctx.get())) {
        BN_MONT_CTX_free(mont_ctx_);
        mont_ctx_ = nullptr; // Ensure it's null on failure
        throw std::runtime_error("Failed to set BN_MONT_CTX: " + get_openssl_error());
    }
    LOG_DEBUG("ModAccel created and set.");
}