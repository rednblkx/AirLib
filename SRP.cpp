#include "SRP.hpp"
#include <cstring>  // For strlen
#include <stdexcept>
#include "BigNum.hpp"
#include <openssl/crypto.h> // For CRYPTO_memcmp

Hasher::Hasher(const EVP_MD* md) : md_(md) {
  if (!md_) throw std::invalid_argument("Hash algorithm cannot be null");
  md_ctx_ = EVP_MD_CTX_new();
  if (!md_ctx_)
    throw std::runtime_error("Failed to create EVP_MD_CTX: " +
                             get_openssl_error());
  if (!EVP_DigestInit_ex(md_ctx_, md_, nullptr)) {
    EVP_MD_CTX_free(md_ctx_);
    throw std::runtime_error("Failed to initialize digest context: " +
                             get_openssl_error());
  }
  LOG_DEBUG("Hasher created for {}", EVP_MD_get0_name(md_));
}

Hasher::~Hasher() {
  if (md_ctx_) {
    EVP_MD_CTX_free(md_ctx_);
    LOG_DEBUG("Hasher destroyed.");
  }
}

Hasher::Hasher(Hasher&& other) noexcept : md_ctx_(other.md_ctx_), md_(other.md_) {
  other.md_ctx_ = nullptr;
  other.md_ = nullptr;
}

Hasher& Hasher::operator=(Hasher&& other) noexcept {
  if (this != &other) {
    if (md_ctx_) EVP_MD_CTX_free(md_ctx_);
    md_ctx_ = other.md_ctx_;
    md_ = other.md_;
    other.md_ctx_ = nullptr;
    other.md_ = nullptr;
  }
  return *this;
}

void Hasher::reset() {
  if (!EVP_DigestInit_ex(md_ctx_, md_, nullptr)) {
    throw std::runtime_error("Failed to reset digest context: " +
                             get_openssl_error());
  }
  LOG_DEBUG("Hasher reset.");
}

void Hasher::update(std::span<const unsigned char> data) {
  if (!EVP_DigestUpdate(md_ctx_, data.data(), data.size())) {
    throw std::runtime_error("Failed to update digest: " + get_openssl_error());
  }
  // LOG_DEBUG << "Hasher updated with " << data.size() << " bytes." <<
  // std::endl;
}

// Overload for convenience with std::string
void Hasher::update(const std::string& str) {
  // Directly create a span of unsigned char from the string's data
  update(std::span<const unsigned char>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size()));
}

// Overload for convenience with C-style string literal
void Hasher::update(const char* c_str) {
  // Directly create a span of unsigned char from the C-string's data
  size_t len = strlen(c_str);
  update(std::span<const unsigned char>(
      reinterpret_cast<const unsigned char*>(c_str), len));
}

std::vector<unsigned char> Hasher::finalize() {
  std::vector<unsigned char> digest(EVP_MD_CTX_get_size(md_ctx_));
  unsigned int digest_len = 0;  // Actual length written
  if (!EVP_DigestFinal_ex(md_ctx_, digest.data(), &digest_len)) {
    throw std::runtime_error("Failed to finalize digest: " +
                             get_openssl_error());
  }
  digest.resize(digest_len);  // Resize to actual length
  LOG_DEBUG("Hasher finalized. Digest size: {}", digest_len);

  reset();
  return digest;
}

size_t Hasher::digest_size() const {
  int size = EVP_MD_get_size(md_);
  return (size > 0) ? static_cast<size_t>(size) : 0;
}

size_t Hasher::key_size() const { return digest_size(); }

const EVP_MD* Hasher::get_md() const { return md_; }

namespace SRPPredefinedParameters {
    const SRPParameters& RFC5054_3072_SHA512() {
        static const SRPParameters params = []{
            const unsigned char kSRPGenerator5[] = { 5 };
            const unsigned char kSRPModulus3072[] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
                0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
                0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
                0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
                0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
                0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
                0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
                0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
                0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
                0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
                0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
                0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
                0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
                0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
                0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
                0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
                0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };
            return SRPParameters{
                BigNum::from_bytes(kSRPModulus3072),
                BigNum::from_bytes(kSRPGenerator5),
                EVP_sha512(),
                "RFC5054_3072_SHA512"
            };
        }();
        return params;
    }
} // namespace SRPPredefinedParameters

// --- MGF1 Implementation (Mask Generation Function 1) ---
inline std::vector<unsigned char> mgf1(
    std::span<const unsigned char> seed,
    size_t mask_len,
    const EVP_MD* mgf1_hash_algo = EVP_sha1() // Default to SHA1 as in original
) {
    LOG_INFO("Generating MGF1 mask (len={}) using {}", mask_len, EVP_MD_get0_name(mgf1_hash_algo));
    Hasher hasher(mgf1_hash_algo);
    std::vector<unsigned char> mask;
    mask.reserve(mask_len);
    unsigned int counter = 0;
    size_t h_len = hasher.digest_size();
    if (h_len == 0) throw std::runtime_error("MGF1 hash algorithm has zero size");

    while (mask.size() < mask_len) {
        // Counter bytes (big-endian)
        unsigned char counter_bytes[4] = {
            static_cast<unsigned char>((counter >> 24) & 0xFF),
            static_cast<unsigned char>((counter >> 16) & 0xFF),
            static_cast<unsigned char>((counter >> 8) & 0xFF),
            static_cast<unsigned char>(counter & 0xFF)
        };

        hasher.reset();
        hasher.update(seed);
        hasher.update({counter_bytes, 4});
        std::vector<unsigned char> h_out = hasher.finalize();

        size_t remaining = mask_len - mask.size();
        size_t to_copy = std::min(remaining, h_len);
        mask.insert(mask.end(), h_out.begin(), h_out.begin() + to_copy);

        ++counter;
    }
    LOG_DEBUG("MGF1 generated mask: {}", mask);
    return mask;
}

// --- Base SRP Class ---

namespace SRPCommon {
// Calculate H(N) XOR H(g)
inline std::vector<unsigned char> calculate_H_N_xor_H_g(
    const BigNum& N, const BigNum& g, Hasher& hasher)
{
    size_t digest_len = hasher.digest_size();
    std::vector<unsigned char> h_N(digest_len);
    std::vector<unsigned char> h_g(digest_len);

    hasher.reset();
    hasher.update(N.to_bytes());
    h_N = hasher.finalize(); // Consumes hasher state, need reset

    hasher.reset();
    hasher.update(g.to_bytes());
    h_g = hasher.finalize();

    if (h_N.size() != digest_len || h_g.size() != digest_len) {
            throw std::logic_error("Hash output size mismatch during H(N) xor H(g)");
    }

    std::vector<unsigned char> result(digest_len);
    for (size_t i = 0; i < digest_len; ++i) {
        result[i] = h_N[i] ^ h_g[i];
    }
    LOG_DEBUG("Calculated H(N) xor H(g): {}", result);
    return result;
}

// Calculate k = H(N, g) for SRP-6a
inline BigNum calculate_k_srp6a(const BigNum& N, const BigNum& g, Hasher& hasher, size_t N_len_bytes) {
    hasher.reset();
    // Pad N and g to N's byte length for the hash (as per SRP-6a spec)
    hasher.update(N.to_bytes_padded(N_len_bytes));
    hasher.update(g.to_bytes_padded(N_len_bytes));
    std::vector<unsigned char> h_N_g = hasher.finalize();
    BigNum k = BigNum::from_bytes(h_N_g);
    LOG_DEBUG("Calculated k (SRP-6a) = H(pad(N), pad(g)): {}", k.to_hex());
    if (k == 0) {
        throw std::runtime_error("SRP-6a k value cannot be zero");
    }
    return k;
}

// Generate random bytes
inline std::vector<unsigned char> generate_random(size_t num_bytes) {
    std::vector<unsigned char> buf(num_bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(num_bytes)) != 1) {
        throw std::runtime_error("Failed to generate random bytes: " + get_openssl_error());
    }
    LOG_DEBUG("Generated {} random bytes.", num_bytes);
    return buf;
}

// Calculate x = H(s, H(U, ':', P))
inline BigNum calculate_x(
    std::span<const unsigned char> salt,
    const std::string& username,
    const std::string& password,
    Hasher& hasher)
{
    LOG_INFO("Calculating x = H(s, H(U, ':', P)) for user: {}", username);
    // Inner hash: H(U, ':', P)
    hasher.reset();
    hasher.update(username);
    hasher.update(":");
    hasher.update(password);
    std::vector<unsigned char> inner_hash = hasher.finalize();
    LOG_DEBUG("Inner hash H(U, ':', P): {}", inner_hash);

    // Outer hash: H(s, inner_hash)
    hasher.reset();
    hasher.update(salt);
    hasher.update(inner_hash);
    std::vector<unsigned char> outer_hash = hasher.finalize();
    LOG_DEBUG("Outer hash H(s, H(U, ':', P)): {}", outer_hash);

    return BigNum::from_bytes(outer_hash);
}

// Calculate u = H(A, B) with padding if needed
inline BigNum calculate_u(
    const BigNum& A, const BigNum& B, Hasher& hasher, size_t pad_len)
{
    LOG_INFO("Calculating u = H(pad(A), pad(B))");
    hasher.reset();
    hasher.update(A.to_bytes_padded(pad_len));
    hasher.update(B.to_bytes_padded(pad_len));
    std::vector<unsigned char> h_A_B = hasher.finalize();
    LOG_DEBUG("H(pad(A), pad(B)): {}", h_A_B);
    BigNum u = BigNum::from_bytes(h_A_B);
    LOG_DEBUG("u = {}", u.to_hex());
    if (u == 0) {
        throw std::runtime_error("SRP error: u value cannot be zero");
    }
    return u;
}

// Calculate session key K from S
inline std::vector<unsigned char> calculate_K(const BigNum& S, Hasher& hasher) {
    LOG_INFO("Calculating session key K = H(S)");
    LOG_DEBUG("S = {}", S.to_hex());
    hasher.reset();
    hasher.update(S.to_bytes()); // Use minimal byte representation for S
    std::vector<unsigned char> K = hasher.finalize();
    LOG_DEBUG("K = {}", K);
    return K;
}

    // Calculate session key K from S using MGF1 (for original SHA1Interleaved case)
inline std::vector<unsigned char> calculate_K_mgf1(const BigNum& S, size_t key_len) {
    LOG_INFO("Calculating session key K = MGF1-SHA1(S) with length {}", key_len);
    LOG_DEBUG("S = {}", S.to_hex());
    std::vector<unsigned char> s_bytes = S.to_bytes();
    std::vector<unsigned char> K = mgf1(s_bytes, key_len, EVP_sha1());
    LOG_DEBUG("K = {}", K);
    return K;
}


// Calculate Client Proof M1 = H(H(N) xor H(g), H(U), s, A, B, K)
inline std::vector<unsigned char> calculate_M1(
    const std::vector<unsigned char>& H_N_xor_H_g,
    const std::string& username,
    std::span<const unsigned char> salt,
    const BigNum& A,
    const BigNum& B,
    std::span<const unsigned char> K,
    Hasher& hasher,
    size_t pad_len)
{
    LOG_INFO("Calculating client proof M1 = H(H(N)^H(g) | H(U) | s | pad(A) | pad(B) | K)");
    hasher.reset();
    hasher.update(H_N_xor_H_g);

    // H(U)
    Hasher user_hasher(hasher.get_md());
    user_hasher.update(username);
    std::vector<unsigned char> h_U = user_hasher.finalize();
    hasher.update(h_U);
    LOG_DEBUG("H(U): {}", h_U);

    hasher.update(salt);
    LOG_DEBUG("s: {}", salt);

    std::vector<unsigned char> A_bytes = A.to_bytes_padded(pad_len);
    hasher.update(A_bytes);
    LOG_DEBUG("pad(A): {}", A_bytes);

    std::vector<unsigned char> B_bytes = B.to_bytes_padded(pad_len);
    hasher.update(B_bytes);
    LOG_DEBUG("pad(B): {}", B_bytes);

    hasher.update(K);
    LOG_DEBUG("K: {}", K);

    std::vector<unsigned char> M1 = hasher.finalize();
    LOG_DEBUG("M1 = {}", M1);
    return M1;
}

// Calculate Server Proof M2 = H(A, M1, K)
inline std::vector<unsigned char> calculate_M2(
    const BigNum& A,
    std::span<const unsigned char> M1,
    std::span<const unsigned char> K,
    Hasher& hasher,
    size_t pad_len)
{
    LOG_INFO("Calculating server proof M2 = H(pad(A) | M1 | K)");
    hasher.reset();

    std::vector<unsigned char> A_bytes = A.to_bytes_padded(pad_len);
    hasher.update(A_bytes);
    LOG_DEBUG("pad(A): {}", A_bytes);

    hasher.update(M1);
    LOG_DEBUG("M1: {}", M1);

    hasher.update(K);
    LOG_DEBUG("K: {}", K);

    std::vector<unsigned char> M2 = hasher.finalize();
    LOG_DEBUG("M2 = {}", M2);
    return M2;
}

// Determine secret exponent size
inline int get_secret_exponent_bits(int modulus_bits) {
    return std::min(256, modulus_bits);
}

} // namespace SRPCommon


SRPServer::SRPServer(SRPVersion version, const SRPParameters& params,
                     bool use_mod_accel)
    : version_(version),
      params_(params),
      hasher_(params.hash_algo),
      use_mod_accel_(use_mod_accel),
      N_len_bytes_(params_.N.num_bytes()),
      ctx_() //Initialize BnCtx
{
  LOG_INFO("SRPServer initializing...");
  LOG_INFO("Version: {}", (version == SRPVersion::SRP6 ? "SRP-6" : "SRP-6a"));
  LOG_INFO("Parameters: {}", params.identifier);
  LOG_INFO("Hash: {}", EVP_MD_get0_name(params.hash_algo));
  LOG_INFO("N bits: {}", params.N.num_bits());

  if (!params_.is_valid()) {
    throw std::invalid_argument("Invalid SRP parameters provided.");
  }

  if (use_mod_accel_) {
    try {
      accel_ = ModAccel(params_.N, ctx_);
      LOG_INFO("Modular exponentiation acceleration enabled.");
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to initialize modular accelerator: {}", e.what());
      use_mod_accel_ = false;
    }
  } else {
    LOG_INFO("Modular exponentiation acceleration disabled.");
  }

  // Precompute H(N) xor H(g)
  H_N_xor_H_g_ = SRPCommon::calculate_H_N_xor_H_g(params_.N, params_.g, hasher_);

  // Precompute k for SRP-6a
  if (version_ == SRPVersion::SRP6a) {
    k_ = SRPCommon::calculate_k_srp6a(params_.N, params_.g, hasher_,
                                       N_len_bytes_);
  } else {
    k_ = BigNum(3);  // k = 3 for SRP-6
    LOG_DEBUG("Using k = 3 for SRP-6.");
  }
  LOG_INFO("SRPServer initialized successfully.");
}

void SRPServer::set_user_password(const std::string& username,
                                 const std::string& password, size_t salt_len) {
  if (v_.has_value()) throw std::logic_error("Credentials already set.");
  LOG_INFO("Setting server credentials for user '{}' using password.",
           username);
  username_ = username;
  salt_ = SRPCommon::generate_random(salt_len);
  LOG_DEBUG("Generated salt (len={}): {}", salt_->size(),
            salt_.has_value() ? salt_.value() : std::vector<unsigned char>());

  BigNum x = SRPCommon::calculate_x(
      salt_.has_value() ? salt_.value() : std::vector<unsigned char>(),
      username_.has_value() ? username_.value() : std::string(), password,
      hasher_);
  LOG_DEBUG("Calculated x: {}", x.to_hex());

  v_ = params_.g.mod_exp(x, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
  LOG_DEBUG("Calculated verifier v = g^x mod N: {}", v_->to_hex());
  state_ = State::CREDENTIALS_SET;
}

void SRPServer::set_user_verifier(const std::string& username,
                                std::vector<unsigned char> salt, BigNum verifier) {
  if (v_.has_value()) throw std::logic_error("Credentials already set.");
  LOG_INFO("Setting server credentials for user '{}' using pre-computed verifier.",
           username);
  username_ = username;
  salt_ = std::move(salt);
  v_ = std::move(verifier);
  LOG_DEBUG("Using provided salt: {}",
            salt_.has_value() ? salt_.value() : std::vector<unsigned char>());
  LOG_DEBUG("Using provided verifier v: {}", v_->to_hex());
  if (salt_.has_value() && salt_.value().empty() || v_->is_zero()) {
    throw std::invalid_argument("Provided salt or verifier is invalid.");
  }
  state_ = State::CREDENTIALS_SET;
}

std::vector<unsigned char> SRPServer::generate_public_key() {
  if (state_ < State::CREDENTIALS_SET)
    throw std::logic_error("Credentials not set.");
  if (state_ >= State::PUBLIC_KEY_GENERATED)
    return B_->to_bytes_padded(N_len_bytes_);  // Idempotent

  LOG_INFO("Generating server ephemeral public key B...");
  int secret_bits = SRPCommon::get_secret_exponent_bits(params_.N.num_bits());
  size_t secret_bytes = (secret_bits + 7) / 8;

  b_ = BigNum::from_bytes(SRPCommon::generate_random(secret_bytes));
  LOG_DEBUG("Generated server secret b (bits={}): {}", b_->num_bits(),
            b_->to_hex());

  // B = (k*v + g^b) % N
  BigNum g_b = params_.g.mod_exp(*b_, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
  BigNum k_v = k_.mod_mul(*v_, params_.N, ctx_);
  B_ = (k_v + g_b) % params_.N;  // Use overloaded operators with context
                                  // awareness if implemented, else manual mod
  // Manual mod:
  // BigNum temp_sum = k_v + g_b;
  // B_ = temp_sum % params_.N;

  LOG_DEBUG("g^b mod N: {}", g_b.to_hex());
  LOG_DEBUG("k*v mod N: {}", k_v.to_hex());
  LOG_DEBUG("Server public key B = (kv + g^b) mod N: {}", B_->to_hex());

  state_ = State::PUBLIC_KEY_GENERATED;
  return B_->to_bytes_padded(N_len_bytes_);
}

std::vector<unsigned char> SRPServer::compute_session_key(
    std::span<const unsigned char> client_A_bytes) {
  if (state_ < State::PUBLIC_KEY_GENERATED)
    throw std::logic_error("Server public key not generated.");
  if (state_ >= State::KEY_COMPUTED) return *K_;  // Idempotent

  LOG_INFO("Computing session key K using client public key A...");
  A_ = BigNum::from_bytes(client_A_bytes);
  LOG_DEBUG("Received client public key A: {}", A_->to_hex());

  // Safety check: A % N != 0
  if ((*A_ % params_.N).is_zero()) {
    throw std::runtime_error(
        "SRP error: Client public key A is congruent to 0 mod N.");
  }

  u_ = SRPCommon::calculate_u(*A_, *B_, hasher_, N_len_bytes_);

  // Calculate S = (A * v^u)^b % N
  LOG_DEBUG("Calculating server session key S = (A * v^u)^b mod N");
  BigNum v_u = v_->mod_exp(*u_, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
  LOG_DEBUG("v^u mod N: {}", v_u.to_hex());
  BigNum A_vu = A_->mod_mul(v_u, params_.N, ctx_);
  LOG_DEBUG("A * v^u mod N: {}", A_vu.to_hex());

  // Check for A*v^u = 1 mod N (from original code, t3 = A*v^u, check t3 == 1)
  // This translates to checking if A*v^u mod N is 0 or 1, or -1 (N-1).

  BigNum S = A_vu.mod_exp(*b_, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
  LOG_DEBUG("Server session key S: {}", S.to_hex());

  // Calculate K = H(S)
  K_ = SRPCommon::calculate_K(S, hasher_);

  state_ = State::KEY_COMPUTED;
  return *K_;
}

bool SRPServer::verify_client_proof(
    std::span<const unsigned char> client_M1_bytes) {
  if (state_ < State::KEY_COMPUTED)
    throw std::logic_error("Session key not computed.");
  if (state_ >= State::CLIENT_VERIFIED) return true;  // Already verified

  LOG_INFO("Verifying client proof M1...");
  LOG_DEBUG("Received M1: {}", client_M1_bytes);

  M1_ = SRPCommon::calculate_M1(
      H_N_xor_H_g_, *username_,
      salt_.has_value() ? salt_.value() : std::vector<unsigned char>(), *A_, *B_,
      *K_, hasher_, N_len_bytes_);

  // Constant-time comparison is important here
  bool success = (client_M1_bytes.size() == M1_->size()) &&
                 (CRYPTO_memcmp(client_M1_bytes.data(), M1_->data(),
                                M1_->size()) == 0);

  if (success) {
    LOG_INFO("Client proof M1 verified successfully.");
    // Calculate server proof M2 = H(A, M1, K) now that M1 is verified
    M2_ = SRPCommon::calculate_M2(*A_, *M1_, *K_, hasher_, N_len_bytes_);
    state_ = State::CLIENT_VERIFIED;
    return true;
  } else {
    LOG_ERROR("Client proof M1 verification failed!");
    LOG_DEBUG("Expected M1: {}", *M1_);
    // Optionally clear sensitive state on failure
    // K_.reset(); M1_.reset(); ...
    return false;
  }
}

std::vector<unsigned char> SRPServer::generate_server_proof() const {
  if (state_ < State::CLIENT_VERIFIED)
    throw std::logic_error("Client not verified yet.");
  LOG_INFO("Generating server proof M2.");
  return *M2_;
}

const std::vector<unsigned char>& SRPServer::get_salt() const {
  if (!v_.has_value()) throw std::logic_error("Credentials not set.");
  return *salt_;
}

const BigNum& SRPServer::get_verifier() const {
  if (!v_.has_value()) throw std::logic_error("Credentials not set.");
  return *v_;
}

const std::vector<unsigned char>& SRPServer::get_session_key() const {
  if (state_ < State::KEY_COMPUTED)
    throw std::logic_error("Session key not computed.");
  return *K_;
}

SRPClient::SRPClient(SRPVersion version, const SRPParameters& params,
    bool use_mod_accel)
: version_(version),
params_(params),
hasher_(params.hash_algo),
use_mod_accel_(use_mod_accel),
N_len_bytes_(params_.N.num_bytes()),
ctx_() //Initialize BnCtx
{
LOG_INFO("SRPClient initializing...");
LOG_INFO("Version: {}", (version == SRPVersion::SRP6 ? "SRP-6" : "SRP-6a"));
LOG_INFO("Parameters: {}", params.identifier);
LOG_INFO("Hash: {}", EVP_MD_get0_name(params.hash_algo));
LOG_INFO("N bits: {}", params.N.num_bits());

if (!params_.is_valid()) {
throw std::invalid_argument("Invalid SRP parameters provided.");
}

if (use_mod_accel_) {
try {
accel_ = ModAccel(params_.N, ctx_);
LOG_INFO("Modular exponentiation acceleration enabled.");
} catch (const std::exception& e) {
LOG_ERROR("Failed to initialize modular accelerator: {}", e.what());
use_mod_accel_ = false;
}
} else {
LOG_INFO("Modular exponentiation acceleration disabled.");
}

// Precompute H(N) xor H(g)
H_N_xor_H_g_ = SRPCommon::calculate_H_N_xor_H_g(params_.N, params_.g, hasher_);

// Precompute k for SRP-6a
if (version_ == SRPVersion::SRP6a) {
k_ = SRPCommon::calculate_k_srp6a(params_.N, params_.g, hasher_,
                      N_len_bytes_);
} else {
k_ = BigNum(3);  // k = 3 for SRP-6
LOG_DEBUG("Using k = 3 for SRP-6.");
}
LOG_INFO("SRPClient initialized successfully.");
}

void SRPClient::set_credentials(const std::string& username,
               const std::string& password) {
if (state_ >= State::CREDENTIALS_SET)
throw std::logic_error("Credentials already set.");
LOG_INFO("Setting client credentials for user '{}'", username);
username_ = username;
password_ = password;  // Store password temporarily until x is calculated
state_ = State::CREDENTIALS_SET;
}

std::vector<unsigned char> SRPClient::generate_public_key() {
if (state_ < State::CREDENTIALS_SET)
throw std::logic_error("Credentials not set.");
if (state_ >= State::PUBLIC_KEY_GENERATED)
return A_->to_bytes_padded(N_len_bytes_);  // Idempotent

LOG_INFO("Generating client ephemeral public key A...");
int secret_bits = SRPCommon::get_secret_exponent_bits(params_.N.num_bits());
size_t secret_bytes = (secret_bits + 7) / 8;

a_ = BigNum::from_bytes(SRPCommon::generate_random(secret_bytes));
LOG_DEBUG("Generated client secret a (bits={}): {}", a_->num_bits(),
a_->to_hex());

// A = g^a % N
A_ = params_.g.mod_exp(*a_, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
LOG_DEBUG("Client public key A = g^a mod N: {}", A_->to_hex());

state_ = State::PUBLIC_KEY_GENERATED;
return A_->to_bytes_padded(N_len_bytes_);
}

std::vector<unsigned char> SRPClient::compute_session_key(
std::span<const unsigned char> salt_bytes,
std::span<const unsigned char> server_B_bytes) {
if (state_ < State::PUBLIC_KEY_GENERATED)
throw std::logic_error("Client public key not generated.");
if (state_ >= State::KEY_COMPUTED) return *K_;  // Idempotent

LOG_INFO("Computing session key K using salt and server public key B...");
salt_ = std::vector<unsigned char>(salt_bytes.begin(), salt_bytes.end());
B_ = BigNum::from_bytes(server_B_bytes);
LOG_DEBUG("Received salt: {}", *salt_);
LOG_DEBUG("Received server public key B: {}", B_->to_hex());

// Safety check: B % N != 0
if ((*B_ % params_.N).is_zero()) {
throw std::runtime_error(
"SRP error: Server public key B is congruent to 0 mod N.");
}

u_ = SRPCommon::calculate_u(*A_, *B_, hasher_, N_len_bytes_);
// u cannot be zero (checked in calculate_u)

// Calculate x = H(s, H(U, ':', P))
x_ = SRPCommon::calculate_x(*salt_, *username_, *password_, hasher_);
password_.reset();  // Clear password now that x is computed
LOG_DEBUG("Calculated x: {}", x_->to_hex());

// Calculate S = (B - k * g^x)^(a + u*x) % N
LOG_DEBUG("Calculating client session key S = (B - k*g^x)^(a + u*x) mod N");
BigNum g_x = params_.g.mod_exp(*x_, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
LOG_DEBUG("g^x mod N: {}", g_x.to_hex());
BigNum k_g_x = k_.mod_mul(g_x, params_.N, ctx_);
LOG_DEBUG("k * g^x mod N: {}", k_g_x.to_hex());

// Need to handle potential negative result of (B - k_g_x) before
// exponentiation
BigNum base;
if (*B_ >= k_g_x) {
base = *B_ - k_g_x;
} else {
// If B < k_g_x, result is negative. Add N to make it positive modulo N.
base = *B_ + params_.N - k_g_x;
}
// base = base % params_.N; // Ensure base is within [0, N-1]
LOG_DEBUG("Base (B - k*g^x) mod N: {}", base.to_hex());

BigNum u_x = u_->mod_mul(*x_, params_.N, ctx_);  // Exponent part needs care
                                  // with modulus
BigNum exponent = (*a_ + u_x);  // Calculate a + u*x normally first
// The exponentiation is mod N, but the exponent itself is not reduced mod N.
// However, due to Fermat's Little Theorem / Euler's theorem, we *can* reduce
// the exponent modulo phi(N) if N is prime or phi(N) is known.
// Standard SRP doesn't typically require reducing the exponent a + u*x.
LOG_DEBUG("u*x: {}", u_x.to_hex());  // This intermediate might be large
LOG_DEBUG("Exponent (a + u*x): {}", exponent.to_hex());

BigNum S = base.mod_exp(exponent, params_.N, ctx_, use_mod_accel_ ? &accel_ : nullptr);
LOG_DEBUG("Client session key S: {}", S.to_hex());

// Calculate K = H(S)
K_ = SRPCommon::calculate_K(S, hasher_);

state_ = State::KEY_COMPUTED;
return *K_;
}

std::vector<unsigned char> SRPClient::generate_client_proof() {
if (state_ < State::KEY_COMPUTED)
throw std::logic_error("Session key not computed.");
if (M1_.has_value()) return *M1_;  // Idempotent

LOG_INFO("Generating client proof M1...");
M1_ = SRPCommon::calculate_M1(H_N_xor_H_g_, *username_, *salt_, *A_, *B_,
                *K_, hasher_, N_len_bytes_);
state_ = State::CLIENT_PROOF_GENERATED;
return *M1_;
}

bool SRPClient::verify_server_proof(
std::span<const unsigned char> server_M2_bytes) {
if (state_ < State::CLIENT_PROOF_GENERATED)
throw std::logic_error("Client proof M1 not generated.");
if (state_ >= State::SERVER_VERIFIED) return true;  // Already verified

LOG_INFO("Verifying server proof M2...");
LOG_DEBUG("Received M2: {}", server_M2_bytes);

std::vector<unsigned char> expected_M2 = SRPCommon::calculate_M2(*A_, *M1_, *K_, hasher_, N_len_bytes_);

// Constant-time comparison
bool success = (server_M2_bytes.size() == expected_M2.size()) &&
(CRYPTO_memcmp(server_M2_bytes.data(), expected_M2.data(),
               expected_M2.size()) == 0);

if (success) {
LOG_INFO("Server proof M2 verified successfully.");
state_ = State::SERVER_VERIFIED;
return true;
} else {
LOG_ERROR("Server proof M2 verification failed!");
LOG_DEBUG("Expected M2: {}", expected_M2);
return false;
}
}

const std::vector<unsigned char>& SRPClient::get_session_key() const {
if (state_ < State::KEY_COMPUTED)
throw std::logic_error("Session key not computed.");
return *K_;
}