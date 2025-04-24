#include "PairingUtils.hpp"
#include "sodium/crypto_aead_chacha20poly1305.h"
#include "sodium/crypto_scalarmult_curve25519.h"
#include <cstddef>
#include <cstdio>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <chrono>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <optional>
#include <nlohmann/json.hpp>
#include "logger.hpp"
// Global mutex for throttling
static std::mutex gPairingGlobalLock;
static uint32_t gPairingMaxTries = 0;
static uint32_t gPairingTries = 0;

// Helper function to convert UUID bytes to string
static std::string UUIDToString(const uint8_t uuid[16]) {
    char uuidStr[37];
    snprintf(uuidStr, sizeof(uuidStr),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    return std::string(uuidStr);
}

void PairingSession::setIdentifier(std::string_view identifier) {
    pImpl->identifier = std::string(identifier);
}

void PairingSession::setMaxTries(int maxTries) {
    std::lock_guard<std::mutex> lock(gPairingGlobalLock);
    gPairingMaxTries = static_cast<uint32_t>(maxTries);
}

void PairingSession::setMTU(size_t mtu) {
    // Calculate max payload size for TLV8 format
    size_t payloadSize = 0;
    size_t n, r;

    if (mtu < 2) return;
    n = mtu - ( 2 * ( mtu / 257 ) );
    r = mtu % 257;
    if (      r  > 1 ) n -= 2;
    else if (r != 0)
      n -= 1;
    payloadSize = n;

    if (payloadSize == 0) {
        throw std::runtime_error("Invalid MTU size");
    }
    mtuPayload = payloadSize;
    mtuTotal = mtu;
}

void PairingSession::setSetupCode(std::string_view setupCode) {
    pImpl->setupCode = std::string(setupCode);
}

// Constructor implementation
PairingSession::PairingSession(const PairingDelegate& inDelegate, SessionType inType, std::string storagePath)
    : delegate(inDelegate)
    , type(inType)
    , storagePath(storagePath)
    , pImpl(std::make_unique<Impl>()) {
    if(storagePath.size() == 0) this->storagePath = std::filesystem::current_path();
    
    pImpl->delegate = inDelegate;

    // Initialize crypto arrays with zeros
    key.fill(0);
    ourCurvePK.fill(0);
    ourCurveSK.fill(0);
    ourEdPK.fill(0);
    ourEdSK.fill(0);
    peerCurvePK.fill(0);
    peerEdPK.fill(0);
    sharedSecret.fill(0);

    initialize_srp_library();

    // Create SRP context if needed
    if (type == SessionType::SetupServer) {
        const SRPParameters& params = SRPPredefinedParameters::RFC5054_3072_SHA512();
        SRPVersion version = SRPVersion::SRP6a;
        srpContext = std::unique_ptr<SRPServer>(new SRPServer(version, params));
    }
}

// Move constructor implementation
PairingSession::PairingSession(PairingSession&& other) noexcept
    : delegate(std::move(other.delegate))
    , type(other.type)
    , mtuPayload(other.mtuPayload)
    , mtuTotal(other.mtuTotal)
    , key(other.key)
    , ourCurvePK(other.ourCurvePK)
    , ourCurveSK(other.ourCurveSK)
    , ourEdPK(other.ourEdPK)
    , ourEdSK(other.ourEdSK)
    , peerCurvePK(other.peerCurvePK)
    , peerEdPK(other.peerEdPK)
    , sharedSecret(other.sharedSecret)
    , srpContext(std::move(other.srpContext))
    , srpPK(std::move(other.srpPK))
    , srpSalt(std::move(other.srpSalt))
    , srpSharedSecret(std::move(other.srpSharedSecret))
    , pImpl(std::move(other.pImpl)) {
    
    // Zero out the source arrays
    other.key.fill(0);
    other.ourCurvePK.fill(0);
    other.ourCurveSK.fill(0);
    other.ourEdPK.fill(0);
    other.ourEdSK.fill(0);
    other.peerCurvePK.fill(0);
    other.peerEdPK.fill(0);
    other.sharedSecret.fill(0);
}

// Move assignment implementation
PairingSession& PairingSession::operator=(PairingSession&& other) noexcept {
    if (this != &other) {
        // Move everything
        delegate = std::move(other.delegate);
        type = other.type;
        mtuPayload = other.mtuPayload;
        mtuTotal = other.mtuTotal;
        key = other.key;
        ourCurvePK = other.ourCurvePK;
        ourCurveSK = other.ourCurveSK;
        ourEdPK = other.ourEdPK;
        ourEdSK = other.ourEdSK;
        peerCurvePK = other.peerCurvePK;
        peerEdPK = other.peerEdPK;
        sharedSecret = other.sharedSecret;
        srpContext = std::move(other.srpContext);
        srpPK = std::move(other.srpPK);
        srpSalt = std::move(other.srpSalt);
        srpSharedSecret = std::move(other.srpSharedSecret);
        pImpl = std::move(other.pImpl);
        
        // Zero out the source arrays
        other.key.fill(0);
        other.ourCurvePK.fill(0);
        other.ourCurveSK.fill(0);
        other.ourEdPK.fill(0);
        other.ourEdSK.fill(0);
        other.peerCurvePK.fill(0);
        other.peerEdPK.fill(0);
        other.sharedSecret.fill(0);
    }
    return *this;
}

// Destructor implementation
PairingSession::~PairingSession() {
    finalize_srp_library();
}

// Exchange function to handle pairing protocol messages
std::pair<std::vector<uint8_t>, bool> PairingSession::exchange(const std::vector<uint8_t>& input) {
    // Reset output fragment buffer if starting new exchange
    if (input.empty()) {
        pImpl->outputBuf.clear();
        pImpl->outputFragmentOffset = 0;
        pImpl->outputDone = false;
    }

    // Process input if we have any
    if (!input.empty()) {
      LOG_DEBUG("input size: {}", input.size());
        pImpl->inputBuf.clear();
        // Append input to fragment buffer
        pImpl->inputBuf.insert(
            pImpl->inputBuf.end(),
            input.begin(),
            input.end()
        );

        // Process the input data
        auto err = progressInput();
        LOG_DEBUG("progressInput err: {}", err);
        if (err != 0) {
            throw std::runtime_error("Failed to process input data");
        }
    }

    // Return any pending output
    std::vector<uint8_t> output;
    if (!pImpl->outputBuf.empty()) {
        LOG_DEBUG("outputFragmentBuf size: {}", pImpl->outputBuf.size());
        size_t remaining = pImpl->outputBuf.size() - pImpl->outputFragmentOffset;
        size_t sendLen = std::min(remaining, mtuPayload);

        output.assign(
            pImpl->outputBuf.begin() + pImpl->outputFragmentOffset,
            pImpl->outputBuf.begin() + pImpl->outputFragmentOffset + sendLen
        );

        pImpl->outputFragmentOffset += sendLen;
        if (pImpl->outputFragmentOffset >= pImpl->outputBuf.size()) {
            pImpl->outputBuf.clear();
            pImpl->outputFragmentOffset = 0;
        }
    }

    return {output, pImpl->outputDone};
}

// Process input data and advance the pairing state machine
int32_t PairingSession::progressInput() {
    try {
        TLV8 responseBuf;

        int32_t err = 0;
        switch (type) {
            case SessionType::SetupServer:
                err = handleSetupServerExchange(responseBuf);
                break;
            case SessionType::VerifyServer:
                err = handleVerifyServerExchange(responseBuf);
                break;
            default:
                throw std::runtime_error("Invalid session type");
        }

        if (err) {
            return err;
        }

        // Copy response to output buffer
        if (responseBuf.size_packed() > 0) {
            LOG_DEBUG("Response TLV: {}", responseBuf);
            pImpl->outputBuf.resize(responseBuf.size_packed());
            pImpl->outputBuf = responseBuf.get();
            pImpl->outputFragmentOffset = 0;
            LOG_DEBUG("outputBuf({}): {:16xL32}", pImpl->outputBuf.size(), pImpl->outputBuf);
        }

        return 0;
    } catch (const std::exception& e) {
        return -1;
    }
}

// Derive encryption keys using HKDF via EVP interface
int32_t PairingSession::deriveKey(std::string_view salt, std::string_view info,
                                  size_t keyLen, std::vector<uint8_t> &outKey,
                                  bool setup, std::vector<uint8_t> optionalSecret)
 {
    outKey.resize(keyLen);
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return -1;
    }

    int32_t err = 0;
    try {
        if (EVP_PKEY_derive_init(ctx) <= 0) throw std::runtime_error("HKDF init failed");
        
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha512()) <= 0) {
            throw std::runtime_error("HKDF set md failed");
        }

        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, 
            reinterpret_cast<const unsigned char*>(salt.data()), 
            salt.length()) <= 0) {
            throw std::runtime_error("HKDF set salt failed");
        }

        if (EVP_PKEY_CTX_set1_hkdf_key(ctx,
            setup ? srpSharedSecret.data() : optionalSecret.empty() ? sharedSecret.data() : optionalSecret.data(),
            setup ? srpSharedSecret.size() : optionalSecret.empty() ? sharedSecret.size() : optionalSecret.size()) <= 0) {
            throw std::runtime_error("HKDF set key failed");
        }

        if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
            reinterpret_cast<const unsigned char*>(info.data()),
            info.length()) <= 0) {
            throw std::runtime_error("HKDF set info failed");
        }

        size_t outLen = keyLen;
        if (EVP_PKEY_derive(ctx, outKey.data(), &outLen) <= 0) {
            throw std::runtime_error("HKDF derive failed");
        }

        if (outLen != keyLen) {
            throw std::runtime_error("HKDF unexpected output length");
        }

    } catch (const std::exception& e) {
        err = -1;
        LOG_ERROR("Key derivation error: {}", e.what());
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

// Handle the initial state for setup server
int32_t PairingSession::handleSetupServerExchange(TLV8& responseBuf) {
    int32_t err = 0;
    const uint8_t* ptr = nullptr;
    const uint8_t* next = nullptr;
    size_t len = 0;
    TLV8 etlv;
    std::vector<uint8_t> storage;
    std::vector<uint8_t> encrypted;
    uint8_t state = 0;

    try {
        // Parse input TLV if we have any
        if (!pImpl->inputBuf.empty()) {
          LOG_DEBUG("inputFragmentBuf size: {}", pImpl->inputBuf.size());
            etlv.parse(pImpl->inputBuf.data(), pImpl->inputBuf.size());
            // Get state
            auto it = etlv.find(6);
            if (it == etlv.end()) throw std::runtime_error("Failed to get state from TLV");
            if (it->length() != 1) throw std::runtime_error("Invalid state length");

            state = *it->data();

            // Reset if starting new session
            if (state == 1) { // kPairSetupStateM1
                pImpl->state = 0;
                pImpl->setupCodeFailed = false;
                pImpl->showingSetupCode = false;
                pImpl->outputDone = false;
            }

            // Verify state matches expected
            if (pImpl->state == 0) pImpl->state = 1;
            if (state != pImpl->state) throw std::runtime_error("Invalid state");

            switch (state) {
            case 1: { // M1: Initial state
                    LOG_DEBUG("Pair-setup server M1 -- start request");

                    // Get method
                    uint8_t method;
                    auto it = etlv.find(0);
                    if (it == etlv.end()) throw std::runtime_error("Failed to get method from TLV");
                    pImpl->requestMethod = *it->data();
                    LOG_DEBUG("requestMethod: {}", pImpl->requestMethod);

                    // Show setup code if we have a delegate
                    if (delegate.showSetupCode_f) {
                        char setupCode[12]; // Format: XXX-XX-XXX\0
                        err = delegate.showSetupCode_f(
                            setupCode,
                            sizeof(setupCode),
                            delegate.context
                        );
                        if (err) throw std::runtime_error("Failed to show setup code");

                        pImpl->setupCode = setupCode;
                        pImpl->showingSetupCode = true;
                    }
                    LOG_DEBUG("SRP server start");
                    LOG_DEBUG("setupCode: {}", pImpl->setupCode.data());
                    srpContext->set_user_password("Pair-Setup", pImpl->setupCode);
                    std::vector<unsigned char> salt = srpContext->get_salt();
                    std::vector<unsigned char> server_B_bytes = srpContext->generate_public_key();
                    LOG_DEBUG("Server: Generated Salt: {}", salt);
                    LOG_DEBUG("Server: Generated Public Key B: {}", server_B_bytes);
                    LOG_DEBUG("SRP server start err: {}", err);
                    if (err) throw std::runtime_error("SRP server start failed");

                    // Store the server public key
                    srpPK.assign(server_B_bytes.begin(), server_B_bytes.end());
                    srpSalt = std::move(salt);
                    pImpl->state = 2;
                    // Build response TLV
                    responseBuf.add(6, pImpl->state);
                    if (err) throw std::runtime_error("Failed to append state to TLV");

                    responseBuf.add(2, srpSalt);
                    if (err) throw std::runtime_error("Failed to append salt to TLV");

                    responseBuf.add(3, server_B_bytes.size(), server_B_bytes.data());
                    if (err) throw std::runtime_error("Failed to append public key to TLV");

                    pImpl->state = 3; // Move to M3
                    break;
                }

                case 3: { // M3: Verify Request
                    LOG_DEBUG("Pair-setup server M3 -- verify request");
                    if (!srpContext) throw std::runtime_error("SRP context not initialized");


                    // Get client public key and proof
                    const uint8_t* clientPKPtr;
                    size_t clientPKLen;
                    uint8_t *					clientPKStorage	= NULL;
	                uint8_t *					proofStorage	= NULL;
                    auto it = etlv.find(3);
                    if (it == etlv.end()) throw std::runtime_error("Failed to get client public key");
                    clientPKPtr = it->data();
                    clientPKLen = it->length();
                    clientPKStorage = it->data();
                    next = it->data() + it->length();

                    const uint8_t* proofPtr;
                    size_t proofLen;
                    it = etlv.find(4);
                    if (it == etlv.end()) throw std::runtime_error("Failed to get client proof");
                    proofPtr = it->data();
                    proofLen = it->length();
                    proofStorage = it->data();
                    next = it->data() + it->length();

                    std::vector<unsigned char> server_K = srpContext->compute_session_key(std::span<const unsigned char>(clientPKPtr, clientPKLen));
                    LOG_INFO("Server: Computed Session Key K: {}", server_K);
                    LOG_INFO("Server: Verifying Client Proof M1");
                    if (srpContext->verify_client_proof(std::span<const unsigned char>(proofPtr, proofLen))) {
                        LOG_INFO("Server: Client proof M1 is valid.");
                    } else {
                        LOG_ERROR("Server: Client proof M1 is INVALID.");
                        throw std::runtime_error("Client proof verification failed");
                    }
                    LOG_INFO("Server: Generating Proof M2");
                    std::vector<unsigned char> server_M2_bytes = srpContext->generate_server_proof();
                    LOG_INFO("Server: Generated Proof M2: {}", server_M2_bytes);
                    if (err) {
                        pImpl->setupCodeFailed = true;
                        uint8_t error = 2;
                        responseBuf.add(7, error);
                        if (err) throw std::runtime_error("Failed to append error to TLV");

                        responseBuf.add(6, pImpl->state);
                        if (err) throw std::runtime_error("Failed to append state to TLV");

                        throw std::runtime_error("SRP verification failed");
                    }

                    // Store the shared secret
                    srpSharedSecret.assign(server_K.begin(), server_K.end());
                    pImpl->state = 4;
                    // Build response TLV
                    responseBuf.add(6, pImpl->state);
                    if (err) throw std::runtime_error("Failed to append state to TLV");

                    responseBuf.add(4, server_M2_bytes.size(), server_M2_bytes.data());
                    if (err) throw std::runtime_error("Failed to append server proof to TLV");

                    // Hide setup code if we were showing it
                    if (pImpl->showingSetupCode && delegate.hideSetupCode_f) {
                        delegate.hideSetupCode_f(delegate.context);
                        pImpl->showingSetupCode = false;
                    }

                    // Derive session key
                    std::string salt = "Pair-Setup-Encrypt-Salt";
                    std::string info = "Pair-Setup-Encrypt-Info";
                    key.fill(0);
                    std::vector<uint8_t> tempKey(key.begin(), key.end());
                    err = deriveKey(salt, info, key.size(), tempKey, true);
                    if (err) throw std::runtime_error("Failed to derive session key");
                    std::copy(tempKey.begin(), tempKey.end(), key.begin());

                    pImpl->state = 5; // Move to M5
                    break;
                }

                case 5: { // M5: Exchange Request
                    LOG_DEBUG("Pair-setup server M5 -- exchange request");
                    if (srpSharedSecret.empty()) throw std::runtime_error("No SRP shared secret available");

                    LOG_DEBUG("TLV types in buffer:");
                    LOG_DEBUG("{}", etlv);
                    // Get and decrypt encrypted data
                    const uint8_t* encryptedPtr;
                    size_t encryptedLen;
                    auto it = etlv.find(5);
                    if (it == etlv.end()) throw std::runtime_error("Failed to get encrypted data");
                    encryptedPtr = it->data();
                    encryptedLen = it->length();
                    if (encryptedLen <= 16) throw std::runtime_error("Encrypted data too short");

                    std::vector<uint8_t> decrypted(encryptedLen - 16);

                    err = crypto_aead_chacha20poly1305_ietf_decrypt(
                        decrypted.data(), NULL, NULL, encryptedPtr,
                        encryptedLen, NULL, 0, (const uint8_t*)"\x00\x00\x00\x00PS-Msg05",
                        key.data()
                    );
                    LOG_DEBUG("Decrypt error: {}", err);
                    if (err != 0) {
                        throw std::runtime_error("Failed to decrypt data");
                    }

                    // Parse decrypted TLV
                    uint8_t *storageIdentifier = nullptr;
                    TLV8 decryptedTLV;
                    decryptedTLV.parse(decrypted.data(), decrypted.size());
                    // Get peer identifier
                    it = decryptedTLV.find(1);
                    if (it == decryptedTLV.end()) throw std::runtime_error("Failed to get peer identifier");
                    ptr = it->data();
                    len = it->length();
                    storageIdentifier = it->data();
                    next = it->data() + it->length();
                    pImpl->activeIdentifier.assign((const char *)ptr, len);
                    LOG_DEBUG("Pair-setup server M5 -- active identifier: {}", pImpl->activeIdentifier.c_str());
                    // Get peer Ed25519 public key
                    it = decryptedTLV.find(3);
                    if (it == decryptedTLV.end()) throw std::runtime_error("Failed to get peer public key");
                    ptr = it->data();
                    len = it->length();
                    memcpy(peerEdPK.data(), ptr, len);
                    if (len != 32) throw std::runtime_error("Invalid public key length");

                    // Get signature
                    std::vector<uint8_t> signature(64);
                    it = decryptedTLV.find(0x0a);
                    if (it == decryptedTLV.end()) throw std::runtime_error("Failed to get signature");
                    ptr = it->data();
                    len = it->length();
                    memcpy(signature.data(), ptr, len);
                    if (len != 64) throw std::runtime_error("Invalid signature length");

                    // Verify signature
                    std::vector<uint8_t> signData;
                    std::vector<uint8_t> signingKey(32);
                    
                    // Derive signing key
                    std::string salt = "Pair-Setup-Controller-Sign-Salt";
                    std::string info = "Pair-Setup-Controller-Sign-Info";
                    err = deriveKey(salt, info, signingKey.size(), signingKey, true);
                    if (err) throw std::runtime_error("Failed to derive signing key");

                    // Build data to verify
                    signData.insert(signData.begin(), signingKey.begin(), signingKey.end());
                    signData.insert(signData.begin() + signingKey.size(), pImpl->activeIdentifier.begin(), pImpl->activeIdentifier.end());
                    signData.insert(signData.begin() + signingKey.size() + pImpl->activeIdentifier.size(), peerEdPK.begin(), peerEdPK.end());
                    LOG_DEBUG("Sign data hexdump ({}): {:16xL32}", signData.size(), signData);
                    LOG_DEBUG("signingkey length: {}", signingKey.size());
                    LOG_DEBUG("pImpl->activeIdentifier length: {}", pImpl->activeIdentifier.size());
                    LOG_DEBUG("peerEdPK length: {}", peerEdPK.size());

                    struct EVP_PKEY_Deleter {
                        void operator()(EVP_PKEY* p) { if(p) EVP_PKEY_free(p); }
                    };
                    
                    struct EVP_MD_CTX_Deleter {
                        void operator()(EVP_MD_CTX* p) { if(p) EVP_MD_CTX_free(p); }
                    };

                    auto verifyKey = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(
                        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, peerEdPK.data(), peerEdPK.size())
                    );
                    if (!verifyKey) throw std::runtime_error("Failed to create Ed25519 key");

                    auto verifyCtx = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>(EVP_MD_CTX_new());
                    if (!verifyCtx) throw std::runtime_error("Failed to create signature context");

                    if (EVP_DigestVerifyInit(verifyCtx.get(), nullptr, nullptr, nullptr, verifyKey.get()) <= 0) {
                        throw std::runtime_error("Failed to init signature verification");
                    }

                    if (EVP_DigestVerify(verifyCtx.get(), signature.data(), signature.size(),
                                       signData.data(), signData.size()) <= 0) {
                        uint8_t error = 2; // kTLVError_Authentication
                        responseBuf.add(7, sizeof(error), &error);
                        if (err) throw std::runtime_error("Failed to append error to TLV");
                        
                        state = 6; // Move to M6
                        responseBuf.add(6, sizeof(state), &state);
                        if (err) throw std::runtime_error("Failed to append state to TLV");
                        
                        throw std::runtime_error("Signature verification failed");
                    }

                    // Save peer
                    err = savePeer(pImpl->activeIdentifier, peerEdPK.data(), delegate.context);
                    if (err) {
                        uint8_t error = 2; // kTLVError_Authentication
                        responseBuf.add(7, sizeof(error), &error);
                        if (err) throw std::runtime_error("Failed to append error to TLV");
                        
                        state = 6; // Move to M6
                        responseBuf.add(6, sizeof(state), &state);
                        if (err) throw std::runtime_error("Failed to append state to TLV");
                        
                        throw std::runtime_error("Failed to save peer");
                    }
                    LOG_DEBUG("Saved peer");

                    // Get our Ed25519 keys
                    if (delegate.copyIdentity_f) {
                        err = delegate.copyIdentity_f(
                            true, // Allow create
                            nullptr,
                            ourEdPK.data(),
                            ourEdSK.data(),
                            delegate.context
                        );
                        if (err) throw std::runtime_error("Failed to get/create identity");
                    } else {
                        auto identity = loadIdentity();
                        if (!identity)
                          throw std::runtime_error("Failed to load identity");
                        pImpl->identifier = identity->identifier;
                        std::copy(identity->publicKey.begin(), identity->publicKey.end(), ourEdPK.begin());
                        std::copy(identity->privateKey.begin(), identity->privateKey.end(), ourEdSK.begin());
                    }

                    // Generate our signature
                    salt = "Pair-Setup-Accessory-Sign-Salt";
                    info = "Pair-Setup-Accessory-Sign-Info";
                    err = deriveKey(salt, info, signingKey.size(), signingKey, true);
                    if (err) throw std::runtime_error("Failed to derive signing key");
                    LOG_DEBUG("identifier: {}", pImpl->identifier.c_str());
                    signData.clear();
                    signData.insert(signData.begin(), signingKey.begin(), signingKey.end());
                    signData.insert(signData.begin() + signingKey.size(), pImpl->identifier.begin(), pImpl->identifier.end());
                    signData.insert(signData.begin() + signingKey.size() + pImpl->identifier.size(), ourEdPK.begin(), ourEdPK.end());

                    signature.resize(64);
                    auto signKey = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(
                        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, ourEdSK.data(), ourEdSK.size())
                    );
                    if (!signKey) throw std::runtime_error("Failed to create Ed25519 key");

                    auto signCtx = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>(EVP_MD_CTX_new());
                    if (!signCtx) throw std::runtime_error("Failed to create signature context");

                    if (EVP_DigestSignInit(signCtx.get(), nullptr, nullptr, nullptr, signKey.get()) <= 0) {
                        throw std::runtime_error("Failed to init signature");
                    }

                    size_t sigLen = signature.size();
                    if (EVP_DigestSign(signCtx.get(), signature.data(), &sigLen, signData.data(), signData.size()) <= 0) {
                        throw std::runtime_error("Failed to create signature");
                    }
                    TLV8 responseTLV;
                    // Build encrypted response
                    responseTLV.add(1, pImpl->identifier.size(), (uint8_t*)pImpl->identifier.data());
                    if (err) throw std::runtime_error("Failed to append identifier to TLV");

                    responseTLV.add(3, ourEdPK.size(), ourEdPK.data());
                    if (err) throw std::runtime_error("Failed to append public key to TLV");

                    responseTLV.add(0x0a, signature.size(), signature.data());
                    if (err)
                      throw std::runtime_error(
                          "Failed to append signature to TLV");
                    auto tlvbuf = std::vector<uint8_t>(responseTLV.size_packed());
                    tlvbuf = responseTLV.get();

                    encrypted.resize(responseTLV.size_packed() + 16);

                    err = crypto_aead_chacha20poly1305_ietf_encrypt(
                        encrypted.data(),
                        NULL,
                        tlvbuf.data(),
                        tlvbuf.size(),
                        NULL,
                        0,
                        NULL,
                        (const uint8_t*)"\x00\x00\x00\x00PS-Msg06",
                        key.data()
                    );

                    state = 6; // Move to M6
                    responseBuf.add(5, encrypted.size(), encrypted.data());
                    if (err) throw std::runtime_error("Failed to append encrypted data to TLV");

                    responseBuf.add(6, sizeof(state), &state);
                    if (err) throw std::runtime_error("Failed to append state to TLV");

                    pImpl->state = 7; // Done
                    pImpl->outputDone = true;
                    break;
                }

                default:
                    throw std::runtime_error("Invalid state");
            }
        }

        pImpl->inputBuf.clear();
        return 0;

    } catch (const std::exception& e) {
      err = -1;
        LOG_ERROR("Setup server exchange error: {}", e.what());
    }

    return err;
}

// Handle verify server exchange
int32_t PairingSession::handleVerifyServerExchange(TLV8& responseBuf) {
    try {
      const uint8_t *ptr = nullptr;
      int32_t err = 0;
        size_t len = 0;
        TLV8 requestTLV;
        requestTLV.parse(pImpl->inputBuf.data(), pImpl->inputBuf.size());
        // Get state from TLV
        auto it = requestTLV.find(6);
        if (it == requestTLV.end() || it->length() != 1) {
            throw std::runtime_error("Failed to get state from TLV");
        }

        // Reset session if starting new verify
        if (*it->data() == 1) { // M1
            pImpl->state = 0;
            key = {};
            ourCurvePK = {};
            ourCurveSK = {};
            peerCurvePK = {};
            sharedSecret = {};
        }

        // Verify state matches expected
        if (pImpl->state == 0) pImpl->state = 1;
        if (*it->data() != pImpl->state) throw std::runtime_error("Invalid state");

        switch (pImpl->state) {
            case 1: { // M1: Start Request
                // Generate new random ECDH key pair
                std::vector<uint8_t> random(32);
                if (!RAND_bytes(random.data(), random.size())) {
                    throw std::runtime_error("Failed to generate random bytes");
                }
                std::copy(random.begin(), random.end(), ourCurveSK.begin());
                // Derive our curve secret key
                std::string salt = "Pair-Verify-ECDH-Salt";
                std::string info = "Pair-Verify-ECDH-Info";
                std::vector<uint8_t> derivedKey(32);
                std::vector<uint8_t> curveSK(ourCurveSK.begin(), ourCurveSK.end());
                if (deriveKey(salt, info, derivedKey.size(), derivedKey, false, curveSK)) {
                    throw std::runtime_error("Failed to derive key");
                }
                std::copy(derivedKey.begin(), derivedKey.end(), ourCurveSK.begin());

                // Generate our curve public key
                crypto_scalarmult_curve25519_base(ourCurvePK.data(), ourCurveSK.data());
                // Get peer's curve public key
                auto it = requestTLV.find(3);
                if (it == requestTLV.end() || it->length() != 32) {
                    throw std::runtime_error("Failed to get peer public key");
                }
                std::copy(it->data(), it->data() + 32, peerCurvePK.begin());
                // Generate shared secret
                crypto_scalarmult_curve25519(sharedSecret.data(), ourCurveSK.data(), peerCurvePK.data());

                // Get our Ed25519 keys
                if (delegate.copyIdentity_f) {
                    if (delegate.copyIdentity_f(true, nullptr, ourEdPK.data(), ourEdSK.data(), delegate.context)) {
                        throw std::runtime_error("Failed to get identity");
                    }
                } else {
                    auto identity = loadIdentity();
                    if (!identity) throw std::runtime_error("Failed to load identity");
                    pImpl->identifier = identity->identifier;
                    std::copy(identity->publicKey.begin(), identity->publicKey.end(), ourEdPK.begin());
                    std::copy(identity->privateKey.begin(), identity->privateKey.end(), ourEdSK.begin());
                }
                LOG_DEBUG("identifier: {}", pImpl->identifier.c_str());
                // Generate signature
                std::vector<uint8_t> signData;
                signData.insert(signData.begin(), ourCurvePK.begin(), ourCurvePK.end());
                signData.insert(signData.begin() + ourCurvePK.size(), pImpl->identifier.begin(), pImpl->identifier.end());
                signData.insert(signData.begin() + ourCurvePK.size() +
                                    pImpl->identifier.size(),
                                peerCurvePK.begin(), peerCurvePK.end());

                LOG_DEBUG("Sign data hexdump ({}): {:16xL32}", signData.size(), signData);

                std::vector<uint8_t> signature(64);
                struct EVP_PKEY_Deleter {
                    void operator()(EVP_PKEY* p) { if(p) EVP_PKEY_free(p); }
                };
                
                struct EVP_MD_CTX_Deleter {
                    void operator()(EVP_MD_CTX* p) { if(p) EVP_MD_CTX_free(p); }
                };

                std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> signKey(
                    EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, ourEdSK.data(), ourEdSK.size())
                );
                if (!signKey) throw std::runtime_error("Failed to create Ed25519 key");

                std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> signCtx(EVP_MD_CTX_new());
                if (!signCtx) throw std::runtime_error("Failed to create signature context");

                if (EVP_DigestSignInit(signCtx.get(), nullptr, nullptr, nullptr, signKey.get()) <= 0) {
                    throw std::runtime_error("Failed to init signature");
                }

                size_t sigLen = signature.size();
                if (EVP_DigestSign(signCtx.get(), signature.data(), &sigLen, signData.data(), signData.size()) <= 0) {
                    throw std::runtime_error("Failed to create signature");
                }

                // Build encrypted response TLV
                TLV8 etlv;
                etlv.add(0x01, pImpl->identifier.size(), (uint8_t*)pImpl->identifier.data());
                etlv.add(0x0A, signature.size(), signature.data());
                auto tlvbuf = std::vector<uint8_t>(etlv.size_packed());
                tlvbuf = etlv.get();

                // Encrypt response
                std::vector<uint8_t> encrypted(etlv.size_packed() + 16);
                std::string saltStr = "Pair-Verify-Encrypt-Salt";
                std::string infoStr = "Pair-Verify-Encrypt-Info";
                std::vector<uint8_t> keyVec(32);
                if (deriveKey(saltStr, infoStr, keyVec.size(), keyVec)) {
                    throw std::runtime_error("Failed to derive encryption key");
                }
                std::copy(keyVec.begin(), keyVec.end(), key.begin());

                struct EVP_CIPHER_CTX_Deleter {
                    void operator()(EVP_CIPHER_CTX* p) { if(p) EVP_CIPHER_CTX_free(p); }
                };
                
                err = crypto_aead_chacha20poly1305_ietf_encrypt(
                    encrypted.data(),
                    NULL,
                    tlvbuf.data(),
                    tlvbuf.size(),
                    NULL,
                    0,
                    NULL,
                    (const uint8_t*)"\x00\x00\x00\x00PV-Msg02",
                    key.data()
                );

                // Build final response
                pImpl->state = 2; // M2
                responseBuf.add(0x06, sizeof(pImpl->state), &pImpl->state);
                if (err) throw std::runtime_error("Failed to append state to TLV");

                responseBuf.add(0x03, ourCurvePK.size(), ourCurvePK.data());
                if (err) throw std::runtime_error("Failed to append public key to TLV");

                responseBuf.add(0x05, encrypted.size(), encrypted.data());
                if (err) throw std::runtime_error("Failed to append encrypted data to TLV");

                pImpl->state = 3; // Ready for M3
                break;
            }

            case 3: { // M3: Finish Request
                // Get encrypted data
                const uint8_t* ptr = nullptr;
                size_t len = 0;
                auto it = requestTLV.find(5);
                if (it == requestTLV.end()) {
                    throw std::runtime_error("Failed to get encrypted data");
                }
                ptr = it->data();
                len = it->length();

                if (len <= 16) throw std::runtime_error("Encrypted data too short");

                // Decrypt data
                std::vector<uint8_t> decrypted(len - 16);
                err = crypto_aead_chacha20poly1305_ietf_decrypt(
                    decrypted.data(), NULL, NULL, ptr, len, NULL, 0, (const uint8_t*)"\x00\x00\x00\x00PV-Msg03", key.data());
                if (err != 0) {
                    LOG_DEBUG("Decryption failed");
                    // Authentication failed
                    pImpl->state = 4;
                    responseBuf.add(0x07, sizeof("\x02"), (uint8_t*)"\x02");
                    if (err) throw std::runtime_error("Failed to append error to TLV");

                    responseBuf.add(0x06, sizeof(pImpl->state), &pImpl->state);
                    if (err) throw std::runtime_error("Failed to append state to TLV");

                    return 0;
                }

                // Parse decrypted TLV
                TLV8 decryptedTLV;
                decryptedTLV.parse(decrypted.data(), decrypted.size());
                // Get peer identifier
                std::string peerIdentifier;
                it = decryptedTLV.find(1);
                if (it == decryptedTLV.end()) {
                    throw std::runtime_error("Failed to get peer identifier");
                }
                ptr = it->data();
                len = it->length();
                peerIdentifier.assign(reinterpret_cast<const char*>(ptr), len);

                // Find peer's public key
                std::array<uint8_t, 32> peerPK;
                if (delegate.findPeer_f) {
                    if (delegate.findPeer_f(peerIdentifier.data(), peerIdentifier.size(), 
                                          peerPK.data(), delegate.context)) {
                        // Peer not found
                        pImpl->state = 4;
                        responseBuf.add(0x07, sizeof("\x02"), (uint8_t*)"\x02");
                        if (err) throw std::runtime_error("Failed to append error to TLV");

                        responseBuf.add(0x06, sizeof(pImpl->state), &pImpl->state);
                        if (err) throw std::runtime_error("Failed to append state to TLV");

                        return 0;
                    }
                } else {
                    auto peer = findPeer(peerIdentifier);
                    if (!peer) {
                        LOG_DEBUG("Peer not found");
                        // Peer not found
                        pImpl->state = 4;
                        responseBuf.add(0x07, sizeof("\x02"), (uint8_t*)"\x02");
                        if (err) throw std::runtime_error("Failed to append error to TLV");

                        responseBuf.add(0x06, sizeof(pImpl->state), &pImpl->state);
                        if (err) throw std::runtime_error("Failed to append state to TLV");

                        return 0;
                    }
                    std::copy(peer->publicKey.begin(), peer->publicKey.end(), peerPK.begin());
                }

                // Verify signature
                std::vector<uint8_t> signature(64);
                it = decryptedTLV.find(0x0A);
                if (it == decryptedTLV.end()) {
                    throw std::runtime_error("Failed to get signature");
                }
                ptr = it->data();
                len = it->length();
                memcpy(signature.data(), ptr, len);

                std::vector<uint8_t> signData;
                signData.insert(signData.end(), peerCurvePK.begin(), peerCurvePK.end());
                signData.insert(signData.end(), peerIdentifier.begin(), peerIdentifier.end());
                signData.insert(signData.end(), ourCurvePK.begin(), ourCurvePK.end());

                struct EVP_PKEY_Deleter {
                    void operator()(EVP_PKEY* p) { if(p) EVP_PKEY_free(p); }
                };

                struct EVP_MD_CTX_Deleter {
                    void operator()(EVP_MD_CTX* p) { if(p) EVP_MD_CTX_free(p); }
                };

                std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> verifyKey(
                    EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, 
                        peerPK.data(), peerPK.size())
                );
                if (!verifyKey) throw std::runtime_error("Failed to create Ed25519 key");

                std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> verifyCtx(EVP_MD_CTX_new());
                if (!verifyCtx) throw std::runtime_error("Failed to create signature context");

                if (EVP_DigestVerifyInit(verifyCtx.get(), nullptr, nullptr, nullptr, verifyKey.get()) <= 0) {
                    throw std::runtime_error("Failed to init signature verification");
                }

                if (EVP_DigestVerify(verifyCtx.get(), signature.data(), signature.size(),
                                   signData.data(), signData.size()) <= 0) {
                    LOG_DEBUG("Signature verification failed");
                    // Signature verification failed
                    pImpl->state = 4;
                    responseBuf.add(0x07, sizeof("\x02"), (uint8_t*)"\x02");
                    if (err) throw std::runtime_error("Failed to append error to TLV");

                    responseBuf.add(0x06, sizeof(pImpl->state), &pImpl->state);
                    if (err) throw std::runtime_error("Failed to append state to TLV");

                    return 0;
                }

                // Build success response
                pImpl->state = 4;
                responseBuf.add(0x06, sizeof(pImpl->state), &pImpl->state);
                if (err) throw std::runtime_error("Failed to append state to TLV");

                pImpl->state = 5; // Done
                pImpl->outputDone = true;
                pImpl->activeIdentifier = peerIdentifier;
                break;
            }

            default:
                throw std::runtime_error("Invalid state");
        }

        return 0;
    } catch (const std::exception &e) {
        LOG_ERROR("Error: {}", e.what());
        // Reset session state on error
        pImpl->state = 0;
        key = {};
        ourCurvePK = {};
        ourCurveSK = {};
        peerCurvePK = {};
        sharedSecret = {};
        return -1;
    }
}

// Peer management functions
struct PeerInfo {
    std::string identifier;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> signature;
    bool isAdmin{false};
    std::chrono::system_clock::time_point lastSeen;
};

// Find a peer by identifier
std::optional<PairingSession::PeerInfo> PairingSession::findPeer(std::string_view identifier) {
    int32_t err = 0;
    PairingSession::PeerInfo peer;

    try {
        // Get storage path from delegate
        if (err) throw std::runtime_error("Failed to get storage path");

        // Load peer data from JSON file
        std::string peerPath = storagePath + "/peers/" + std::string(identifier) + ".json";
        std::ifstream file(peerPath);
        if (!file.is_open()) {
            return std::nullopt;
        }

        nlohmann::json j;
        file >> j;

        // Parse peer data
        peer.identifier = j["identifier"].get<std::string>();
        peer.publicKey = j["publicKey"].get<std::vector<uint8_t>>();
        peer.signature = j["signature"].get<std::vector<uint8_t>>();
        peer.isAdmin = j["isAdmin"].get<bool>();
        peer.lastSeen = std::chrono::system_clock::from_time_t(j["lastSeen"].get<int64_t>());

        return peer;

    } catch (const std::exception& e) {
        return std::nullopt;
    }
}

int32_t PairingSession::savePeer(std::string_view identifier, const uint8_t peerPK[32], void *inContext) {
    int32_t err = 0;

    try {
        // Create peers directory if it doesn't exist
        std::string peersDir = storagePath + "/peers";
        std::filesystem::create_directories(peersDir);

        // Create peer info
        PeerInfo peer;
        peer.identifier = std::string(identifier);
        peer.publicKey.assign(peerPK, peerPK + 32);
        peer.isAdmin = false; // Default to non-admin
        peer.lastSeen = std::chrono::system_clock::now();

        // Generate signature over identifier using our Ed25519 secret key
        std::vector<uint8_t> signData;
        signData.insert(signData.end(), peer.identifier.begin(), peer.identifier.end());
        signData.insert(signData.end(), peer.publicKey.begin(), peer.publicKey.end());

        std::vector<uint8_t> signature(64); // Ed25519 signatures are 64 bytes
        EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, ourEdSK.data(), ourEdSK.size());
        if(!key) throw std::runtime_error("Failed to create Ed25519 key");

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if(!ctx) {
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to create signature context");
        }

        if(EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to init signature");
        }

        size_t sigLen = signature.size();
        if(EVP_DigestSign(ctx, signature.data(), &sigLen, signData.data(), signData.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to create signature");
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);

        peer.signature = std::move(signature);

        // Convert peer data to JSON
        nlohmann::json j;
        j["identifier"] = peer.identifier;
        j["publicKey"] = peer.publicKey;
        j["signature"] = peer.signature;
        j["isAdmin"] = peer.isAdmin;
        j["lastSeen"] = std::chrono::system_clock::to_time_t(peer.lastSeen);

        std::string peerPath = peersDir + "/" + std::string(identifier) + ".json";
        std::string tempPath = peerPath + ".tmp";

        // Write to temporary file first
        std::ofstream file(tempPath);
        if(!file.is_open()) {
            throw std::runtime_error("Failed to create peer file");
        }
        file << j.dump(4);
        file.close();

        // Rename temporary file to final name
        std::filesystem::rename(tempPath, peerPath);

    } catch(const std::exception& e) {
        err = -1;
        LOG_ERROR("Save peer error: {}", e.what());
    }

    return err;
}

// Update or store peer information
int32_t PairingSession::updatePeer(const PeerInfo& peer) {
    int32_t err = 0;

    try {
        // Create peers directory if it doesn't exist
        std::string peersDir = storagePath + "/peers";
        std::filesystem::create_directories(peersDir);

        // Convert peer data to JSON
        nlohmann::json j;
        j["identifier"] = peer.identifier;
        j["publicKey"] = peer.publicKey;
        j["signature"] = peer.signature;
        j["isAdmin"] = peer.isAdmin;
        j["lastSeen"] = std::chrono::system_clock::to_time_t(peer.lastSeen);

        // Write to file atomically
        std::string peerPath = peersDir + "/" + peer.identifier + ".json";
        std::string tempPath = peerPath + ".tmp";

        // Write to temporary file first
        std::ofstream file(tempPath);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to create peer file");
        }
        file << j.dump(4);
        file.close();

        // Rename temporary file to final name
        std::filesystem::rename(tempPath, peerPath);

    } catch (const std::exception& e) {
        err = -1;
        LOG_ERROR("Update peer error: {}", e.what());
    }

    return err;
}

// Delete a peer
int32_t PairingSession::deletePeer(std::string_view identifier) {
    int32_t err = 0;

    try {
        // Delete peer file
        std::string peerPath = storagePath + "/peers/" + std::string(identifier) + ".json";
        std::filesystem::remove(peerPath);

    } catch (const std::exception& e) {
        err = -1;
        LOG_ERROR("Delete peer error: {}", e.what());
    }

    return err;
}

// List all peers
std::vector<PairingSession::PeerInfo> PairingSession::listPeers() {
    std::vector<PairingSession::PeerInfo> peers;

    try {
        // Iterate through peers directory
        std::string peersDir = storagePath + "/peers";
        if (!std::filesystem::exists(peersDir)) {
            return peers;
        }

        for (const auto& entry : std::filesystem::directory_iterator(peersDir)) {
            if (entry.path().extension() != ".json") continue;

            try {
                // Load peer data
                std::ifstream file(entry.path());
                if (!file.is_open()) continue;

                nlohmann::json j;
                file >> j;

                PeerInfo peer;
                peer.identifier = j["identifier"].get<std::string>();
                peer.publicKey = j["publicKey"].get<std::vector<uint8_t>>();
                peer.signature = j["signature"].get<std::vector<uint8_t>>();
                peer.isAdmin = j["isAdmin"].get<bool>();
                peer.lastSeen = std::chrono::system_clock::from_time_t(j["lastSeen"].get<int64_t>());

                peers.push_back(std::move(peer));

            } catch (const std::exception& e) {
                LOG_ERROR("Failed to load peer {}: {}", entry.path().string().c_str(), e.what());
                continue;
            }
        }

    } catch (const std::exception& e) {
        LOG_ERROR("List peers error: {}", e.what());
    }

    return peers;
}

// Identity management functions
struct IdentityInfo {
    std::string identifier;  // UUID v4
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> signature;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastUsed;
};

void UUIDGet(void *outUUID) {
  uint8_t *uuid = (uint8_t *)outUUID;

  // Generate 16 random bytes
  for (int i = 0; i < 16; i++) {
    uuid[i] = rand() % 256;
  }

  // Apply UUID version and variant bits
  uuid[6] = (uuid[6] & 0x0F) | 0x40; // Set version to 4
  uuid[8] = (uuid[8] & 0x3F) | 0x80; // Set variant to RFC4122
}

// Create a new identity
int32_t PairingSession::createIdentity() {
    int32_t err = 0;

    try {
        // Create identities directory if it doesn't exist
        std::string identitiesDir = storagePath + "/identities";
        std::filesystem::create_directories(identitiesDir);

        uint8_t uuid[16];
        UUIDGet(uuid);
        std::string identifier = UUIDToString(uuid);

        // Generate Ed25519 key pair
        std::vector<uint8_t> publicKey(32);
        std::vector<uint8_t> privateKey(32);

        EVP_PKEY* key = EVP_PKEY_new();
        if (!key) throw std::runtime_error("Failed to create key");

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) {
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to create key context");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to init key generation");
        }

        if (EVP_PKEY_keygen(ctx, &key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to generate key pair");
        }

        EVP_PKEY_CTX_free(ctx);

        size_t pkLen = publicKey.size();
        size_t skLen = privateKey.size();
        if (EVP_PKEY_get_raw_public_key(key, publicKey.data(), &pkLen) <= 0 ||
            EVP_PKEY_get_raw_private_key(key, privateKey.data(), &skLen) <= 0) {
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to export key pair");
        }

        EVP_PKEY_free(key);

        // Generate signature over identifier using private key
        std::vector<uint8_t> signature(64); // Ed25519 signatures are 64 bytes
        key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privateKey.data(), privateKey.size());
        if (!key) throw std::runtime_error("Failed to create signing key");

        EVP_MD_CTX* signCtx = EVP_MD_CTX_new();
        if (!signCtx) {
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to create signature context");
        }

        if (EVP_DigestSignInit(signCtx, nullptr, nullptr, nullptr, key) <= 0) {
            EVP_MD_CTX_free(signCtx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to init signature");
        }

        size_t sigLen = signature.size();
        if (EVP_DigestSign(signCtx, signature.data(), &sigLen,
            reinterpret_cast<const uint8_t*>(identifier.data()), identifier.size()) <= 0) {
            EVP_MD_CTX_free(signCtx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to create signature");
        }

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(key);

        // Create identity info
        IdentityInfo identity;
        identity.identifier = std::string(identifier);
        identity.publicKey = std::move(publicKey);
        identity.privateKey = std::move(privateKey);
        identity.signature = std::move(signature);
        identity.createdAt = std::chrono::system_clock::now();
        identity.lastUsed = identity.createdAt;

        // Convert to JSON
        nlohmann::json j;
        j["identifier"] = identity.identifier;
        j["publicKey"] = identity.publicKey;
        j["privateKey"] = identity.privateKey;
        j["signature"] = identity.signature;
        j["createdAt"] = std::chrono::system_clock::to_time_t(identity.createdAt);
        j["lastUsed"] = std::chrono::system_clock::to_time_t(identity.lastUsed);

        // Write to file atomically
        std::string identityPath = identitiesDir + "/identity.json";
        std::string tempPath = identityPath + ".tmp";

        std::ofstream file(tempPath);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to create identity file");
        }
        file << j.dump(4);
        file.close();

        std::filesystem::rename(tempPath, identityPath);

    } catch (const std::exception& e) {
        err = -1;
        LOG_ERROR("Create identity error: {}", e.what());
    }

    return err;
}

// Load the identity
std::optional<PairingSession::IdentityInfo> PairingSession::loadIdentity() {
    int32_t err = 0;
    IdentityInfo identity;

    try {
        // Load identity data from JSON file
        std::string identityPath = storagePath + "/identities/identity.json";
        std::ifstream file(identityPath);
        if (!file.is_open()) {
            // Create new identity if file doesn't exist
            err = createIdentity();
            if (err) {
                LOG_ERROR("Failed to create identity");
                return std::nullopt;
            }

            // Try loading again
            file.open(identityPath);
            if (!file.is_open()) {
                LOG_ERROR("Failed to open newly created identity file {}", identityPath.c_str());
                return std::nullopt;
            }
        }

        nlohmann::json j;
        file >> j;

        // Parse identity data
        identity.identifier = j["identifier"].get<std::string>();
        identity.publicKey = j["publicKey"].get<std::vector<uint8_t>>();
        identity.privateKey = j["privateKey"].get<std::vector<uint8_t>>();
        identity.signature = j["signature"].get<std::vector<uint8_t>>();
        identity.createdAt = std::chrono::system_clock::from_time_t(j["createdAt"].get<int64_t>());
        identity.lastUsed = std::chrono::system_clock::from_time_t(j["lastUsed"].get<int64_t>());

        // Verify the signature
        EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, 
            identity.publicKey.data(), identity.publicKey.size());
        if (!key) throw std::runtime_error("Failed to create verification key");

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to create verification context");
        }

        if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Failed to init signature verification");
        }

        if (EVP_DigestVerify(ctx, identity.signature.data(), identity.signature.size(),
            reinterpret_cast<const uint8_t*>(identity.identifier.data()), 
            identity.identifier.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw std::runtime_error("Signature verification failed");
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);

        // Update last used time
        identity.lastUsed = std::chrono::system_clock::now();
        j["lastUsed"] = std::chrono::system_clock::to_time_t(identity.lastUsed);

        // Write updated data back
        file.close();
        std::ofstream outFile(identityPath);
        if (outFile.is_open()) {
            outFile << j.dump(4);
        }

        return identity;

    } catch (const std::exception &e) {
        LOG_ERROR("Load identity error: {}", e.what());
        return std::nullopt;
    }
}

// Delete the identity
int32_t PairingSession::deleteIdentity() {
    int32_t err = 0;

    try {
        // Delete identity file
        std::string identityPath = storagePath + "/identities/identity.json";
        std::filesystem::remove(identityPath);

    } catch (const std::exception& e) {
        err = -1;
        LOG_ERROR("Delete identity error: {}", e.what());
    }

    return err;
}

// List all identities (now just returns the single identity if it exists)
std::vector<PairingSession::IdentityInfo> PairingSession::listIdentities() {
    std::vector<IdentityInfo> identities;

    try {
        // Load single identity file
        std::string identityPath = storagePath + "/identities/identity.json";
        if (!std::filesystem::exists(identityPath)) {
            return identities;
        }

        std::ifstream file(identityPath);
        if (!file.is_open()) return identities;

        nlohmann::json j;
        file >> j;

        IdentityInfo identity;
        identity.identifier = j["identifier"].get<std::string>();
        identity.publicKey = j["publicKey"].get<std::vector<uint8_t>>();
        identity.privateKey = j["privateKey"].get<std::vector<uint8_t>>();
        identity.signature = j["signature"].get<std::vector<uint8_t>>();
        identity.createdAt = std::chrono::system_clock::from_time_t(j["createdAt"].get<int64_t>());
        identity.lastUsed = std::chrono::system_clock::from_time_t(j["lastUsed"].get<int64_t>());

        identities.push_back(std::move(identity));

    } catch (const std::exception& e) {
        LOG_ERROR("List identities error: {}", e.what());
    }

    return identities;
}