#include "MFiSAP.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <curl/curl.h>
#include <filesystem>
#include <openssl/sha.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "logger.hpp"

struct memory {
    char *response;
    size_t size;
};

struct WriteThis {
    const char *readptr;
    size_t sizeleft;
};

static size_t read_callback(char *dest, size_t size, size_t nmemb, void *userp)
{
    struct WriteThis *wt = (struct WriteThis *)userp;
    size_t buffer_size = size*nmemb;

    if(wt->sizeleft) {
        size_t copy_this_much = wt->sizeleft;
        if(copy_this_much > buffer_size)
            copy_this_much = buffer_size;
        memcpy(dest, wt->readptr, copy_this_much);

        wt->readptr += copy_this_much;
        wt->sizeleft -= copy_this_much;
        return copy_this_much;
    }

    return 0;
}

static size_t cb(char *data, size_t size, size_t nmemb, void *clientp)
{
  size_t realsize = size * nmemb;
  struct memory *mem = (struct memory *)clientp;

  char *ptr = (char *)realloc(mem->response, mem->size + realsize + 1);
  if(!ptr)
      return 0;  /* out of memory */

  mem->response = ptr;
  memcpy(&mem->response[mem->size], data, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;

  return realsize;
}

MFiSAP::MFiSAP() {
  curl_global_init(CURL_GLOBAL_NOTHING);
  const char *configPath = std::getenv("CONFIG_FOLDER_PATH");
  const char *address = std::getenv("MFI_ADDRESS");
  if(address) deviceAddress = address;
  certificatePath = configPath ? std::format("{}{}",configPath, "/airplay.pem") : std::filesystem::current_path().string() + "/airplay.pem";
  copyCertificate(certificate);
}

#define	WriteBig32( PTR, X ) \
	do \
	{ \
		( (uint8_t *)(PTR) )[ 0 ] = (uint8_t)( ( (X) >> 24 ) & 0xFF ); \
		( (uint8_t *)(PTR) )[ 1 ] = (uint8_t)( ( (X) >> 16 ) & 0xFF ); \
		( (uint8_t *)(PTR) )[ 2 ] = (uint8_t)( ( (X) >>  8 ) & 0xFF ); \
		( (uint8_t *)(PTR) )[ 3 ] = (uint8_t)(   (X)         & 0xFF ); \
	\
	}	while( 0 )

MFiSAP::~MFiSAP() { curl_global_cleanup(); }

void MFiSAP::copyCertificate(std::vector<uint8_t> &certificate) {
    const char* configPath;
    if(deviceAddress.empty()){
        LOG_WARN("No address set for the MFi chip, cannot continue!");
        return;
    }
    FILE *file = fopen(certificatePath.c_str(), "r");
    if (file) {
        LOG_DEBUG("Copying certificate from {}", certificatePath);
        fseek(file, 0, SEEK_END);
        size_t fileSize = ftell(file);
        rewind(file);
        certificate.resize(fileSize);
        fread(certificate.data(), 1, fileSize, file);
        fclose(file);
        return;
    }
    CURL * curl;
    CURLcode res;
    struct memory chunk = {0};

    curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, std::format("http://{}/certificate", deviceAddress).c_str());

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
 
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* Perform the request, res gets the return code */
    res = curl_easy_perform(curl);

    LOG_DEBUG("curl res = {}", curl_easy_strerror(res));
    /* Check for errors */
    if(res != CURLE_OK){
        LOG_ERROR("curl_easy_perform() failed: {}", curl_easy_strerror(res));
        return;
    }

    certificate.resize(chunk.size);

    memcpy(certificate.data(), chunk.response, chunk.size);

    free(chunk.response);

    /* always cleanup */
    curl_easy_cleanup(curl);
    FILE *fp = fopen(certificatePath.c_str(), "wb");
    if (fp) {
        fwrite(certificate.data(), 1, certificate.size(), fp);
        fclose(fp);
    } else {
        LOG_ERROR("Failed to open certificate file for writing");
    }
}

void MFiSAP::createSignature(std::vector<uint8_t> &data, std::vector<uint8_t> &signature) {
    struct WriteThis wt;
    struct memory chunk = {0};
 
    wt.readptr = (const char *)data.data();
    wt.sizeleft = data.size();

    CURL * curl;
    CURLcode res;
    struct curl_slist *slist = NULL;

    curl = curl_easy_init();
	
    LOG_DEBUG("MFi auth create signature");
 
    /* Remove a header curl would otherwise add by itself */
    slist = curl_slist_append(slist, "Content-Type: application/octet-stream");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
	
    curl_easy_setopt(curl, CURLOPT_URL, std::format("http://{}/get-signature", deviceAddress).c_str());
    
    /* Now specify we want to POST data */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
 
    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
 
    /* pointer to pass to our read function */
    curl_easy_setopt(curl, CURLOPT_READDATA, &wt);
 
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
 
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* get verbose debug output please */
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)wt.sizeleft);


    /* Perform the request, res gets the return code */
    res = curl_easy_perform(curl);

    LOG_DEBUG("curl res = {}", curl_easy_strerror(res));
    /* Check for errors */
    if(res != CURLE_OK){
        LOG_ERROR("curl_easy_perform() failed: {}", curl_easy_strerror(res));
        return;
    }

    signature.resize(chunk.size);

    memcpy(signature.data(), chunk.response, chunk.size);

    free(chunk.response);
    /* always cleanup */
    curl_easy_cleanup(curl);

    curl_slist_free_all(slist);
}

void MFiSAP::aesCtrEncrypt(AES_CTR_Context *ctx, const uint8_t *key,
                           const uint8_t *nonce, const uint8_t *plainText,
                           uint8_t *cipherText, size_t len) {
    AES_set_encrypt_key(key, 128, &ctx->key);
    memcpy(ctx->ctr, nonce, 16);
    ctx->used = 0;
    size_t used = ctx->used;
    const uint8_t *		src = plainText;
	uint8_t *			dst = cipherText;
	uint8_t *			buf = ctx->buf;
    size_t i;
	
	// If there's any buffered key material from a previous block then use that first.
	
	while( ( len > 0 ) && ( used != 0 ) ) 
	{
		*dst++ = *src++ ^ buf[ used++ ];
		used %= 16;
		len -= 1;
	}
	ctx->used = used;
	// Process whole blocks.
	
	while( len >= 16 )
	{
		AES_encrypt( ctx->ctr, buf, &ctx->key );
		for (int i = 15; i >= 0; --i) {
            if (++(ctx->ctr[i]) != 0) {
                break;
            }
        }
		for( i = 0; i < 16; ++i )
		{
			dst[ i ] = src[ i ] ^ buf[ i ];
		}
		src   += 16;
		dst   += 16;
		len -= 16;
	}
	
	// Process any trailing sub-block bytes. Extra key material is buffered for next time.
	
	if( len > 0 )
	{
		AES_encrypt( ctx->ctr, buf, &ctx->key );
		for (int i = 15; i >= 0; --i) {
            if (++(ctx->ctr[i]) != 0) {
                break;
            }
        }
		for( i = 0; i < len; ++i )
		{
			*dst++ = *src++ ^ buf[ used++ ];
		}
		ctx->used = used;
	}
}

void MFiSAP::exchange(std::vector<uint8_t> &data, std::vector<uint8_t> &response) {
    LOG_DEBUG("MFi auth exchange");
    int err = 0;
    std::array<uint8_t, 32> peerPK;
    std::array<uint8_t, 32> ourSK;
    std::array<uint8_t, 32> ourPK;
    SHA_CTX sha1Ctx;
    std::array<uint8_t, 20> digest;
    std::vector<uint8_t> signature;
    std::array<uint8_t, 20> aesKey; // Only 16 bytes needed for AES, but 20 bytes needed to store full SHA-1 hash.
    std::array<uint8_t, 20> aesIV;
    size_t len;

    uint8_t version = data.data()[0];
    if (version != 1) {
        LOG_ERROR("Error: Version != 1");
        return;
    }
    memcpy(peerPK.data(), data.data() + 1, 32);

    // Generate a random ECDH key pair.
    RAND_bytes( ourSK.data(), ourSK.size() );

    crypto_scalarmult_curve25519_base(ourPK.data(), ourSK.data());

    // Use our private key and the client's public key to generate the shared secret.
    // Hash the shared secret with salt and truncate to form the AES key and IV.

    err = crypto_scalarmult_curve25519(sharedSecret, ourSK.data(), peerPK.data());
    if (err != 0) {
        LOG_ERROR("Error: crypto_scalarmult_curve25519 failed");
        return;
    }
    SHA1_Init(&sha1Ctx);
    SHA1_Update(&sha1Ctx, "AES-KEY", sizeof("AES-KEY") - 1);
    SHA1_Update(&sha1Ctx, sharedSecret, sizeof(sharedSecret));
    SHA1_Final(aesKey.data(), &sha1Ctx);

    SHA1_Init(&sha1Ctx);
    SHA1_Update(&sha1Ctx, "AES-IV", sizeof("AES-IV") - 1);
    SHA1_Update(&sha1Ctx, sharedSecret, sizeof(sharedSecret));
    SHA1_Final(aesIV.data(), &sha1Ctx);

    // Use the auth chip to sign a hash of <32:our ECDH public key> <32:client's ECDH public key>.
    // And copy the auth chip's certificate so the client can verify the signature.

    SHA1_Init(&sha1Ctx);
    SHA1_Update(&sha1Ctx, ourPK.data(), ourPK.size());
    SHA1_Update(&sha1Ctx, peerPK.data(), peerPK.size());
    SHA1_Final(digest.data(), &sha1Ctx);
    LOG_DEBUG("Digest: {}", digest);
    std::vector<uint8_t> digestVec(digest.begin(), digest.end());
    createSignature(digestVec, signature);
    LOG_DEBUG("Signature: {}", signature);

    std::vector<uint8_t> encryptedSignature(signature.size());
    aesCtrEncrypt(&aesCtx, aesKey.data(), aesIV.data(), signature.data(), encryptedSignature.data(), signature.size());

    bool aesValid = true;

    // Return the response:
    //
    //      <32:our ECDH public key>
    //      <4:big endian certificate length>
    //      <N:certificate data>
    //      <4:big endian signature length>
    //      <N:encrypted signature data>

    len = 32 + 4 + certificate.size() + 4 + encryptedSignature.size();
    std::vector<uint8_t> buf(len);
    uint8_t *dst = buf.data();
    memcpy(dst, ourPK.data(), ourPK.size()); dst += ourPK.size();
    WriteBig32(dst, certificate.size()); dst += 4;
    memcpy(dst, certificate.data(), certificate.size()); dst += certificate.size();
    WriteBig32(dst, encryptedSignature.size()); dst += 4;
    memcpy(dst, encryptedSignature.data(), encryptedSignature.size()); dst += encryptedSignature.size();

    LOG_DEBUG("Our Public Key: {}", ourPK);

    LOG_DEBUG("Certificate: {}", certificate);

    LOG_DEBUG("Encrypted Signature: {}", encryptedSignature);

    if (dst != (buf.data() + len)) {
        LOG_ERROR("Error: Size mismatch in output buffer");
    }

    response = buf;
}