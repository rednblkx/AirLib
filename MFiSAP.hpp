#include <cstdint>
#include <openssl/aes.h>
#include <vector>
#include <string>

typedef struct
{
	AES_KEY				key;
	uint8_t				ctr[ 16 ];
	uint8_t				buf[ 16 ];
	size_t				used;

}	AES_CTR_Context;

class MFiSAP {
  public:
      MFiSAP();
      ~MFiSAP();
      std::vector<uint8_t> certificate;
      void exchange(std::vector<uint8_t> &data, std::vector<uint8_t> &response);
    private:
    void createSignature(std::vector<uint8_t> &data, std::vector<uint8_t> &signature);
    void copyCertificate(std::vector<uint8_t> &certificate);
    void aesCtrEncrypt(AES_CTR_Context *inContext, const uint8_t *inKey, const uint8_t *inNonce, const uint8_t *inSrc, uint8_t *inDst, size_t inLen);
    std::string certificatePath;
    std::string deviceAddress;
    uint8_t sharedSecret[32];
    AES_CTR_Context aesCtx;
    bool aesCreated;
};