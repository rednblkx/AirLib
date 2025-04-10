#include "dnssd.h"
#include "browse.h"
#include <cstdio>
#include <format>
#include <netinet/in.h>
#include <curl/curl.h>
#include <pthread.h>
#include <string>
#include <vector>

AirDNS::AirDNS(std::string name, uint8_t deviceId[6], uint16_t port, AirFeatures1 features1, AirFeatures2 features2) : name(name), servicePort(port), features1(features1), features2(features2){
    memcpy(this->deviceId.data(), deviceId, 6);
}

static void DNSSD_API BonjourRegistrationHandler(
    DNSServiceRef inRef, DNSServiceFlags inFlags, DNSServiceErrorType inError,
    const char *inName, const char *inType, const char *inDomain,
    void *inContext) {
  printf("dnssd error: %d\n", inError);
}

DNSServiceErrorType AirDNS::registerAP(std::string identifier, std::vector<uint8_t> _pk) {
  TXTRecordRef txtRec;
  const uint8_t *txtPtr;
  uint16_t txtLen;
  uint8_t txtBuf[256];
  char id[18];
  int j = 0;
  for (int i=0; i<deviceId.size(); i++) {
    sprintf(&id[j++], "%02X", deviceId[i]);
    j++;
    i != 5 ? sprintf(&id[j++], ":") : id[j++] = '\0';
  }
  
  std::string features = "";

  const char *_features1 = (const char *)features1;
  const char *_features2 = (const char *)features2;
  
  features.append(_features1).append(",").append(_features2);
  
  TXTRecordCreate(&txtRec, (uint16_t)sizeof(txtBuf), txtBuf);
  TXTRecordSetValue(&txtRec, "deviceid", (uint8_t)strlen(id), id);
  TXTRecordSetValue(&txtRec, "features", features.size(), features.c_str());
  const char *flags = "0x4";
  TXTRecordSetValue(&txtRec, "flags", (uint8_t)strlen(flags), flags);
  const char *model = "AppleTV3,2";
  TXTRecordSetValue(&txtRec, "model", (uint8_t)strlen(model), model);

  TXTRecordSetValue(&txtRec, "pi", (uint8_t)identifier.size(), identifier.c_str());

  std::string pk;
  pk.resize(32 * 2);
  for (int i=0;i<_pk.size();i++) {
    std::snprintf(pk.data() + (i * 2), 2, "%02x", _pk[i]);
  }
  TXTRecordSetValue(&txtRec, "pk", pk.size(), pk.c_str());

  const char *srcvers = "320.17";
  TXTRecordSetValue(&txtRec, "srcvers", (uint8_t)strlen(srcvers), srcvers);

  txtPtr = (const uint8_t *)TXTRecordGetBytesPtr(&txtRec);
  txtLen = TXTRecordGetLength(&txtRec);

  return DNSServiceRegister(&dnsRegPtr, 0, 0, name.c_str(), "_airplay._tcp.", NULL, NULL,
                     htons(servicePort), txtLen, txtPtr, BonjourRegistrationHandler, NULL);
}

void AirDNS::startBrowse(){
  pthread_create(&browse_thread, 0, dns_browse_thread, &this->deviceId);
}