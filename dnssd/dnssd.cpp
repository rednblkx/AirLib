#include "dnssd.hpp"
#include <cstdio>
#include <netinet/in.h>
#include <curl/curl.h>
#include <string>
#include <vector>
#include "logger.hpp"
#include <thread>

#ifdef ANDROID
extern void registerBonjour(const std::string& name, const uint16_t& port, std::map<std::string, std::string>& records) __attribute__((weak));
extern void browseService(const std::string&) __attribute__((weak));
#endif
#ifdef LINUX
 void dns_browse_thread(std::array<uint8_t, 6>& deviceId);
#endif

AirDNS::AirDNS(std::string name, uint8_t deviceId[6], uint16_t port, AirFeatures1 features1, AirFeatures2 features2) : name(name), servicePort(port), features1(features1), features2(features2) {
    memcpy(this->deviceId.data(), deviceId, 6);
}

int AirDNS::registerAP(const std::string& identifier, std::vector<uint8_t> _pk) {
  int err = 0;
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

  std::string features;

  const char *_features1 = (const char *)features1;
  const char *_features2 = (const char *)features2;

  features.append(_features1).append(",").append(_features2);

    const char *flags = "0x4";
    const char *model = "AppleTV3,2";
    std::string pk;
    pk.resize(32 * 2);
    for (int i=0;i<_pk.size();i++) {
        std::snprintf(pk.data() + (i * 2), 3, "%02x", _pk[i]);
    }
    const char *srcvers = "320.17";
#ifdef LINUX
    TXTRecordRef txtRec;
    TXTRecordCreate(&txtRec, (uint16_t)sizeof(txtBuf), txtBuf);
    TXTRecordSetValue(&txtRec, "deviceid", (uint8_t)strlen(id), id);
    TXTRecordSetValue(&txtRec, "features", features.size(), features.c_str());
    TXTRecordSetValue(&txtRec, "flags", (uint8_t)strlen(flags), flags);
    TXTRecordSetValue(&txtRec, "model", (uint8_t)strlen(model), model);

    TXTRecordSetValue(&txtRec, "pi", (uint8_t)identifier.size(), identifier.c_str());

    TXTRecordSetValue(&txtRec, "pk", pk.size(), pk.c_str());

  TXTRecordSetValue(&txtRec, "srcvers", (uint8_t)strlen(srcvers), srcvers);

  txtPtr = (const uint8_t *)TXTRecordGetBytesPtr(&txtRec);
  txtLen = TXTRecordGetLength(&txtRec);
//  RegisterRef = mainRef;
    err = DNSServiceRegister(&RegisterRef, 0, kDNSServiceInterfaceIndexAny, name.c_str(), "_airplay._tcp.", NULL, NULL,
                                htons(servicePort), txtLen, txtPtr, [](DNSServiceRef sdRef, DNSServiceFlags flags, DNSServiceErrorType errorCode,
                                                            const char* name, const char* regtype, const char* domain, void* context) {
              if (errorCode == kDNSServiceErr_NoError) {
                  LOG_INFO("Service registered: {}.{}.{}", name, regtype, domain);
              } else {
                  LOG_ERROR("Registration callback error: {}", errorCode);
              }
          }, nullptr);
    LOG_INFO("DNSServiceRegister: {}", err);
#elif ANDROID
    std::map<std::string, std::string> records;
    records["deviceid"] = id;
    records["features"] = features;
    records["flags"] = flags;
    records["model"] = model;
    records["pi"] = identifier;
    records["pk"] = pk;
    records["srcvers"] = srcvers;
    registerBonjour(name.c_str(), servicePort, records);
#endif
    return err;
}

void AirDNS::startBrowse(){
#ifdef LINUX
    browse_thread = std::thread(dns_browse_thread, std::ref(this->deviceId));
#elif ANDROID
    browseService("_carplay-ctrl._tcp.");
#endif
}

AirDNS::~AirDNS(){
    stop();
}

void AirDNS::stop(){
}