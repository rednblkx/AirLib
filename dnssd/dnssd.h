#pragma once
#include <avahi-common/simple-watch.h>
#include <bitset>
#include <dns_sd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <string>
#include <array>
#include <vector>

struct AirFeatures1 {
    char str[11];
    enum {
        Video = 1 << 0,
        Photo = 1 << 1,
        VideoFP = 1 << 2,
        VideoVolumeControl = 1 << 3,
        VideoHTTPLive = 1 << 4,
        Slideshow = 1 << 5,
        Unknown1 = 1 << 6,
        Screen = 1 << 7,
        ScreenRotate = 1 << 8,
        Audio = 1 << 9,
        Unknown2 = 1 << 10,
        AudioRedundant = 1 << 11,
        FPSAPv2_AES_GCM = 1 << 12,
        PhotoCaching = 1 << 13,
        FPAuth = 1 << 14,
        MetadataFeatureArtwork = 1 << 15,
        MetadataFeatureProgress = 1 << 16,
        MetadataFeatureText = 1 << 17,
        AudioPCM = 1 << 18,
        AudioAAC_ELD = 1 << 19,
        AudioAAC_LC = 1 << 20,
        AudioALAC = 1 << 21,
        Unknown3 = 1 << 22,
        RSAAuth = 1 << 23,
        Unknown4 = 1 << 25,
        AudioAES_128_SAPv1 = 1 << 26,
        LegacyPairing = 1 << 27,
        UnifiedServices = 1 << 30
    };
    uint32_t bytes;
    operator const char *() {std::snprintf(str, 11, "%#x", bytes);return str;}
};

struct AirFeatures2 {
    private:
    char str[11];
    public:
    enum {
        isCarplay = 1 << 0,
        APVideoQ = 1 << 1,
        APFromCloud  = 1 << 2,
        carPlayControl = 1 << 5,
        CoreUtilsPairingAndEncryption  = 1 << 6,
        bufferedAudio = 1 << 8,
        ptp  = 1 << 9,
        screenMultiCodec  = 1 << 10,
        systemPairing = 1 << 11,
        hkPairingAndAccessControl = 1 << 14,
        transientPairing = 1 << 16,
        metadataBinaryPlist = 1 << 18,
        mfiAuth = 1 << 19,
        setPeersExtendedMessage = 1 << 20
    };
    uint32_t bytes;
    operator const char *() {std::snprintf(str, 11, "%#x", bytes);return str;}
};

class AirDNS {
    private:
        std::string name;
        std::array<uint8_t, 6> deviceId;
        uint16_t servicePort;
        struct AirFeatures1 features1;
        struct AirFeatures2 features2;
        DNSServiceRef dnsRegPtr;
        pthread_t browse_thread;
    public:
        // Service name, device ID (e.g. MAC Address) and service port
        AirDNS(std::string name, uint8_t deviceId[6], uint16_t port, struct AirFeatures1 features1, struct AirFeatures2 features2);
        DNSServiceErrorType registerAP(std::string identifier, std::vector<uint8_t> pk);
        void startBrowse();
};