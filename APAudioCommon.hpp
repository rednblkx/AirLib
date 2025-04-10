#ifndef AIRPLAY_AUDIO_COMMON_HPP
#define AIRPLAY_AUDIO_COMMON_HPP

#include <boost/endian/conversion.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace AirPlay {
namespace Session {
namespace Stream {

struct AudioStreamDescriptor {
    enum AudioFormat { Invalid, PCM, AAC_LC, AAC_ELD, ALAC, OPUS };
    AudioFormat audioFormat = Invalid;
    uint32_t sr = 0;
    uint32_t fpp = 0;
    uint8_t cpf = 0;
    uint8_t bpc;
};

// RTP/RTCP
const uint8_t kRTPVersion = 2;
const size_t kRTPHeaderSize = 12;
const uint8_t kRTCPTypeTimeAnnounce = 212;
const uint8_t kRTCPTypeRetransmitRequest = 213;
const uint8_t kRTCPTypeRetransmitResponse = 214;
const size_t kRTCPRetransmitRequestPacketMinSize =
    sizeof(uint8_t) * 2 + sizeof(uint16_t) * 3; // v_p, pt, length, seqStart, seqCount

// Audio Formats
enum class APAudioFormat : int64_t {
    Invalid = 0,
    PCM_8KHz_16Bit_Mono = 1 << 2,
    PCM_8KHz_16Bit_Stereo = 1 << 3,
    PCM_16KHz_16Bit_Mono = 1 << 4,
    PCM_16KHz_16Bit_Stereo = 1 << 5,
    PCM_24KHz_16Bit_Mono = 1 << 6,
    PCM_24KHz_16Bit_Stereo = 1 << 7,
    PCM_32KHz_16Bit_Mono = 1 << 8,
    PCM_32KHz_16Bit_Stereo = 1 << 9,
    PCM_44KHz_16Bit_Mono = 1 << 10,
    PCM_44KHz_16Bit_Stereo = 1 << 11,
    PCM_44KHz_24Bit_Mono = 1 << 12,
    PCM_44KHz_24Bit_Stereo = 1 << 13,
    PCM_48KHz_16Bit_Mono = 1 << 14,
    PCM_48KHz_16Bit_Stereo = 1 << 15,
    PCM_48KHz_24Bit_Mono = 1 << 16,
    PCM_48KHz_24Bit_Stereo = 1 << 17,
    AAC_LC_44KHz_Stereo = 1 << 22,
    AAC_LC_48KHz_Stereo = 1 << 23,
    AAC_ELD_16KHz_Mono = 1 << 26,
    AAC_ELD_24KHz_Mono = 1 << 27,
    AAC_ELD_44KHz_Mono = 1 << 31,
    AAC_ELD_44KHz_Stereo = 1 << 24,
    AAC_ELD_48KHz_Mono = 0x0100000000,
    AAC_ELD_48KHz_Stereo = 1 << 25,
    OPUS_16KHz_Mono = 1 << 28,
    OPUS_24KHz_Mono = 1 << 29,
    OPUS_48KHz_Mono = 1 << 30
};

// --- Basic Structures ---
struct RtpHeader {
    uint8_t version_p_x_cc; // Version (2), Padding (1), Extension (1), CSRC count (4)
    uint8_t m_pt;           // Marker (1), Payload Type (7)
    uint16_t sequenceNumber; // Network byte order initially
    uint32_t timestamp;      // Network byte order initially
    uint32_t ssrc;           // Network byte order initially
};

struct RtcpCommonHeader {
    uint8_t v_p_c; // Version (2), Padding (1), Count (5) (e.g., RC for SR/RR)
    uint8_t pt;    // Payload Type
    uint16_t length; // Packet length in 32-bit words - 1 (Network Byte Order)
};

struct RtcpRetransmitRequestPacket {
    uint8_t v_p; // Version (2), Padding (1), Reserved (5) -> Use RTCPHeaderInsertVersion
    uint8_t pt; // Payload Type (e.g., kRTCPTypeRetransmitRequest)
    uint16_t length; // Packet length in 32-bit words - 1 (Network Byte Order)
    uint16_t seqStart; // Sequence number start (Network Byte Order)
    uint16_t seqCount; // Number of packets (Network Byte Order)
};

struct RtcpRetransmitResponseFailPayload {
    uint16_t seq; // Sequence number that failed (Network Byte Order)
};

struct APTimestampTuple {
    uint64_t hostTime = 0;     // NTP time
    uint64_t hostTimeRaw = 0;  // Raw host ticks/nanos
    uint32_t sampleTime = 0;   // Audio sample time
};

// --- Utility Functions ---
inline uint64_t GetCurrentNanos() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

inline uint64_t GetCurrentMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Modular Arithmetic Helpers
inline bool Mod32_LT(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
inline bool Mod32_LE(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
inline bool Mod32_GT(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
inline bool Mod32_GE(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }
inline bool Mod32_EQ(uint32_t a, uint32_t b) { return a == b; }
inline uint32_t Mod32_Diff(uint32_t a, uint32_t b) { return a - b; }

inline bool Mod16_LT(uint16_t a, uint16_t b) { return (int16_t)(a - b) < 0; }
inline bool Mod16_LE(uint16_t a, uint16_t b) { return (int16_t)(a - b) <= 0; }
inline bool Mod16_GT(uint16_t a, uint16_t b) { return (int16_t)(a - b) > 0; }
inline bool Mod16_GE(uint16_t a, uint16_t b) { return (int16_t)(a - b) >= 0; }
inline bool Mod16_EQ(uint16_t a, uint16_t b) { return a == b; }
inline int16_t Mod16_Cmp(uint16_t a, uint16_t b) { return (int16_t)(a - b); }

} // namespace Stream
} // namespace Session
} // namespace AirPlay

#endif // AIRPLAY_AUDIO_COMMON_HPP