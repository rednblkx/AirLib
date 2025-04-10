// APTimeSync.hpp
#ifndef AIRPLAY_TIME_SYNCHRONIZER_HPP
#define AIRPLAY_TIME_SYNCHRONIZER_HPP

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace AirPlay {
namespace Session {
constexpr uint16_t kDefaultTimingLocalPort =
    0; // 0 for ephemeral local port
constexpr uint64_t kNTPvsUnixSeconds =
    2208988800ULL; // Seconds between NTP epoch (1900) and Unix epoch (1970)
constexpr double kNTPFraction =
    (1.0 / 4294967296.0); // 1 / 2^32

// RTCP Types (from AirPlayCommon.h)
enum class RtcpType : uint8_t {
    SR = 200,                // Sender Report
    RR = 201,                // Receiver Report
    SDES = 202,              // Source Description
    BYE = 203,
    APP = 204,
    TIME_SYNC_REQUEST = 210, // RTCPTimeSyncPacket
    TIME_SYNC_RESPONSE = 211, // RTCPTimeSyncPacket
    TIME_ANNOUNCE = 212,      // RTCPTimeAnnouncePacket
    RETRANSMIT_REQUEST = 213, // RTCPRetransmitRequestPacket
    RETRANSMIT_RESPONSE = 214 // RTCPRetransmitResponsePacket
};

// RTCP Common Header (from AirPlayCommon.h)
constexpr uint8_t kRtcpVersion = 2;

#pragma pack(push, 1) // Ensure struct packing matches C layout

struct RtcpCommonHeader {
    uint8_t v_p_c; // Version (V), Padding (P), and Count (C) fields.
    uint8_t pt;    // RTCP packet type (RtcpType)
    uint16_t length; // Packet length in 32-bit words - 1.

    void setVersion(uint8_t version) {
        v_p_c = (v_p_c & ~0xC0) | ((version << 6) & 0xC0);
    }
    uint8_t getVersion() const { return (v_p_c >> 6) & 0x03; }

    void setCount(uint8_t count) {
        v_p_c = (v_p_c & ~0x1F) | (count & 0x1F);
    }
    uint8_t getCount() const { return v_p_c & 0x1F; }

    void setPadding(bool padding) {
        if (padding) {
            v_p_c |= 0x20;
        } else {
            v_p_c &= ~0x20;
        }
    }
    bool getPadding() const { return (v_p_c & 0x20) != 0; }
};
static_assert(sizeof(RtcpCommonHeader) == 4, "Incorrect RtcpCommonHeader size");

// RTCPTimeSync Packet (from AirPlayCommon.h)
struct RtcpTimeSyncPacket {
    uint8_t v_p_m; // Version (V), Padding (P), and Marker (M) fields.
    uint8_t pt;    // RTCP packet type.
    uint16_t length; // Packet length in 32-bit words - 1.

    uint32_t rtpTimestamp; // RTP timestamp at NTP Transit (T3) time
    uint32_t ntpOriginateHi; // NTP Originate (T1) timestamp, high word
    uint32_t ntpOriginateLo; // NTP Originate (T1) timestamp, low word
    uint32_t ntpReceiveHi;   // NTP Receive   (T2) timestamp, high word
    uint32_t ntpReceiveLo;   // NTP Receive   (T2) timestamp, low word
    uint32_t ntpTransmitHi;  // NTP Transmit  (T3) timestamp, high word
    uint32_t ntpTransmitLo;  // NTP Transmit  (T3) timestamp, low word

    void setVersion(uint8_t version) {
        v_p_m = (v_p_m & ~0xC0) | ((version << 6) & 0xC0);
    }
    uint8_t getVersion() const { return (v_p_m >> 6) & 0x03; }

    void setMarker(bool marker) {
        if (marker) {
            v_p_m |= 0x10;
        } else {
            v_p_m &= ~0x10;
        }
    }
    bool getMarker() const { return (v_p_m & 0x10) != 0; }

    void ntoh() { // Convert fields from network to host byte order
        length = boost::endian::big_to_native(length);
        rtpTimestamp = boost::endian::big_to_native(rtpTimestamp);
        ntpOriginateHi = boost::endian::big_to_native(ntpOriginateHi);
        ntpOriginateLo = boost::endian::big_to_native(ntpOriginateLo);
        ntpReceiveHi = boost::endian::big_to_native(ntpReceiveHi);
        ntpReceiveLo = boost::endian::big_to_native(ntpReceiveLo);
        ntpTransmitHi = boost::endian::big_to_native(ntpTransmitHi);
        ntpTransmitLo = boost::endian::big_to_native(ntpTransmitLo);
    }

    void hton() { // Convert fields from host to network byte order
        length = boost::endian::native_to_big(length);
        rtpTimestamp = boost::endian::native_to_big(rtpTimestamp);
        ntpOriginateHi = boost::endian::native_to_big(ntpOriginateHi);
        ntpOriginateLo = boost::endian::native_to_big(ntpOriginateLo);
        ntpReceiveHi = boost::endian::native_to_big(ntpReceiveHi);
        ntpReceiveLo = boost::endian::native_to_big(ntpReceiveLo);
        ntpTransmitHi = boost::endian::native_to_big(ntpTransmitHi);
        ntpTransmitLo = boost::endian::native_to_big(ntpTransmitLo);
    }
};
static_assert(sizeof(RtcpTimeSyncPacket) == 32,
              "Incorrect RtcpTimeSyncPacket size");

// Union for receiving various RTCP packets
union RtcpPacket {
    RtcpCommonHeader header;
    RtcpTimeSyncPacket timeSync;
    // Add other RTCP packet types here if needed (SR, RR, SDES, etc.)
    uint8_t
        raw[1500]; // Buffer large enough for typical MTU, adjust if needed
};

#pragma pack(pop) // Restore default packing

// AirTunesTime structure (from AirTunesClock.h)
struct AirTunesTime {
    int32_t secs = 0;  // Number of seconds since 1970-01-01 00:00:00 (Unix time).
    uint64_t frac = 0; // Fraction of a second in units of 1/2^64.

    void addFrac(uint64_t inFrac) {
        uint64_t oldFrac = frac;
        frac += inFrac;
        if (oldFrac > frac) { // Check for wrap-around
            secs += 1;
        }
    }

    void add(const AirTunesTime &other) {
        uint64_t oldFrac = frac;
        frac += other.frac;
        if (oldFrac > frac) { // Check for wrap-around
            secs += 1;
        }
        secs += other.secs;
    }

    void sub(const AirTunesTime &other) {
        uint64_t oldFrac = frac;
        frac -= other.frac;
        if (oldFrac < frac) { // Check for wrap-around (borrow)
            secs -= 1;
        }
        secs -= other.secs;
    }

    double toDouble() const {
        return static_cast<double>(secs) +
               (static_cast<double>(frac) *
                (1.0 / static_cast<double>(std::numeric_limits<uint64_t>::max())));
    }

    void fromDouble(double fp) {
        double intPart;
        double fracPart = std::modf(fp, &intPart);
        secs = static_cast<int32_t>(intPart);
        frac = static_cast<uint64_t>(
            fracPart * static_cast<double>(std::numeric_limits<uint64_t>::max())
        );
    }

    uint64_t toNtpTimestamp() const {
        // NTP timestamp is seconds since 1900-01-01 00:00:00
        // High 32 bits are integer seconds, low 32 bits are fractional part
        return static_cast<uint64_t>(secs) << 32 | static_cast<uint64_t>(frac) >> 32;
    }

    uint64_t toNanoseconds() const {
        uint64_t ns = static_cast<uint64_t>(secs) * 1000000000ULL;
        // Approximate conversion of 1/2^64 fraction to nanoseconds
        // (frac / 2^64) * 10^9 = (frac * 10^9) / 2^64
        // More precise:
        uint64_t high = (frac >> 32) * 1000000000ULL;
        uint64_t low = (frac & 0xFFFFFFFFULL) * 1000000000ULL;
        ns += (high >> 32) + (low >> 32) + (high & 0xFFFFFFFFULL);
        return ns;
    }
};

// 64-bit fixed-point math (32.32) - Simplified as a class
class Fixed64 {
  private:
    int64_t value_ = 0;

    static constexpr int kFracBits = 32;

  public:
    Fixed64() = default;
    explicit Fixed64(int64_t rawValue) : value_(rawValue) {}

    int64_t getRaw() const { return value_; }
    void setRaw(int64_t val) { value_ = val; }

    void clear() { value_ = 0; }

    Fixed64 &operator+=(const Fixed64 &other) {
        value_ += other.value_;
        return *this;
    }

    Fixed64 &operator-=(const Fixed64 &other) {
        value_ -= other.value_;
        return *this;
    }

    Fixed64 &operator*=(int32_t multiplier) {
        value_ *= multiplier; // Note: Potential overflow if multiplier is large
        return *this;
    }

    // Right shift with sign handling
    Fixed64 &rightShift(int n) {
        if (value_ < 0) {
            value_ = -((-value_) >> n);
        } else {
            value_ = value_ >> n;
        }
        return *this;
    }

    int32_t getInteger() const {
        if (value_ < 0) {
            return -static_cast<int32_t>((-value_) >> kFracBits);
        } else {
            return static_cast<int32_t>(value_ >> kFracBits);
        }
    }

    void setInteger(int32_t integerPart) {
        value_ = static_cast<int64_t>(integerPart) << kFracBits;
    }

    static Fixed64 fromInteger(int32_t integerPart) {
        Fixed64 f;
        f.setInteger(integerPart);
        return f;
    }
};

// Main class combining clock and timing logic
class APTimeSync {
  public:
    // Use steady_clock for monotonic time
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;
    using Ticks = uint64_t; // Representing clock ticks

    APTimeSync(boost::asio::io_context &ioContext,
                            const boost::asio::ip::address &remoteAddress,
                            uint16_t remotePort,
                            uint16_t localPort = kDefaultTimingLocalPort);

    ~APTimeSync();

    // Delete copy/move operations
    APTimeSync(const APTimeSync &) = delete;
    APTimeSync &
    operator=(const APTimeSync &) = delete;
    APTimeSync(APTimeSync &&) = delete;
    APTimeSync &operator=(APTimeSync &&) = delete;

    // Start the synchronization process (negotiation + threads)
    void start();

    // Stop the synchronization process
    void stop();

    uint16_t getLocalPort() const { return localPort_; }
    uint16_t getRemotePort() const { return remotePort_; }

    // Get current synchronized time
    AirTunesTime getSynchronizedTime();
    uint64_t getSynchronizedNtpTime();

    // Estimate synchronized time near a specific tick count
    AirTunesTime getSynchronizedTimeNearTicks(Ticks ticks);

    // Estimate local ticks near a specific synchronized NTP time
    Ticks getTicksNearSynchronizedNtpTime(uint64_t ntpTime);
    Ticks getTicksNearSynchronizedNtpTimeMid32(uint32_t ntpMid32);
    // ADDED: Get the latest filtered clock offset (RemoteTime = LocalTime + Offset)
    int64_t getClockOffsetNanoseconds() const;

    // ADDED: Convert a remote time (nanos since Unix epoch) to local time
    int64_t convertRemoteNanosToLocalNanos(int64_t remoteNanos) const;

    // ADDED: Convert a local time (nanos since Unix epoch) to remote time
    int64_t convertLocalNanosToRemoteNanos(int64_t localNanos) const;


  private:
    std::atomic<int64_t> filteredOffsetNanoseconds_{0}; // ADDED: Store the measured offset atomically
    uint16_t localPort_;
    uint16_t remotePort_;
    // --- Clock State ---
    AirTunesTime epochTime_; // Base time offset
    AirTunesTime upTime_;    // Time elapsed since clock start (adjusted)
    AirTunesTime lastTime_;  // Last calculated absolute time
    Ticks lastTicks_;        // Last tick count read
    uint32_t lastTicks32_;   // Last tick count read (32-bit)
    uint64_t frequency_;     // Ticks per second of the monotonic clock
    uint64_t scale_; // Scaling factor (1/2^64 sec units per tick)
    int64_t adjustment_; // Last calculated adjustment value (raw fixed-point)

    // --- PLL State ---
    static constexpr int32_t kMaxPhase = 500000000; // Max phase error (ns)
    static constexpr int32_t kMaxFrequency = 500000; // Max freq error (ns/s)
    static constexpr int kPllShift = 4;              // PLL loop gain shift

    int32_t lastOffsetNs_ = 0; // Last time offset applied (nanoseconds)
    int32_t lastAdjustTimeSecs_ = 0; // Time (seconds part) of last adjustment
    Fixed64 offset_;                 // Current phase offset estimate (ns, 32.32)
    Fixed64 frequencyOffset_; // Current frequency offset estimate (ns/s, 32.32)
    Fixed64 tickAdjust_;      // Amount to adjust per tick interval (ns/s, 32.32)
    int32_t currentSecond_ = 1; // Current second part of synchronized time

    // --- Timing Protocol State ---
    static constexpr size_t kTimingHistorySize = 8;
    std::vector<double> rtcpTIClockDelayArray_;
    std::vector<double> rtcpTIClockOffsetArray_;
    size_t rtcpTIClockIndex_ = 0;
    size_t rctpTIClockUsedIndex_ = 0; // Index of the best measurement used
    uint32_t rtcpTILastTransmitTimeHi_ = 0;
    uint32_t rtcpTILastTransmitTimeLo_ = 0;
    uint64_t rtcpTIResponseCount_ = 0;
    uint32_t rtcpTISendCount_ = 0;
    uint32_t rtcpTIStepCount_ = 0;
    bool rtcpTIForceStep_ = true; // Force clock step initially
    double rtcpTIClockRTTMin_ = std::numeric_limits<double>::max();
    double rtcpTIClockRTTMax_ = 0.0;
    double rtcpTIClockRTTAvg_ = 0.0;
    double rtcpTIClockOffsetMin_ = std::numeric_limits<double>::max();
    double rtcpTIClockOffsetMax_ = std::numeric_limits<double>::lowest();
    double rtcpTIClockOffsetAvg_ = 0.0;

    // --- System State ---
    boost::asio::io_context &ioContext_;
    boost::asio::ip::udp::socket timingSocket_;
    boost::asio::ip::udp::endpoint remoteEndpoint_;
    boost::asio::ip::udp::endpoint senderEndpoint_; // For recv_from
    boost::asio::steady_timer clockTimer_;
    boost::asio::steady_timer timingRequestTimer_;
    std::thread clockThread_; // If io_context runs in a separate thread
    std::mutex mutex_;        // Protects shared state (clock, PLL, timing stats)
    std::atomic<bool> running_{false};
    std::vector<uint8_t> recvBuffer_;
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<> distrib_{0, 999999}; // For random usec
    bool socketConnected_ = false;

    // --- Private Methods ---

    // Clock management
    void initializeClockState();
    void clockTick(); // Periodic clock update and adjustment calculation
    bool adjustClock(int64_t offsetNanoseconds, bool reset); // Apply adjustment
    Ticks getCurrentTicks() const;
    uint32_t getCurrentTicks32() const;
    uint64_t ticksToNanos(Ticks ticks) const;
    Ticks nanosToTicks(uint64_t nanos) const;
    uint64_t ntpToTicks(uint64_t ntpDiff) const; // Replacement for NTPtoUpTicks
    // Timing protocol
    void startTimingNegotiation();
    void timingNegotiationAttempt(int attempt, int &successCount,
                                  int &failureCount);
    void startTimingLoop();
    void scheduleNextTimingRequest();
    void sendTimingRequest(boost::system::error_code ec = {});
    void startReceive();
    void handleReceive(const boost::system::error_code &ec,
                       std::size_t bytes_transferred);
    void processTimingResponse(const RtcpTimeSyncPacket &packet,
                               const AirTunesTime &receiveTime);

    // Threading and Async
    void runClockUpdates(); // Function run by clockTimer_
    void stopInternal();    // Internal stop logic
};

} // namespace Session
} // namespace AirPlay

#endif // AIRPLAY_TIME_SYNCHRONIZER_HPP