// AirPlayTimeSynchronizer.cpp
#include "APTimeSync.hpp"
#include <asm-generic/socket.h>
#include <boost/asio/ip/host_name.hpp> // For resolving host
#include <boost/asio/placeholders.hpp>
#include <boost/bind/bind.hpp> // For boost::bind
#include "logger.hpp"
#include <boost/multiprecision/cpp_int.hpp>

namespace AirPlay {
namespace Session {
// Helper to get frequency (ticks per second) from std::chrono::steady_clock
uint64_t getSteadyClockFrequency() {
    // Period is ratio<num, den> seconds. Frequency is den / num.
    return static_cast<uint64_t>(APTimeSync::Clock::period::den) /
           APTimeSync::Clock::period::num;
}

APTimeSync::APTimeSync(
    boost::asio::io_context &ioContext, const boost::asio::ip::address &remoteAddress,
    uint16_t remotePort, uint16_t localPort) :
    ioContext_(ioContext),
    timingSocket_(ioContext_),
    clockTimer_(ioContext_),
    timingRequestTimer_(ioContext_),
    gen_(rd_()),
    recvBuffer_(1500) // MTU size buffer
{
    LOG_INFO("Initializing AirPlayTimeSynchronizer...");
    initializeClockState();

    // Resolve remote endpoint
    boost::asio::ip::udp::resolver resolver(ioContext_);
    try {
        remoteEndpoint_ =
            *resolver.resolve(remoteAddress.is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4(), remoteAddress.to_string(),
                              std::to_string(remotePort))
                 .begin();
        LOG_INFO("Resolved remote host {}:{} to {}:{}", remoteAddress.to_string(), remotePort, remoteEndpoint_.address().to_string(), remoteEndpoint_.port());
    } catch (const std::exception &e) {
        LOG_ERROR("Failed to resolve remote host '{}': {}", remoteAddress.to_string(), e.what());
        throw; // Re-throw exception
    }

    // Open and bind the local socket
    try {
        boost::asio::ip::udp::endpoint localEndpoint(
            remoteAddress.is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4(), localPort);
        timingSocket_.open(localEndpoint.protocol());
        timingSocket_.bind(localEndpoint);
        LOG_INFO("Timing socket opened and bound to local port {}", timingSocket_.local_endpoint().port());
        localPort_ = timingSocket_.local_endpoint().port();
        remotePort_ = remotePort;
        boost::system::error_code ec;
        timingSocket_.set_option(
                boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_TIMESTAMP>(true),
                ec);
        timingSocket_.set_option(
                boost::asio::detail::socket_option::integer<IPPROTO_IP, IP_TOS>(0xC0),
                ec);
        if (ec) {
            LOG_WARN("Failed to set socket QoS (TOS): {}", ec.message());
        } else {
            LOG_DEBUG("Socket QoS (TOS=0xC0/CS6) set.");
        }
        timingSocket_.async_connect(remoteEndpoint_, [this](const boost::system::error_code& ec) {
            if (ec) {
              LOG_ERROR("Failed to connect to remote endpoint: {}", ec.message());
              socketConnected_ = false;
              stop();
            } else {
              LOG_INFO("Connected to remote endpoint: {}", remoteEndpoint_.address().to_string());
              socketConnected_ = true;
            }
        });
    } catch (const std::exception &e) {
        LOG_ERROR("Failed to open or bind timing socket: {}", e.what());
        throw; // Re-throw exception
    }

    rtcpTIClockDelayArray_.resize(kTimingHistorySize, 1000.0);
    rtcpTIClockOffsetArray_.resize(kTimingHistorySize, 0.0);
}

APTimeSync::~APTimeSync() {
    LOG_INFO("Destructing AirPlayTimeSynchronizer...");
    stopInternal(); // Ensure everything is stopped
}

void APTimeSync::initializeClockState() {
    LOG_INFO("Initializing clock state...");
    std::lock_guard<std::mutex> lock(mutex_);

    epochTime_.secs = 0;
    epochTime_.frac = 0;
    upTime_.secs = 0;
    upTime_.frac = 0;
    lastTime_.secs = 0;
    lastTime_.frac = 0;

    frequency_ = getSteadyClockFrequency();
    if (frequency_ == 0) {
        LOG_ERROR("System clock frequency is zero!");
        throw std::runtime_error("System clock frequency is zero");
    }
    // Calculate scale: (1/2^64 sec) / (1 / frequency_ sec) = frequency_ / 2^64
    // To avoid overflow, calculate as (freq / 2^32) * (1 / 2^32) if needed
    // Or use 128-bit math if available.
    scale_ = (frequency_ > 0)
                 ? (std::numeric_limits<uint64_t>::max() / frequency_)
                 : 0;

    lastTicks_ = getCurrentTicks();
    lastTicks32_ = getCurrentTicks32();
    adjustment_ = 0;
    lastOffsetNs_ = 0;
    lastAdjustTimeSecs_ = 0;

    offset_.clear();
    frequencyOffset_.clear();
    tickAdjust_.clear();

    currentSecond_ = 1;

    LOG_INFO("Clock frequency: {} Hz", frequency_);
    LOG_INFO("Clock scale factor calculated.");
}

APTimeSync::Ticks APTimeSync::getCurrentTicks() const {
    // Convert time_point to ticks since epoch
    return Clock::now().time_since_epoch().count();
}

uint32_t APTimeSync::getCurrentTicks32() const {
    return static_cast<uint32_t>(getCurrentTicks() & 0xFFFFFFFFULL);
}

int64_t APTimeSync::getClockOffsetNanoseconds() const {
    // Read the atomic value - no lock needed for read
    return filteredOffsetNanoseconds_.load();
}

int64_t APTimeSync::convertRemoteNanosToLocalNanos(int64_t remoteNanos) const {
    // LocalTime = RemoteTime - Offset
    return remoteNanos - getClockOffsetNanoseconds();
}

 int64_t APTimeSync::convertLocalNanosToRemoteNanos(int64_t localNanos) const {
    // RemoteTime = LocalTime + Offset
    return localNanos + getClockOffsetNanoseconds();
}

uint64_t APTimeSync::ticksToNanos(Ticks ticks) const {
    if (frequency_ == 0)
        return 0;
    // Convert ticks to nanoseconds: ticks * (1e9 / frequency)
    // Use 128-bit intermediate if possible to avoid overflow
    // Or calculate as: (ticks / frequency) * 1e9 + ((ticks % frequency) * 1e9) / frequency
    uint64_t secs = ticks / frequency_;
    uint64_t remainder_ticks = ticks % frequency_;
    uint64_t ns = secs * 1000000000ULL;
    // Careful about overflow with remainder_ticks * 1e9
    uint64_t frac_ns = ((static_cast<boost::multiprecision::uint128_t>(remainder_ticks) * 1000000000ULL) / frequency_).convert_to<uint64_t>();
    return ns + frac_ns;

}

APTimeSync::Ticks
APTimeSync::nanosToTicks(uint64_t nanos) const {
    if (frequency_ == 0)
        return 0;
    // Convert nanoseconds to ticks: nanos * (frequency / 1e9)
    // Use 128-bit intermediate if possible
    // Or calculate as: (nanos / 1e9) * frequency + ((nanos % 1e9) * frequency) / 1e9
     uint64_t secs = nanos / 1000000000ULL;
     uint64_t remainder_ns = nanos % 1000000000ULL;
     Ticks ticks = secs * frequency_;
     // Careful about overflow with remainder_ns * frequency
     Ticks frac_ticks = ((static_cast<boost::multiprecision::uint128_t>(remainder_ns) * frequency_) / 1000000000ULL).convert_to<uint64_t>();
     return ticks + frac_ticks;
}


// Replacement for NTPtoUpTicks - converts NTP time difference to local ticks
uint64_t APTimeSync::ntpToTicks(uint64_t ntpDiff) const {
    // ntpDiff is in NTP units (1/2^32 seconds)
    // Convert to nanoseconds: ntpDiff * (1e9 / 2^32)
    // Then convert nanoseconds to ticks
    uint64_t ntpSecs = ntpDiff >> 32;
    uint64_t ntpFrac = ntpDiff & 0xFFFFFFFFULL;
    uint64_t nanos = ntpSecs * 1000000000ULL;
    // frac_ns = (ntpFrac * 1e9) / 2^32
    uint64_t frac_ns = ((static_cast<boost::multiprecision::uint128_t>(ntpFrac) * 1000000000ULL) >> 32).convert_to<uint64_t>();
    return nanosToTicks(nanos + frac_ns);
}


void APTimeSync::start() {
    LOG_INFO("Starting synchronization...");
    if (running_.exchange(true)) {
        LOG_INFO("Already running.");
        return;
    }

    if (!socketConnected_) {
      timingSocket_.async_connect(remoteEndpoint_, [this](const boost::system::error_code& ec) {
        if (ec) {
          LOG_ERROR("Failed to connect to remote endpoint: {}", ec.message());
          socketConnected_ = false;
          stop();
        } else {
          LOG_INFO("Connected to remote endpoint: {}", remoteEndpoint_.address().to_string());
          socketConnected_ = true;
        }
      });
    }

    // Start clock update timer (runs every ~10ms)
    clockTimer_.expires_after(std::chrono::milliseconds(10));
    clockTimer_.async_wait([this](const boost::system::error_code& ec) {
        if (!ec) {
            // std::cout << "[Sync] Clock update timer expired." << std::endl; // Verbose
            std::lock_guard<std::mutex> lock(mutex_);
            runClockUpdates();
        }
    });
    LOG_INFO("Clock update timer started.");
    // Start timing negotiation
    startTimingNegotiation(); // This will start the timing loop upon success
}

void APTimeSync::stop() {
    LOG_INFO("Stopping synchronization...");
    stopInternal();
}

void APTimeSync::stopInternal() {
    if (!running_.exchange(false)) {
        return; // Already stopped
    }
    LOG_INFO("Signalling timers and socket to stop...");

    try {
        // Cancel timers
        clockTimer_.cancel();
        timingRequestTimer_.cancel();
    } catch (const std::exception &e) {
        LOG_WARN("Warning: Error cancelling timers: {}", e.what());
    }
    // Close socket (this will also cancel pending async operations)
    if (timingSocket_.is_open()) {
      boost::system::error_code ec;
      timingSocket_.close(ec);
        if (ec)
          LOG_WARN("Warning: Error closing timing socket: {}", ec.message());
    }

    LOG_INFO("Synchronization stopped.");
}

// --- Clock Methods ---

void APTimeSync::clockTick() {
    // This function is called periodically by clockTimer_
    // std::cout << "[Sync] Clock tick." << std::endl; // Verbose

    // std::lock_guard<std::mutex> lock(mutex_);

    // Update the current uptime from the delta between now and the last update.
    Ticks currentTicks = getCurrentTicks();
    // Prevent huge jumps if time goes backwards or clock is unstable initially
    if (currentTicks < lastTicks_) {
        LOG_WARN("Warning: Clock ticks went backwards. Resetting lastTicks.");
        lastTicks_ = currentTicks;
        lastTicks32_ = getCurrentTicks32();
        // Optionally return or handle differently? For now, proceed with delta=0.
    }
    Ticks deltaTicks = currentTicks - lastTicks_;
    lastTicks_ = currentTicks;
    lastTicks32_ = getCurrentTicks32();

    // Add fractional time elapsed: deltaTicks * scale_
    // scale_ is (2^64 / freq), so deltaTicks * scale_ = (deltaTicks / freq) * 2^64
    // This represents the fraction of seconds elapsed in 1/2^64 units.
    // Use 128-bit math for precision: (deltaTicks * 2^64) / frequency
    uint64_t frac_to_add = deltaTicks * scale_;
    upTime_.addFrac(frac_to_add);


    // Perform NTP adjustments each second.
    AirTunesTime currentTime = upTime_;
    currentTime.add(epochTime_); // Get absolute time

    if (currentTime.secs > lastTime_.secs) {
        //  std::cout << "[Sync] Clock second boundary crossed: " << currentTime.secs << std::endl;

        // Calculate adjustment based on PLL state (offset_ and frequencyOffset_)
        Fixed64 ftemp = offset_;
        ftemp.rightShift(kPllShift); // ftemp = offset / 2^kPllShift

        tickAdjust_ = ftemp;         // Store the phase adjustment part
        offset_ -= ftemp;            // Update remaining offset
        tickAdjust_ += frequencyOffset_; // Add frequency component
        adjustment_ = tickAdjust_.getRaw(); // Store the final adjustment value

        // --- Recalculate the scaling factor based on adjustment_ ---
        // This part remains the same, calculating the new scale_ for *future* ticks.
        double adj_s_per_s = static_cast<double>(adjustment_) / (static_cast<double>(1LL << 32) * 1e9);
        // Clamp adjustment factor to prevent extreme scale values? e.g., +/- 5000 PPM
        const double max_adj = 0.005; // 5000 PPM
        adj_s_per_s = std::max(-max_adj, std::min(max_adj, adj_s_per_s));

        double adjusted_freq = static_cast<double>(frequency_) * (1.0 + adj_s_per_s);

        if (adjusted_freq > 0) {
             // Calculate the new scale factor for the *next* interval
             scale_ = static_cast<uint64_t>(std::numeric_limits<uint64_t>::max() / static_cast<uint64_t>(adjusted_freq));
             // std::cout << "[Sync] Recalculated scale factor for adjusted freq: " << adjusted_freq << " Hz, scale: " << scale_ << std::endl; // Verbose
        } else {
             LOG_WARN("Warning: Adjusted frequency is zero or negative, using nominal scale.");
             scale_ = (frequency_ > 0) ? (std::numeric_limits<uint64_t>::max() / frequency_) : 0;
        }
        // --- End Recalculation ---

        currentSecond_ = currentTime.secs;
    }
    lastTime_ = currentTime;
}

bool APTimeSync::adjustClock(int64_t offsetNanoseconds,
                                          bool reset) {
    // std::cout << "[Sync] Adjusting clock by " << offsetNanoseconds << " ns. Reset: " << (reset ? "Yes" : "No") << std::endl;

    if (reset || std::abs(offsetNanoseconds) > 100000000) // 100ms threshold
    {
        // std::cout << "[Sync] Clock step required." << std::endl;
        AirTunesTime offsetTime;
        uint64_t absOffset = std::abs(offsetNanoseconds);
        offsetTime.secs = static_cast<int32_t>(absOffset / 1000000000ULL);
        // Convert remainder ns to 1/2^64 fraction: (rem_ns * 2^64) / 1e9
        uint64_t rem_ns = absOffset % 1000000000ULL;
        boost::multiprecision::uint128_t frac128 = static_cast<boost::multiprecision::uint128_t>(rem_ns) << 64;
        offsetTime.frac = static_cast<uint64_t>(frac128 / 1000000000ULL);


        { // Lock scope
            // std::lock_guard<std::mutex> lock(mutex_);
            if (offsetNanoseconds < 0) {
                epochTime_.sub(offsetTime);
            } else {
                epochTime_.add(offsetTime);
            }
            // Reset PLL state after a step
            offset_.clear();
            frequencyOffset_.clear();
            tickAdjust_.clear();
            lastAdjustTimeSecs_ = 0; // Reset adjustment time
            lastOffsetNs_ = 0;
            adjustment_ = 0;
             // Recalculate nominal scale immediately
            scale_ = (frequency_ > 0) ? (std::numeric_limits<uint64_t>::max() / frequency_) : 0;

        }
        // std::cout << "[Sync] Triggering clock tick..." << std::endl; // Verbose
        // Trigger an immediate clock tick to update times based on new epoch
        clockTick();
        return true; // Clock was stepped
    } else {
        LOG_DEBUG("Slewing clock.");
        // std::lock_guard<std::mutex> lock(mutex_);

        // Clamp the offset for PLL stability
        int32_t clampedOffsetNs = static_cast<int32_t>(
            std::max<int64_t>(-kMaxPhase, std::min<int64_t>(kMaxPhase, offsetNanoseconds))
        );
        lastOffsetNs_ = clampedOffsetNs;
        offset_.setInteger(lastOffsetNs_); // Update phase offset estimate

        if (lastAdjustTimeSecs_ == 0) {
            lastAdjustTimeSecs_ = currentSecond_; // Initialize adjustment time
        }

        // Update frequency offset estimate
        int32_t deltaTimeSecs = currentSecond_ - lastAdjustTimeSecs_;
        if (deltaTimeSecs != 0) { // Avoid division by zero or huge adjustments if time hasn't advanced
            Fixed64 phaseTerm = Fixed64::fromInteger(lastOffsetNs_);
            // Original: RightShift( ftemp, ( kAirTunesClock_PLLShift + 2 ) << 1 );
            // This seems like a large shift, potentially related to loop constants.
            // Let's use a simpler PI controller logic:
            // FreqOffset += Kp * PhaseError + Ki * Integral(PhaseError)
            // Here, we only have the proportional term update based on phase.
            int shiftAmount = (kPllShift + 2) * 2; // = (4+2)*2 = 12
            phaseTerm.rightShift(shiftAmount);
            phaseTerm *= deltaTimeSecs; // Multiply by time delta (integer)
            frequencyOffset_ += phaseTerm;

            lastAdjustTimeSecs_ = currentSecond_;

            // Clamp frequency offset
            int32_t freqOffsetInt = frequencyOffset_.getInteger();
            if (freqOffsetInt > kMaxFrequency) {
                frequencyOffset_.setInteger(kMaxFrequency);
                 LOG_INFO("Clamped frequency offset to +{}", kMaxFrequency);
            } else if (freqOffsetInt < -kMaxFrequency) {
                frequencyOffset_.setInteger(-kMaxFrequency);
                 LOG_INFO("Clamped frequency offset to -{}", kMaxFrequency);
            }
             LOG_DEBUG("Updated frequency offset: {} ns/s", frequencyOffset_.getInteger()); // Verbose
        } else {
             LOG_DEBUG("Skipping frequency offset update (delta time is zero).");
        }

        return false; // Clock is slewing
    }
}

AirTunesTime APTimeSync::getSynchronizedTime() {
    std::lock_guard<std::mutex> lock(mutex_);
    AirTunesTime t = upTime_;
    uint32_t currentTicks32 = getCurrentTicks32();
    // Add fraction for time since last tick update
    uint32_t deltaTicks32 = currentTicks32 - lastTicks32_;
    uint64_t frac_to_add = scale_ * deltaTicks32;
    t.addFrac(frac_to_add);

    t.add(epochTime_); // Add base offset
    // std::cout << "[Sync] getSynchronizedTime: " << t.secs << " " << t.frac << std::endl;
    return t;
}

uint64_t APTimeSync::getSynchronizedNtpTime() {
    // No lock needed as getSynchronizedTime handles locking
    AirTunesTime t = getSynchronizedTime();
    return t.toNtpTimestamp();
}

AirTunesTime
APTimeSync::getSynchronizedTimeNearTicks(Ticks targetTicks) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Get base synchronized time estimate at last tick
    AirTunesTime baseTime = upTime_;
    baseTime.add(epochTime_);

    // Calculate time delta between targetTicks and lastTicks_
    bool future = targetTicks > lastTicks_;
    Ticks deltaTicksAbs = future ? (targetTicks - lastTicks_) : (lastTicks_ - targetTicks);

    // Convert deltaTicksAbs to AirTunesTime format
    AirTunesTime deltaTime;
    deltaTime.secs = static_cast<int32_t>(deltaTicksAbs / frequency_); // Integer seconds
    // Fractional part: (deltaTicksAbs % frequency_) * scale_
    Ticks remTicks = deltaTicksAbs % frequency_;
    boost::multiprecision::uint128_t frac128 = static_cast<boost::multiprecision::uint128_t>(remTicks) << 64;
    deltaTime.frac = static_cast<uint64_t>(frac128 / frequency_);


    // Apply delta
    if (future) {
        baseTime.add(deltaTime);
    } else {
        baseTime.sub(deltaTime);
    }
    return baseTime;
}

APTimeSync::Ticks
APTimeSync::getTicksNearSynchronizedNtpTime(uint64_t targetNtpTime) {
    // No lock needed as called functions handle locking
    uint64_t nowNtp = getSynchronizedNtpTime();
    // std::cout << "[Sync] getTicksNearSynchronizedNtpTime: targetNtpTime: " << targetNtpTime << ", nowNtp: " << nowNtp << std::endl;
    Ticks nowTicks = getCurrentTicks();
    // std::cout << "[Sync] getTicksNearSynchronizedNtpTime: nowTicks: " << nowTicks << std::endl;
    Ticks resultTicks;

    if (targetNtpTime >= nowNtp) {
        uint64_t ntpDiff = targetNtpTime - nowNtp;
        resultTicks = nowTicks + ntpToTicks(ntpDiff);
    } else {
        uint64_t ntpDiff = nowNtp - targetNtpTime;
        Ticks tickDiff = ntpToTicks(ntpDiff);
        resultTicks = (nowTicks > tickDiff) ? (nowTicks - tickDiff) : 0;
    }
    return resultTicks;
}

APTimeSync::Ticks
APTimeSync::getTicksNearSynchronizedNtpTimeMid32(
    uint32_t ntpMid32) {
    // No lock needed as called functions handle locking
    uint64_t nowNtp = getSynchronizedNtpTime();
    Ticks nowTicks = getCurrentTicks();

    // Reconstruct target NTP time around current time
    uint64_t targetNtp = (nowNtp & 0xFFFF000000000000ULL) |
                         (static_cast<uint64_t>(ntpMid32) << 16);

    // Handle potential wrap-around (targetNtp might be in the past/future epoch)
    // If targetNtp is more than half an epoch away, adjust it.
    const uint64_t halfEpoch = 1ULL << 63;
     if ((nowNtp > targetNtp) && ((nowNtp - targetNtp) > halfEpoch)) {
         // targetNtp is likely in the next epoch
         targetNtp += (1ULL << 48); // Add 2^48 seconds (approx 89 centuries) - adjust if needed based on NTP format
     } else if ((targetNtp > nowNtp) && ((targetNtp - nowNtp) > halfEpoch)) {
         // targetNtp is likely in the previous epoch
         if (targetNtp >= (1ULL << 48)) {
            targetNtp -= (1ULL << 48);
         } else {
            // Cannot go back further - target is likely invalid or too far in past
            targetNtp = 0; // Or handle error
         }
     }


    Ticks resultTicks;
    if (targetNtp >= nowNtp) {
        uint64_t ntpDiff = targetNtp - nowNtp;
        resultTicks = nowTicks + ntpToTicks(ntpDiff);
    } else {
        uint64_t ntpDiff = nowNtp - targetNtp;
         Ticks tickDiff = ntpToTicks(ntpDiff);
        resultTicks = (nowTicks > tickDiff) ? (nowTicks - tickDiff) : 0;
    }
    return resultTicks;
}

// --- Timing Protocol Methods ---

void APTimeSync::startTimingNegotiation() {
    LOG_INFO("Starting timing negotiation...");
    rtcpTIForceStep_ = true; // Force step during negotiation
    try {
        int successCount = 0;
        int failureCount = 0;
        timingNegotiationAttempt(0, successCount, failureCount); // Start recursive attempts
    } catch (const std::exception &e) {
        LOG_WARN("Warning: Error starting timing negotiation: {}", e.what());
    }
}

void APTimeSync::timingNegotiationAttempt(int attempt,
                                                       int &successCount,
                                                       int &failureCount) {
    if (!running_) {
        LOG_INFO("Negotiation stopped.");
        return;
    }

    const int maxAttempts = 64;
    const int requiredSuccesses = 5;

    if (successCount >= requiredSuccesses) {
        LOG_INFO("Timing negotiation successful ({})", successCount);
        rtcpTIForceStep_ = false; // Allow slewing now

        // Clean up history - keep only the best measurement from negotiation
         if (rctpTIClockUsedIndex_ > 0 && kTimingHistorySize > 0) {
             rtcpTIClockDelayArray_[0] = rtcpTIClockDelayArray_[rctpTIClockUsedIndex_];
             rtcpTIClockOffsetArray_[0] = rtcpTIClockOffsetArray_[rctpTIClockUsedIndex_];
             // Fill rest with defaults? Or just reset index?
             for(size_t i = 1; i < kTimingHistorySize; ++i) {
                 rtcpTIClockDelayArray_[i] = 1000.0;
                 rtcpTIClockOffsetArray_[i] = 0.0;
             }
             rctpTIClockUsedIndex_ = 0; // Best is now at index 0
         }
         rtcpTIClockIndex_ = 1 % kTimingHistorySize; // Next measurement goes to index 1


        startTimingLoop(); // Start regular timing updates
        return;
    }

    if (failureCount >= maxAttempts || attempt >= maxAttempts * 2 /* Safety limit */) {
        LOG_ERROR("Timing negotiation failed after {} attempts (Success: {}, Fail: {})", attempt, successCount, failureCount);
        stopInternal(); // Stop synchronization on failure
        // Optionally: throw an exception or signal error state
        return;
    }

    LOG_INFO("Negotiation attempt #{} (S: {}, F: {})", attempt + 1, successCount, failureCount);

    // Send request
    boost::system::error_code send_ec;
    sendTimingRequest(send_ec);
    if (send_ec) {
        LOG_ERROR("Negotiation send error: {}", send_ec.message());
        failureCount++;
        // Schedule next attempt after a short delay
        timingRequestTimer_.expires_after(std::chrono::milliseconds(100));
        timingRequestTimer_.async_wait([this, attempt, &successCount, &failureCount](const boost::system::error_code& ec) {
            if (!running_) return;
            if (ec == boost::asio::error::operation_aborted) {
                LOG_INFO("Negotiation send cancelled.");
                return;
            }
            if (ec) {
                LOG_ERROR("Negotiation send error: {}", ec.message());
                failureCount++;
            }
            timingNegotiationAttempt(attempt + 1, successCount, failureCount);
        });
        return;
    }

    if (socketConnected_) {
      timingSocket_.async_receive(
          boost::asio::buffer(recvBuffer_),
          [this, attempt, &successCount, &failureCount](
              const boost::system::error_code &ec, std::size_t bytes_transferred) {
            if (!running_) return;

            if (!ec) {
                // Process response
                handleReceive(ec, bytes_transferred); // This might increment successCount
                // Schedule next attempt immediately
                 timingNegotiationAttempt(attempt + 1, successCount, failureCount);

            } else if (ec == boost::asio::error::operation_aborted) {
                 LOG_INFO("Negotiation receive cancelled.");
                 // Stop initiated elsewhere
            } else {
                 LOG_ERROR("Negotiation receive error: {}", ec.message());
                 failureCount++;
                 // Schedule next attempt
                 timingNegotiationAttempt(attempt + 1, successCount, failureCount);
            }
      });
    } else {
      timingSocket_.async_receive_from(
        boost::asio::buffer(recvBuffer_), senderEndpoint_,
        [this, attempt, &successCount, &failureCount](
            const boost::system::error_code &ec, std::size_t bytes_transferred) {
            if (!running_) return;

            if (!ec) {
                // Process response
                handleReceive(ec, bytes_transferred); // This might increment successCount
                // Schedule next attempt immediately
                 timingNegotiationAttempt(attempt + 1, successCount, failureCount);

            } else if (ec == boost::asio::error::operation_aborted) {
                 LOG_INFO("Negotiation receive cancelled.");
                 // Stop initiated elsewhere
            } else {
                 LOG_ERROR("Negotiation receive error: {}", ec.message());
                 failureCount++;
                 // Schedule next attempt
                 timingNegotiationAttempt(attempt + 1, successCount, failureCount);
            }
        });
    }

     // Start a timer for the receive timeout (e.g., 100ms)
     timingRequestTimer_.expires_after(std::chrono::milliseconds(100));
     timingRequestTimer_.async_wait([this, attempt, &successCount, &failureCount](const boost::system::error_code& ec) {
         if (!running_) return;
         if (ec == boost::asio::error::operation_aborted) {
             // Timer cancelled, likely because receive completed or stop was called
             return;
         }
         if (ec) {
             // Should not happen unless system clock changes drastically
             LOG_ERROR("Negotiation timeout timer error: {}", ec.message());
             failureCount++;
         } else {
             // Timer expired - means receive timed out
             LOG_INFO("Negotiation receive timeout.");
             timingSocket_.cancel(); // Cancel the pending async_receive_from
             failureCount++;
         }
         // Schedule the next attempt regardless of timeout reason (unless stopped)
         if (running_) {
            timingNegotiationAttempt(attempt + 1, successCount, failureCount);
         }
     });
}


void APTimeSync::startTimingLoop() {
    LOG_INFO("Starting regular timing loop...");
    startReceive();              // Start listening for responses
    scheduleNextTimingRequest(); // Schedule the first regular request
}

void APTimeSync::scheduleNextTimingRequest() {
    if (!running_)
        return;

    // Schedule next request 2 seconds + random fraction
    int random_usec = distrib_(gen_);
    auto delay = std::chrono::seconds(2) + std::chrono::microseconds(random_usec);
    timingRequestTimer_.expires_after(delay);
    timingRequestTimer_.async_wait(
        boost::bind(&APTimeSync::sendTimingRequest, this,
                    boost::asio::placeholders::error));
    LOG_VERBOSE("Scheduled next timing request in {} ms.", std::chrono::duration_cast<std::chrono::milliseconds>(delay).count()); // Verbose
}

void APTimeSync::sendTimingRequest(boost::system::error_code ec) {
    if (ec == boost::asio::error::operation_aborted || !running_) {
        LOG_INFO("Send timing request cancelled or stopped.");
        return;
    }
     if (ec) {
         LOG_ERROR("Error waiting for send timer: {}", ec.message());
         // Reschedule anyway?
         scheduleNextTimingRequest();
         return;
     }


    LOG_VERBOSE("Sending timing request..."); // Verbose

    RtcpTimeSyncPacket pkt = {}; // Zero initialize
    AirTunesTime now;
    uint32_t transmitHi, transmitLo;

    {
      now = getSynchronizedTime(); // Get current synchronized time under lock
      transmitHi = static_cast<uint32_t>(now.secs + kNTPvsUnixSeconds);
      transmitLo = static_cast<uint32_t>(now.frac >> 32);

      // Store transmit time for matching response
      rtcpTILastTransmitTimeHi_ = transmitHi;
      rtcpTILastTransmitTimeLo_ = transmitLo;
    }

    pkt.setVersion(kRtcpVersion);
    pkt.pt = static_cast<uint8_t>(RtcpType::TIME_SYNC_REQUEST);
    pkt.length = (sizeof(pkt) / 4) - 1; // Length in 32-bit words - 1
    pkt.rtpTimestamp = 0;
    pkt.ntpOriginateHi = 0; // Server fills this on response based on our transmit time
    pkt.ntpOriginateLo = 0;
    pkt.ntpReceiveHi = 0;
    pkt.ntpReceiveLo = 0;
    pkt.ntpTransmitHi = transmitHi;
    pkt.ntpTransmitLo = transmitLo;

    pkt.hton(); // Convert to network byte order

    // std::cout << "[Sync] Sending timing request to " << remoteEndpoint_ << std::endl; // Verbose
    if (socketConnected_) {
      timingSocket_.async_send(
          boost::asio::buffer(&pkt, sizeof(pkt)),
          [this](const boost::system::error_code &ec, std::size_t /*bytes_sent*/) {
              if (!running_) return;
              if (ec) {
                  LOG_ERROR("Error sending timing request: {}", ec.message());
              } else {
                  // std::cout << "[Sync] Timing request sent successfully." << std::endl; // Verbose
                  std::lock_guard<std::mutex> lock(mutex_);
                  rtcpTISendCount_++;
              }
              // Schedule the next request regardless of success/failure of this one
              scheduleNextTimingRequest();
          });
    } else {
      timingSocket_.async_send_to(
          boost::asio::buffer(&pkt, sizeof(pkt)), remoteEndpoint_,
          [this](const boost::system::error_code &ec, std::size_t /*bytes_sent*/) {
              if (!running_) return;
              if (ec) {
                  LOG_ERROR("Error sending timing request: {}", ec.message());
              } else {
                  // std::cout << "[Sync] Timing request sent successfully." << std::endl; // Verbose
                  std::lock_guard<std::mutex> lock(mutex_);
                  rtcpTISendCount_++;
              }
              // Schedule the next request regardless of success/failure of this one
              scheduleNextTimingRequest();
          });
    }
}

void APTimeSync::startReceive() {
    if (!running_) return;
    LOG_VERBOSE("Starting async receive..."); // Verbose
    if (socketConnected_) {
      timingSocket_.async_receive(
          boost::asio::buffer(recvBuffer_),
          [this](const boost::system::error_code &ec, std::size_t bytes_transferred) {
              LOG_VERBOSE("Received {} bytes from {}", bytes_transferred, remoteEndpoint_.address().to_string()); // Verbose
              handleReceive(ec, bytes_transferred);
          });
    } else {
      timingSocket_.async_receive_from(
          boost::asio::buffer(recvBuffer_), senderEndpoint_,
          [this](const boost::system::error_code &ec, std::size_t bytes_transferred) {
                LOG_VERBOSE("Received {} bytes from {}", bytes_transferred, senderEndpoint_.address().to_string()); // Verbose
              handleReceive(ec, bytes_transferred);
          });
    }
}

void APTimeSync::handleReceive(
    const boost::system::error_code &ec, std::size_t bytes_transferred) {
    if (ec == boost::asio::error::operation_aborted || !running_) {
        LOG_INFO("Receive operation cancelled or stopped.");
        return;
    }

    if (ec) {
        LOG_ERROR("Receive error: {}", ec.message());
        // Decide if error is fatal or recoverable
        if (ec == boost::asio::error::connection_refused) {
             LOG_ERROR("Connection refused by server. Stopping.");
             stopInternal();
             return;
        }
        // Continue receiving after other errors
        startReceive();
        return;
    }

    // std::cout << "[Sync] Received " << bytes_transferred << " bytes from " << senderEndpoint_ << std::endl; // Verbose

    if (bytes_transferred < sizeof(RtcpCommonHeader)) {
        LOG_ERROR("Received packet too small for RTCP header ({})", bytes_transferred);
        startReceive(); // Continue listening
        return;
    }

    // Basic validation (check source? check packet type?)
    // Assuming the packet is RTCP for now
    auto *header = reinterpret_cast<const RtcpCommonHeader *>(recvBuffer_.data());

    if (header->getVersion() != kRtcpVersion) {
        LOG_ERROR("Received packet with wrong RTCP version: {}", static_cast<int>(header->getVersion()));
        startReceive();
        return;
    }

    if (header->pt == static_cast<uint8_t>(RtcpType::TIME_SYNC_RESPONSE)) {
        if (bytes_transferred < sizeof(RtcpTimeSyncPacket)) {
            LOG_ERROR("Received TimeSyncResponse too small ({})", bytes_transferred);
            startReceive();
            return;
        }

        // TODO: Get receive timestamp as accurately as possible.
        // Boost.Asio doesn't provide packet timestamps directly in the handler.
        // SO_TIMESTAMPING socket option is the way, but requires platform support
        // and reading ancillary data (cmsg).
        // As a fallback, get time *now*, which includes handler latency.
        AirTunesTime receiveTime = getSynchronizedTime(); // Estimate receive time

        RtcpTimeSyncPacket responsePkt =
            *reinterpret_cast<const RtcpTimeSyncPacket *>(recvBuffer_.data());
        responsePkt.ntoh(); // Convert from network to host order

        processTimingResponse(responsePkt, receiveTime);

    } else {
        // Handle other RTCP packet types if necessary
        LOG_ERROR("Received unhandled RTCP packet type: {}", static_cast<int>(header->pt));
    }

    startReceive(); // Listen for the next packet
}

void APTimeSync::processTimingResponse(
    const RtcpTimeSyncPacket &pkt, const AirTunesTime &receiveTime) {

    std::lock_guard<std::mutex> lock(mutex_);

    // std::cout << "[Sync] Processing timing response..." << std::endl; // Verbose

    // Make sure this response is for the last request we made
    if ((pkt.ntpOriginateHi != rtcpTILastTransmitTimeHi_) ||
        (pkt.ntpOriginateLo != rtcpTILastTransmitTimeLo_)) {
        LOG_INFO("Received duplicate or stale timing response. Ignoring.");
        return;
    }

    // Prevent processing duplicates of the *same* response
    rtcpTILastTransmitTimeHi_ = 0;
    rtcpTILastTransmitTimeLo_ = 0;

    // Extract timestamps (T1, T2, T3, T4) in NTP format (64-bit)
    uint64_t t1 = (static_cast<uint64_t>(pkt.ntpOriginateHi) << 32) | pkt.ntpOriginateLo;
    uint64_t t2 = (static_cast<uint64_t>(pkt.ntpReceiveHi) << 32) | pkt.ntpReceiveLo;
    uint64_t t3 = (static_cast<uint64_t>(pkt.ntpTransmitHi) << 32) | pkt.ntpTransmitLo;
    uint64_t t4 = (static_cast<uint64_t>(receiveTime.secs + kNTPvsUnixSeconds) << 32 ) + ( receiveTime.frac >> 32 );

    // Check for time validity (basic sanity check)
    if (t4 < t1 || t3 < t2) {
         LOG_WARN("Warning: Invalid timestamps received (T4 < T1 or T3 < T2). Ignoring.");
         return;
    }


    // Calculate offset and RTT using doubles for simplicity
    // Note: Original used fixed-point? This uses double.
    // Need signed differences, cast carefully.
    double t2_minus_t1 = static_cast<double>(static_cast<int64_t>(t2 - t1)) * kNTPFraction;
    double t3_minus_t4 = static_cast<double>(static_cast<int64_t>(t3 - t4)) * kNTPFraction;
    double t4_minus_t1 = static_cast<double>(static_cast<int64_t>(t4 - t1)) * kNTPFraction;
    double t3_minus_t2 = static_cast<double>(static_cast<int64_t>(t3 - t2)) * kNTPFraction;

    double offset = 0.5 * (t2_minus_t1 + t3_minus_t4); // Clock offset in seconds
    double rtt = t4_minus_t1 - t3_minus_t2;            // Round-trip time in seconds

    //  std::cout << "[Sync] Calculated RTT: " << rtt * 1000.0 << " ms, Offset: " << offset * 1000.0 << " ms" << std::endl; // Verbose

    if (rtt < 0) {
        LOG_WARN("Warning: Negative RTT calculated ({}) ms. Ignoring measurement.", rtt * 1000.0);
        return; // Ignore measurement with negative RTT
    }


    // Update RTT stats
    rtcpTIClockRTTMin_ = std::min(rtcpTIClockRTTMin_, rtt);
    rtcpTIClockRTTMax_ = std::max(rtcpTIClockRTTMax_, rtt);
    if (rtcpTIResponseCount_ == 0) {
        rtcpTIClockRTTAvg_ = rtt;
    } else {
        // Exponential moving average (alpha = 1/16)
        rtcpTIClockRTTAvg_ = (15.0 * rtcpTIClockRTTAvg_ + rtt) / 16.0;
    }

    // Update clock offset history (NTP filter algorithm)
    if (rtcpTIResponseCount_ == 0) {
        // First measurement, reset history
        std::fill(rtcpTIClockDelayArray_.begin(), rtcpTIClockDelayArray_.end(), 1000.0);
        std::fill(rtcpTIClockOffsetArray_.begin(), rtcpTIClockOffsetArray_.end(), 0.0);
        rtcpTIClockIndex_ = 0;
        rctpTIClockUsedIndex_ = 0;
        rtcpTIClockOffsetAvg_ = 0.0;
        rtcpTIClockOffsetMin_ = offset;
        rtcpTIClockOffsetMax_ = offset;
    }

    // Check if this measurement is better (lower RTT) than existing ones
    bool useMeasurement = true;
    for (double existingDelay : rtcpTIClockDelayArray_) {
        if (rtt > existingDelay) {
            useMeasurement = false;
            break;
        }
    }

    // Store the current measurement in the circular buffer
    rtcpTIClockDelayArray_[rtcpTIClockIndex_] = rtt;
    rtcpTIClockOffsetArray_[rtcpTIClockIndex_] = offset;

    if (useMeasurement) {
        rctpTIClockUsedIndex_ = rtcpTIClockIndex_; // Mark this as the best index
        // std::cout << "[Sync] Using measurement: RTT=" << rtt * 1000.0 << "ms, Offset=" << offset * 1e9 << "ns (Index " << rtcpTIClockIndex_ << ")" << std::endl;
        // Update the atomically stored filtered offset based on the best measurement
        int64_t best_offset_ns = static_cast<int64_t>(rtcpTIClockOffsetArray_[rctpTIClockUsedIndex_] * 1e9);
        filteredOffsetNanoseconds_.store(best_offset_ns);
        LOG_DEBUG("Updated filtered offset: {} ns (from index {}, RTT {} ms)",
                  best_offset_ns, rctpTIClockUsedIndex_, rtcpTIClockDelayArray_[rctpTIClockUsedIndex_] * 1000.0);
        // Update overall offset stats using the current measurement
        rtcpTIClockOffsetAvg_ = (15.0 * rtcpTIClockOffsetAvg_ + offset) / 16.0;
        rtcpTIClockOffsetMin_ = std::min(rtcpTIClockOffsetMin_, offset);
        rtcpTIClockOffsetMax_ = std::max(rtcpTIClockOffsetMax_, offset);

        // Adjust the local clock using the calculated offset
        int64_t offset_ns = static_cast<int64_t>(offset * 1e9);
        bool clockStepped = adjustClock(offset_ns, rtcpTIForceStep_);

        if (clockStepped && !rtcpTIForceStep_) {
            LOG_INFO("Clock stepped unexpectedly after negotiation.");
            rtcpTIStepCount_++;
            // Consider resetting PLL/history if unexpected steps occur?
        }
         rtcpTIResponseCount_++; // Increment only when a measurement is used

    } else {
      //  std::cout << "[Sync] Discarding measurement: RTT (" << rtt * 1000.0 << "ms) is not better than history." << std::endl; // Verbose
    }

    // Advance the history index
    rtcpTIClockIndex_ = (rtcpTIClockIndex_ + 1) % kTimingHistorySize;
}

// --- Threading and Async ---

void APTimeSync::runClockUpdates() {
    if (!running_) {
        LOG_INFO("Clock update loop stopped.");
        return;
    }

    clockTick(); // Perform clock update logic

    // Reschedule the timer
    clockTimer_.expires_at(clockTimer_.expiry() + std::chrono::milliseconds(10));
    clockTimer_.async_wait([this](const boost::system::error_code& ec) {
        if (!ec) {
            // std::cout << "[Sync] Clock update timer expired." << std::endl; // Verbose
            std::lock_guard<std::mutex> lock(mutex_);
            runClockUpdates();
        }
    });
}

} // namespace Session
} // namespace AirPlay
