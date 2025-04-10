#pragma once

#include "APAudioCommon.hpp"
#include "APUtils.hpp"
#include "APTimeSync.hpp"
#include "IAudioStreamDelegate.hpp"
#include <atomic>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/circular_buffer.hpp>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace AirPlay {
namespace Session {
namespace Stream {

inline const char* AudioFormatToString(AudioStreamDescriptor::AudioFormat format) {
    switch(format) {
        case AudioStreamDescriptor::AudioFormat::PCM: return "PCM";
        case AudioStreamDescriptor::AudioFormat::AAC_LC: return "AAC_LC";
        case AudioStreamDescriptor::AudioFormat::AAC_ELD: return "AAC_ELD";
        case AudioStreamDescriptor::AudioFormat::ALAC: return "ALAC";
        case AudioStreamDescriptor::AudioFormat::OPUS: return "OPUS";
        default: return "UnknownFormat";
    }
}

class APAudioStream {
public:
  APAudioStream(boost::asio::io_context &ioCtx,
                APTimeSync *timeSynchronizer);
  ~APAudioStream();

  APAudioStream(const APAudioStream &) = delete;
  APAudioStream &operator=(const APAudioStream &) = delete;

  // Setup based on stream description from the source (e.g., phone)
  bool setup(
      Utils::StreamType streamType, boost::asio::ip::address peerAddress,
      Plist::dictionary_type &streamDesc,
      Plist::dictionary_type &outResponseParams); // Add parameters to response

  bool setMainHighAudio(boost::asio::ip::address peerAddress,
    Plist::dictionary_type &streamDesc,
    Plist::dictionary_type &outResponseParams);

  // Set the delegate responsible for handling decrypted packets
  void setDelegate(IAudioStreamDelegate *delegate) { delegate_ = delegate; }

  // Set the key for decrypting incoming audio packets
  bool setDecryptionKey(const uint8_t *keyData, size_t keySize);

  // Start receiving and processing audio
  bool start();

  // Stop receiving and processing audio
  void stop();

  // Flush audio state up to a certain timestamp/sequence number
  void flush(uint32_t flushUntilTS, uint16_t flushUntilSeq);

  // --- Getters for stream properties ---
  Utils::StreamType getType() const { return type_; }
  uint32_t getSampleRate() const { return descriptor.sr; }
  uint32_t getChannels() const { return descriptor.cpf; }
  uint32_t getBitsPerSample() const { return descriptor.bpc; }
  uint32_t getFramesPerPacket() const { return descriptor.fpp; }
  uint64_t getConnectionID() const { return connectionID_; }
  const std::string &getLabel() const { return label_; }
  bool isStopped() const { return !isRunning_.load(); }
  APTimestampTuple getZeroTime();
  double getRateAvg() const { return rateAvg_; }
  Utils::StreamType getStreamType() const { return type_; }
  AudioStreamDescriptor createDescriptor(APAudioFormat format, uint16_t spf);

private:
  // --- Network Handling ---
  void startRtpReceive();
  void handleRtpReceive(const boost::system::error_code &error,
                        size_t bytes_recvd);
  void startRtcpReceive();
  void handleRtcpReceive(const boost::system::error_code &error,
                         size_t bytes_recvd);
  void sendRtcpPacket(const uint8_t *data, size_t size);

  // --- Packet Processing ---
  void processRtpPacket(const uint8_t *buffer, size_t size, bool isRetransmit);
  void processRtcpPacket(const uint8_t *buffer, size_t size);
  bool trackDuplicate(uint16_t seq);
  void trackLosses(const RtpHeader &rtpHeader);
  bool decryptPacket(const RtpHeader &rtpHeader, const uint8_t *payloadPtr,
                     size_t payloadSize);
  void generateAad(const RtpHeader &rtpHeader, std::vector<uint8_t> &aad);

  // --- Retransmission Handling (Remains similar) ---
  struct AirTunesRetransmitNode {
    AirTunesRetransmitNode *next = nullptr; // Next in free or busy list
    uint16_t seq = 0;
    uint16_t tries = 0;
    uint64_t startNanos = 0;
    uint64_t sentNanos = 0;
    uint64_t nextNanos = 0;
    bool isInUse = false;
  };

  void scheduleRetransmits(uint16_t seqStart, uint16_t seqCount);
  void updateRetransmits(uint16_t receivedSeq);
  void abortRetransmit(uint16_t seq, const char *reason);
  void abortAllRetransmits(const char *reason);
  void sendRetransmitRequest(uint16_t seqStart, uint16_t seqCount);
  void processRetransmitResponse(const uint8_t *data, size_t size);
  AirTunesRetransmitNode *getFreeRetransmitNode();
  void releaseRetransmitNode(AirTunesRetransmitNode *node);
  void checkRetransmitTimeouts(); // Called periodically

  // --- Timing & Rate Estimation ---
  void updateEstimatedRate(uint32_t sampleTime, uint64_t hostTimeNanos);
  APTimeSync *timeSynchronizer_;
  std::chrono::steady_clock::time_point rateUpdateNextTime_;
  std::chrono::milliseconds rateUpdateInterval_{1000};
  boost::circular_buffer<APTimestampTuple>
      rateUpdateSamples_; // History buffer
  uint32_t rateUpdateCount_ = 0;
  double rateAvg_ = 0.0;
  APTimestampTuple zeroTime_; // Last periodic timestamp update
  std::mutex zeroTimeMutex_;

  // --- General Helpers ---
  void cleanup();

  // --- Member Variables ---
  boost::asio::io_context &ioContext_;
  Utils::StreamType type_ = Utils::StreamType::CPMainHighAudio;
  IAudioStreamDelegate *delegate_ = nullptr;
  std::string label_;
  uint64_t connectionID_ = 0;
  AudioStreamDescriptor descriptor;
  // Network
  boost::asio::ip::udp::socket dataSocket_;        // RTP
  boost::asio::ip::udp::socket controlSocket_;     // RTCP
  boost::asio::ip::udp::endpoint peerRtpEndpoint_; // Sender of last RTP packet
  boost::asio::ip::udp::endpoint peerRtcpEndpoint_;
  boost::asio::ip::udp::endpoint localRtpEndpoint_;
  boost::asio::ip::udp::endpoint localRtcpEndpoint_;
  std::vector<uint8_t> rtpReceiveBuffer_;
  std::vector<uint8_t> rtcpReceiveBuffer_;
  bool rtpConnected_ = false;
  bool rtcpConnected_ = false;
  boost::asio::steady_timer retransmitTimer_; // For checking retransmit timeouts

  // Stream Parameters
  uint32_t latencyMin_ = 0; // Min latency in samples (from source)
  uint32_t latencyMax_ = 0; // Max latency in samples (from source)

  std::mutex stateMutex_; // Protects sequence numbers, retransmit lists,
                          // flushing state
  uint16_t lastRtpSeqReceived_ = 0; // For loss detection
  uint32_t lastRtpTsReceived_ = 0;
  bool rtpDupsInitialized_ = false;
  std::vector<uint16_t> rtpDupWindow_; // Ring buffer for duplicate detection
  uint16_t rtpDupLastSeq_ = 0;

  std::vector<std::byte> decryptionBuffer_;
  bool flushing_ = false;
  uint32_t flushUntilTs_ = 0;
  uint32_t flushTimeoutTs_ = 0; // When to stop forced flush mode

  // Cryptography
  enum class SecurityMode {
    NONE,
    AES_CBC,
    CHACHA_POLY
  }; // Keep for potential future use
  SecurityMode securityMode_ =
      SecurityMode::NONE;              // Keep for potential future use
  Utils::StreamCryptor outputCryptor_; // For incoming audio (decrypt)
  // Utils::StreamCryptor inputCryptor_; // For outgoing audio (encrypt)

  // Retransmissions
  std::vector<std::unique_ptr<AirTunesRetransmitNode>> retransmitNodePool_;
  std::list<AirTunesRetransmitNode *> freeRetransmitList_;
  std::list<AirTunesRetransmitNode *> busyRetransmitList_;
  bool rtcpRetransmitDisabled_ = false;
  int64_t rtcpMinRttNanos_ = INT64_MAX;
  int64_t rtcpMaxRttNanos_ = INT64_MIN;
  int64_t rtcpAvgRttNanos_ = 100'000'000; // Default 100ms
  int64_t rtcpDevRttNanos_ = 0;
  int64_t rtcpTimeoutNanos_ = 100'000'000; // Default 100ms
  uint32_t retransmitSendCount_ = 0;
  uint32_t retransmitReceiveCount_ = 0;
  uint32_t retransmitFutileCount_ = 0;
  uint32_t retransmitNotFoundCount_ = 0;
  uint64_t retransmitMinNanos_ = UINT64_MAX;
  uint64_t retransmitMaxNanos_ = 0;
  uint64_t retransmitAvgNanos_ = 0;
  uint64_t retransmitRetryMinNanos_ = UINT64_MAX;
  uint64_t retransmitRetryMaxNanos_ = 0;
  uint32_t retransmitMaxLoss_ = 30;
  uint32_t maxBurstLoss_ = 0;
  uint32_t bigLossCount_ = 0;

  // Statistics
  uint32_t lostPackets_ = 0;
  uint32_t unrecoveredPackets_ = 0;
  uint32_t latePackets_ = 0;

  // Control
  std::atomic<bool> isRunning_{false};
  std::atomic<bool> stopRequested_{false};
};
} // namespace Stream
} // namespace Session
} // namespace AirPlay