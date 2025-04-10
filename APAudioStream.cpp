// ==========================================================================
// APAudioStream.cpp
// ==========================================================================
#include "APAudioStream.hpp"
#include "APAudioCommon.hpp"
#include "APUtils.hpp"
#include "logger.hpp"
#include "plistcpp/Plist.hpp"
#include <algorithm>
#include <asm-generic/socket.h>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/bind/bind.hpp>
#include <chrono>
#include <random>

namespace AirPlay {
namespace Session {
namespace Stream {

using boost::asio::ip::udp;

// --- Helper Functions ---

uint64_t GenerateConnectionID() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> distrib;
  return distrib(gen);
}

// --- Constructor / Destructor ---

APAudioStream::APAudioStream(boost::asio::io_context &ioCtx,
                             APTimeSync *timeSynchronizer)
    : ioContext_(ioCtx), dataSocket_(ioCtx), controlSocket_(ioCtx),
      retransmitTimer_(ioCtx), rtpReceiveBuffer_(2048),
      rtcpReceiveBuffer_(1500), rtpDupWindow_(32, 0), decryptionBuffer_(2048),
      rateUpdateSamples_(20), timeSynchronizer_(timeSynchronizer) {
  LOG_INFO("APAudioStream created.");
}

APAudioStream::~APAudioStream() {
  stop();
  LOG_INFO("[{}]APAudioStream destroyed.", label_);
}

// --- Public Methods ---

APTimestampTuple APAudioStream::getZeroTime() {
  std::lock_guard<std::mutex> lock(zeroTimeMutex_);
  return zeroTime_;
}

bool APAudioStream::setDecryptionKey(const uint8_t *keyData, size_t keySize) {
  LOG_INFO("[{}] Attempting to set decryption key.", connectionID_);
  if (!keyData) {
    LOG_ERROR("[{}] Provided key data pointer is null.", connectionID_);
    return false;
  }
  if (keySize != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
    LOG_ERROR("[{}] Invalid decryption key size provided ({} bytes), expected "
              "{} bytes.",
              connectionID_, keySize,
              crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    return false;
  }

  std::lock_guard<std::mutex> lock(stateMutex_);

  try {
    outputCryptor_.initReadKey(keyData);
    LOG_INFO("[{}] Decryption key set successfully.", label_);
    return true;
  } catch (const std::exception &e) {
    LOG_ERROR("[{}] Exception while setting decryption key: {}", label_,
              e.what());
    outputCryptor_.keyPresent = false;
    return false;
  }
}

AudioStreamDescriptor APAudioStream::createDescriptor(APAudioFormat format,
                                                      uint16_t spf) {
  AudioStreamDescriptor out;
  switch (format) {
  case APAudioFormat::PCM_8KHz_16Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 8000;
    break;
  case APAudioFormat::PCM_8KHz_16Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 8000;
    break;
  case APAudioFormat::PCM_16KHz_16Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 16000;
    break;
  case APAudioFormat::PCM_16KHz_16Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 8000;
    break;
  case APAudioFormat::PCM_24KHz_16Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 24000;
    break;
  case APAudioFormat::PCM_24KHz_16Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 24000;
    break;
  case APAudioFormat::PCM_32KHz_16Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 32000;
    break;
  case APAudioFormat::PCM_32KHz_16Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 32000;
    break;
  case APAudioFormat::PCM_44KHz_16Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 44100;
    break;
  case APAudioFormat::PCM_44KHz_16Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 44100;
    break;
  case APAudioFormat::PCM_44KHz_24Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 24;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 44100;
    break;
  case APAudioFormat::PCM_44KHz_24Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 24;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 44100;
    break;
  case APAudioFormat::PCM_48KHz_16Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 48000;
    break;
  case APAudioFormat::PCM_48KHz_16Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 16;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 48000;
    break;
  case APAudioFormat::PCM_48KHz_24Bit_Mono:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 24;
    out.cpf = 1;
    out.fpp = 1;
    out.sr = 48000;
    break;
  case APAudioFormat::PCM_48KHz_24Bit_Stereo:
    out.audioFormat = AudioStreamDescriptor::PCM;
    out.bpc = 24;
    out.cpf = 2;
    out.fpp = 1;
    out.sr = 48000;
    break;
  case APAudioFormat::AAC_LC_44KHz_Stereo:
    out.audioFormat = AudioStreamDescriptor::AAC_LC;
    out.bpc = 0;
    out.cpf = 2;
    out.fpp = 1024;
    out.sr = 44100;
    break;
  case APAudioFormat::AAC_LC_48KHz_Stereo:
    out.audioFormat = AudioStreamDescriptor::AAC_LC;
    out.bpc = 0;
    out.cpf = 2;
    out.fpp = 1024;
    out.sr = 48000;
    break;
  case APAudioFormat::AAC_ELD_16KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::AAC_ELD;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = 480;
    out.sr = 16000;
    break;
  case APAudioFormat::AAC_ELD_24KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::AAC_ELD;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = 480;
    out.sr = 24000;
    break;
  case APAudioFormat::AAC_ELD_44KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::AAC_ELD;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = 480;
    out.sr = 44100;
    break;
  case APAudioFormat::AAC_ELD_44KHz_Stereo:
    out.audioFormat = AudioStreamDescriptor::AAC_ELD;
    out.bpc = 0;
    out.cpf = 2;
    out.fpp = 480;
    out.sr = 44100;
    break;
  case APAudioFormat::AAC_ELD_48KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::AAC_ELD;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = 480;
    out.sr = 48000;
    break;
  case APAudioFormat::AAC_ELD_48KHz_Stereo:
    out.audioFormat = AudioStreamDescriptor::AAC_ELD;
    out.bpc = 0;
    out.cpf = 2;
    out.fpp = 480;
    out.sr = 48000;
    break;
  case APAudioFormat::OPUS_16KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::OPUS;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = ((16000) * 20) / 1000;
    out.sr = 16000;
    break;
  case APAudioFormat::OPUS_24KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::OPUS;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = ((24000) * 20) / 1000;
    out.sr = 24000;
    break;
  case APAudioFormat::OPUS_48KHz_Mono:
    out.audioFormat = AudioStreamDescriptor::OPUS;
    out.bpc = 0;
    out.cpf = 1;
    out.fpp = ((48000) * 20) / 1000;
    out.sr = 48000;
    break;
  default:
    LOG_ERROR("Unsupported AudioFormat: %u", static_cast<uint32_t>(format));
    break;
  }
  return out;
}

bool APAudioStream::setMainHighAudio(
    boost::asio::ip::address peerAddress, Plist::dictionary_type &streamDesc,
    Plist::dictionary_type &outResponseParams) {
  // --- Extract Parameters ---
  if (streamDesc["streamConnectionID"].type() == typeid(Plist::integer_type)) {
    connectionID_ =
        boost::any_cast<Plist::integer_type>(streamDesc["streamConnectionID"]);
  }
  if (connectionID_ == 0) {
    connectionID_ = GenerateConnectionID();
    LOG_WARN("StreamConnectionID not provided, generated: {}", connectionID_);
  } else {
    LOG_DEBUG("StreamConnectionID: {}", connectionID_);
  }

  descriptor =
      createDescriptor((APAudioFormat)(boost::any_cast<Plist::integer_type>(
                           streamDesc["audioFormat"])),
                       boost::any_cast<Plist::integer_type>(streamDesc["spf"]));

  LOG_DEBUG("[{}] Input Format: {} SR={}kHz, Ch={}, Bits={}", label_,
            AudioFormatToString(descriptor.audioFormat), descriptor.sr,
            descriptor.cpf, descriptor.bpc);

  uint32_t latencyMs;
  if(streamDesc["audioLatencyMs"].type() == typeid(Plist::integer_type)){
    latencyMs = boost::any_cast<int64_t>(streamDesc["audioLatencyMs"]);
  }
  if (latencyMs > 0) {
    latencyMin_ = descriptor.sr * latencyMs / 1000;
    latencyMax_ = latencyMin_;
  }
  if(streamDesc["latencyMin"].type() == typeid(Plist::integer_type) && streamDesc["latencyMax"].type() == typeid(Plist::integer_type)){
    latencyMin_ = boost::any_cast<int64_t>(streamDesc["latencyMin"]);
    latencyMax_ = boost::any_cast<int64_t>(streamDesc["latencyMax"]);
  }
  // Set a default latency if none provided
  if (latencyMin_ == 0 && latencyMax_ == 0) {
    latencyMin_ = descriptor.sr * 100 / 1000; // Default 100ms?
    latencyMax_ = latencyMin_;
    LOG_WARN("No latency specified, using default: {} samples", latencyMin_);
  }
  LOG_DEBUG("[{}] Latency: Min={} samples, Max={} samples", label_, latencyMin_,
            latencyMax_);
  if(streamDesc["redundantAudio"].type() == typeid(Plist::integer_type) ){
    rtcpRetransmitDisabled_ = true;
  }
  // --- Initialize Retransmissions ---
  if (!rtcpRetransmitDisabled_) {
    retransmitNodePool_.reserve(64);
    freeRetransmitList_.clear();
    for (size_t i = 0; i < 64; ++i) {
      retransmitNodePool_.push_back(std::make_unique<AirTunesRetransmitNode>());
      freeRetransmitList_.push_back(retransmitNodePool_.back().get());
    }
    retransmitMaxLoss_ =
        ((latencyMin_ + (descriptor.fpp / 2)) / descriptor.fpp) / 2;
    if (retransmitMaxLoss_ == 0)
      retransmitMaxLoss_ = 1;
    LOG_DEBUG("[{}] Initialized Retransmissions: MaxLoss={}, Timeout={} ms",
              label_, retransmitMaxLoss_, rtcpTimeoutNanos_ / 1'000'000);
  }
  // --- Initialize Rate Estimation ---
  rateUpdateNextTime_ = std::chrono::steady_clock::now() + rateUpdateInterval_;
  rateAvg_ = static_cast<float>(descriptor.sr);

  // --- Setup Networking ---
  boost::system::error_code ec;

  // RTP (Data) Socket
  udp::endpoint rtpListenEndpoint(peerAddress.is_v6()
                                      ? boost::asio::ip::udp::v6()
                                      : boost::asio::ip::udp::v4(),
                                  5004); // Listen on default port initially
  dataSocket_.open(rtpListenEndpoint.protocol(), ec);
  if (ec) {
    LOG_ERROR("Failed to open RTP socket: {}", ec.message().c_str());
    return false;
  }
  dataSocket_.bind(rtpListenEndpoint, ec);
  if (ec) {
    LOG_ERROR("Failed to bind RTP socket: {}", ec.message().c_str());
    return false;
  }
  if (ec) {
    LOG_ERROR("Failed to bind RTP socket: {}", ec.message().c_str());
    dataSocket_.close();
    return false;
  }
  localRtpEndpoint_ = dataSocket_.local_endpoint();
  dataSocket_.set_option(
      boost::asio::detail::socket_option::integer<IPPROTO_IP, IP_TOS>(0xC0));
  dataSocket_.set_option(
      boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_TIMESTAMP>(
          true));
  LOG_DEBUG("[{}] RTP Data socket bound to {}", label_,
            localRtpEndpoint_.address().to_string().c_str());

  // RTCP (Control) Socket
  udp::endpoint rtcpListenEndpoint(peerAddress.is_v6()
                                       ? boost::asio::ip::udp::v6()
                                       : boost::asio::ip::udp::v4(),
                                   5000);
  controlSocket_.open(rtcpListenEndpoint.protocol(), ec);
  controlSocket_.set_option(
      boost::asio::detail::socket_option::integer<IPPROTO_IP, IP_TOS>(0xC0));
  controlSocket_.set_option(
      boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_TIMESTAMP>(
          true));
  if (ec) {
    LOG_ERROR("Failed to open RTCP socket: {}", ec.message().c_str());
    dataSocket_.close();
    return false;
  }
  controlSocket_.bind(rtcpListenEndpoint, ec);
  if (ec) {
    LOG_ERROR("Failed to bind RTCP socket: {}", ec.message().c_str());
    return false;
  }
  // Try to bind
  // uint16_t boundRtcpPort = rtcpListenEndpoint.port();
  // for (int port = 5000; port < 5000 + 100; ++port) {
  //   udp::endpoint bindEp(peerAddress.is_v6() ? boost::asio::ip::udp::v6()
  //                                            : boost::asio::ip::udp::v4(),
  //                        port);
  //   controlSocket_.bind(bindEp, ec);
  //   if (!ec) {
  //     boundRtcpPort = port;
  //     break;
  //   }
  // }
  if (ec) {
    LOG_ERROR("Failed to bind RTCP socket: {}", ec.message().c_str());
    dataSocket_.close();
    controlSocket_.close();
    return false;
  }
  localRtcpEndpoint_ = controlSocket_.local_endpoint();

  peerRtcpEndpoint_ =
      udp::endpoint(peerAddress, static_cast<int64_t>(boost::any_cast<int64_t>(
                                     streamDesc["controlPort"])));
  LOG_DEBUG("[{}] RTCP Control socket bound to {}, peer is {}", label_,
            localRtcpEndpoint_.address().to_string().c_str(),
            peerRtcpEndpoint_.address().to_string().c_str());

  // Try to connect RTCP socket
  controlSocket_.connect(peerRtcpEndpoint_, ec);
  if (!ec) {
    rtcpConnected_ = true;
    LOG_DEBUG("RTCP socket connected to peer.");
  } else {
    rtcpConnected_ = false;
    LOG_WARN("RTCP socket connect failed ({}), will use send_to.",
             ec.message().c_str());
    ec.clear();
  }

  // --- Populate Response Parameters ---
  outResponseParams["type"] = static_cast<int64_t>(type_);
  outResponseParams["dataPort"] =
      static_cast<int64_t>(localRtpEndpoint_.port());
  outResponseParams["controlPort"] =
      static_cast<int64_t>(localRtcpEndpoint_.port());
  if (type_ == Utils::StreamType::APAudio) {
    outResponseParams["streamID"] = static_cast<int64_t>(connectionID_); 
  } else {
    outResponseParams["streamConnectionID"] = static_cast<int64_t>(connectionID_);
  }
  // --- Notify Delegate about Format ---
  if (delegate_) {
    LOG_DEBUG("Notifying delegate of stream format.");
    delegate_->onStreamFormatReady(descriptor);
  } else {
    LOG_WARN("Delegate not set during setup!");
  }
  LOG_DEBUG("Setup complete. Response params populated.");

  return true;
}

bool APAudioStream::setup(Utils::StreamType streamType,
                          boost::asio::ip::address peerAddress,
                          Plist::dictionary_type &streamDesc,
                          Plist::dictionary_type &outResponseParams) {
  type_ = streamType;
  switch (type_) {
  case Utils::StreamType::CPMainHighAudio:
    label_ = "MainHigh";
    break;
  case Utils::StreamType::CPMainAudio:
    label_ = "Main";
    break;
  case Utils::StreamType::CPAltAudio:
    label_ = "Alt";
    break;
  default:
    label_ = "Unknown";
    break;
  }
  LOG_INFO("Setting up APAudioStream for type {}", label_);
  std::lock_guard<std::mutex> lock(stateMutex_); // Protect setup process

  if (isRunning_) {
    LOG_ERROR("Cannot setup while already running.");
    return false;
  }

  try {
    switch (type_) {
        case Utils::StreamType::CPMainHighAudio:{
            return setMainHighAudio(peerAddress, streamDesc, outResponseParams);
        }
        break;
        case Utils::StreamType::CPMainAudio:{

        }
        break;
        case Utils::StreamType::CPAltAudio:{

        }
        break;
        case Utils::StreamType::APAudio:{
            return setMainHighAudio(peerAddress, streamDesc, outResponseParams);
        }
        break;
        default:
            LOG_ERROR("Stream type not implemented: {}", (int)type_);
        break;
    }
    return true;
  } catch (const std::exception &e) {
    LOG_ERROR("Exception during setup: {}", e.what());
    cleanup();
    return false;
  }
}

bool APAudioStream::start() {
  LOG_INFO("[{}] Starting APAudioStream...", label_.c_str());
  if (isRunning_) {
    LOG_WARN("[{}] Already running.", label_.c_str());
    return true;
  }
  if (!dataSocket_.is_open() || !controlSocket_.is_open()) {
    LOG_ERROR("[{}] Cannot start, sockets not open/setup.", label_.c_str());
    return false;
  }
  if (!delegate_) {
    // Allow starting without delegate, but log warning. Packets will be
    // dropped.
    LOG_WARN(
        "[{}] Starting without a delegate set. Audio packets will be dropped.",
        label_.c_str());
  }
  if (!timeSynchronizer_) {
    LOG_ERROR("[{}] Cannot start, time synchronizer not set.", label_.c_str());
    return false;
  }

  isRunning_.store(true);
  stopRequested_.store(false);

  // Start async receives
  startRtpReceive();
  startRtcpReceive();

  // Start retransmit timer if needed
  if (!rtcpRetransmitDisabled_) {
    retransmitTimer_.expires_after(
        std::chrono::nanoseconds(rtcpTimeoutNanos_)); // Initial delay
    retransmitTimer_.async_wait([this](const boost::system::error_code &ec) {
      if (!ec) {
        std::lock_guard<std::mutex> lock(stateMutex_);
        checkRetransmitTimeouts(); // Start the regular checks
      } else if (ec != boost::asio::error::operation_aborted) {
        LOG_ERROR("[{}] Retransmit timer error: {}", label_.c_str(),
                  ec.message());
      }
    });
  }
  LOG_INFO("[{}] APAudioStream started successfully.", label_.c_str());
  return true;
}

void APAudioStream::stop() {
  LOG_INFO("[{}] Stopping APAudioStream...", label_.c_str());
  if (!isRunning_.load() &&
      !stopRequested_.load()) { // Check if already stopped or stopping
    LOG_DEBUG("[{}] Already stopped or stop requested.", label_.c_str());
    return;
  }

  if (stopRequested_.exchange(
          true)) { // Atomically set and check previous value
    LOG_DEBUG("[{}] Stop already requested.", label_.c_str());
    return; // Already stopping
  }
  if (!isRunning_.load()) { // Check again inside the handler
    LOG_DEBUG("[{}] Stop handler: Already stopped.", label_.c_str());
    return;
  }

  LOG_DEBUG("[{}] Executing stop sequence on io_context thread.",
            label_.c_str());

  isRunning_.store(false);

  boost::system::error_code ec;
  retransmitTimer_.cancel();
  LOG_DEBUG("[{}] Retransmit timer cancelled", label_.c_str());

  // Sockets should be closed *after* cancelling operations that use them
  if (dataSocket_.is_open()) {
    dataSocket_.cancel(ec);
    LOG_DEBUG("[{}] RTP socket cancelled: {}", label_.c_str(), ec.message());
    dataSocket_.close(ec);
    LOG_DEBUG("[{}] RTP socket closed: {}", label_.c_str(), ec.message());
  }
  if (controlSocket_.is_open()) {
    controlSocket_.cancel(ec);
    LOG_DEBUG("[{}] RTCP socket cancelled: {}", label_.c_str(), ec.message());
    controlSocket_.close(ec);
    LOG_DEBUG("[{}] RTCP socket closed: {}", label_.c_str(), ec.message());
  }

  {
    std::lock_guard<std::mutex> lock(stateMutex_);
    cleanup();
  }

  LOG_INFO("[{}] APAudioStream stop sequence complete.", label_.c_str());
}

void APAudioStream::cleanup() {
  LOG_DEBUG("[{}] Cleaning up APAudioStream state...", label_.c_str());

  // Reset retransmit nodes
  freeRetransmitList_.clear();
  busyRetransmitList_.clear();
  for (const auto &nodePtr : retransmitNodePool_) {
    if (nodePtr) {
      nodePtr->isInUse = false;
      freeRetransmitList_.push_back(nodePtr.get());
    }
  }

  // Reset state variables
  lastRtpSeqReceived_ = 0;
  lastRtpTsReceived_ = 0;
  rtpDupsInitialized_ = false;
  std::fill(rtpDupWindow_.begin(), rtpDupWindow_.end(), 0);
  rtpDupLastSeq_ = 0;
  flushing_ = false;
  lostPackets_ = 0;
  unrecoveredPackets_ = 0;
  latePackets_ = 0;
  maxBurstLoss_ = 0;
  bigLossCount_ = 0;
  retransmitSendCount_ = 0;
  retransmitReceiveCount_ = 0;
  retransmitFutileCount_ = 0;
  retransmitNotFoundCount_ = 0;

  LOG_DEBUG("[{}] Cleanup finished.", label_.c_str());
}

// --- Network Receive Handlers ---

void APAudioStream::startRtpReceive() {
  if (!isRunning_.load() || stopRequested_.load())
    return;
  if (peerRtpEndpoint_.address().is_unspecified()) {
    dataSocket_.async_receive_from(
        boost::asio::buffer(rtpReceiveBuffer_), peerRtpEndpoint_,
        [this](const boost::system::error_code &error, size_t bytes_recvd) {
          handleRtpReceive(error, bytes_recvd);
        });
  } else {
    dataSocket_.async_receive(
        boost::asio::buffer(rtpReceiveBuffer_),
        [this](const boost::system::error_code &error, size_t bytes_recvd) {
          handleRtpReceive(error, bytes_recvd);
        });
  }
}

void APAudioStream::handleRtpReceive(const boost::system::error_code &error,
                                     size_t bytes_recvd) {
  if (stopRequested_.load() || !isRunning_.load())
    return; // Check running state too

  if (!error && bytes_recvd > 0) {
    LOG_VERBOSE("[{}] RTP Received {} bytes from {}", label_.c_str(),
                bytes_recvd, peerRtpEndpoint_.address().to_string());
    processRtpPacket(rtpReceiveBuffer_.data(), bytes_recvd, false);
    startRtpReceive(); // Listen for the next packet
  } else if (error == boost::asio::error::operation_aborted) {
    LOG_DEBUG("[{}] RTP receive operation aborted.", label_.c_str());
  } else if (error) {
    LOG_ERROR("[{}] RTP receive error: {}", label_.c_str(), error.message());
    // Decide whether to stop or retry
    if (isRunning_.load() && !stopRequested_.load()) {
      startRtpReceive();
    }
  } else {
    LOG_WARN("[{}] RTP receive returned 0 bytes.", label_.c_str());
    startRtpReceive();
  }
}

void APAudioStream::startRtcpReceive() {
  if (!isRunning_.load() || stopRequested_.load())
    return;
  if (rtcpConnected_) {
    controlSocket_.async_receive(
        boost::asio::buffer(rtcpReceiveBuffer_),
        [this](const boost::system::error_code &error, size_t bytes_recvd) {
          handleRtcpReceive(error, bytes_recvd);
        });
  } else {
    controlSocket_.async_receive_from(
        boost::asio::buffer(rtcpReceiveBuffer_), peerRtcpEndpoint_,
        [this](const boost::system::error_code &error, size_t bytes_recvd) {
          handleRtcpReceive(error, bytes_recvd);
        });
  }
}

void APAudioStream::handleRtcpReceive(const boost::system::error_code &error,
                                      size_t bytes_recvd) {
  if (stopRequested_.load() || !isRunning_.load())
    return;

  if (!error && bytes_recvd > 0) {
    LOG_VERBOSE("[{}] RTCP Received {} bytes from {}", label_.c_str(),
                bytes_recvd, peerRtcpEndpoint_.address().to_string());
    processRtcpPacket(rtcpReceiveBuffer_.data(), bytes_recvd);
    startRtcpReceive();
  } else if (error == boost::asio::error::operation_aborted) {
    LOG_DEBUG("[{}] RTCP receive operation aborted.", label_.c_str());
  } else if (error) {
    LOG_ERROR("[{}] RTCP receive error: {}", label_.c_str(), error.message());
    if (isRunning_.load() && !stopRequested_.load()) {
      startRtcpReceive();
    }
  } else {
    LOG_WARN("[{}] RTCP receive returned 0 bytes.", label_.c_str());
    startRtcpReceive();
  }
}

// --- Packet Processing ---

void APAudioStream::processRtpPacket(const uint8_t *buffer, size_t size,
                                     bool isRetransmit) {
  LOG_VERBOSE("[{}] Processing RTP packet: size={}, retransmit={}",
              label_.c_str(), size, isRetransmit);

  if (size < kRTPHeaderSize) {
    LOG_WARN("[{}] RTP packet too small: {} bytes", label_.c_str(), size);
    return;
  }

  // Parse RTP header
  RtpHeader rtpHeader;
  const RtpHeader *rawRtp = reinterpret_cast<const RtpHeader *>(buffer);
  rtpHeader.version_p_x_cc = rawRtp->version_p_x_cc;
  rtpHeader.m_pt = rawRtp->m_pt;
  rtpHeader.sequenceNumber =
      boost::endian::big_to_native(rawRtp->sequenceNumber);
  rtpHeader.timestamp = boost::endian::big_to_native(rawRtp->timestamp);
  rtpHeader.ssrc = boost::endian::big_to_native(rawRtp->ssrc);

  const uint8_t *payloadPtr = buffer + kRTPHeaderSize;
  size_t payloadSize = size - kRTPHeaderSize;

  LOG_VERBOSE("[{}] Parsed RTP: Seq={}, TS={}, Size={}", label_.c_str(),
              rtpHeader.sequenceNumber, rtpHeader.timestamp, payloadSize);

  // Lock state for sequence checks, retransmit updates, flushing check
  std::lock_guard<std::mutex> lock(stateMutex_);

  if (trackDuplicate(rtpHeader.sequenceNumber)) {
    LOG_VERBOSE("[{}] Duplicate RTP packet detected: Seq={}", label_.c_str(),
              rtpHeader.sequenceNumber);
    return; // Discard duplicate
  }

  if (!isRetransmit) {
    trackLosses(rtpHeader);
  }

  if (!rtcpRetransmitDisabled_) {
    // If this packet arrived (retransmit or not), cancel any pending request
    // for it
    updateRetransmits(rtpHeader.sequenceNumber);
  }

  if (flushing_) {
    // Check if packet is before the flush point
    if (Mod32_LT(rtpHeader.timestamp, flushUntilTs_)) {
      LOG_DEBUG(
          "[{}] Discarding pre-flush packet: Seq={}, TS={} (FlushUntil={})",
          label_.c_str(), rtpHeader.sequenceNumber, rtpHeader.timestamp,
          flushUntilTs_);
      return;
    }
    if (Mod32_GE(rtpHeader.timestamp, flushTimeoutTs_)) {
      LOG_INFO("[{}] Flush timeout reached: TS={} >= TimeoutTS={}",
               label_.c_str(), rtpHeader.timestamp, flushTimeoutTs_);
      flushing_ = false;
    }
  }

  bool decryptOk = decryptPacket(rtpHeader, payloadPtr, payloadSize);
  if (!decryptOk) {
    LOG_WARN("[{}] Failed to decrypt packet Seq={}. Discarding.",
             label_.c_str(), rtpHeader.sequenceNumber);
    return;
  }

  // Push to Delegate (if delegate exists)
  if (delegate_) {
    LOG_VERBOSE(
        "[{}] Pushing decrypted packet Seq={} TS={} Size={} to delegate.",
        label_.c_str(), rtpHeader.sequenceNumber, rtpHeader.timestamp,
        decryptionBuffer_.size());
    // Pass the header and a span pointing to the decrypted data
    delegate_->onDecryptedPacketReady(
        rtpHeader, {decryptionBuffer_.data(), decryptionBuffer_.size()});
  } else {
    LOG_VERBOSE("[{}] No delegate set, dropping decrypted packet Seq={}",
                label_.c_str(), rtpHeader.sequenceNumber);
  }

  // Update Rate Estimation
  // Get host time close to arrival (needs SO_TIMESTAMP or approximation)
  uint64_t hostTimeNanos = GetCurrentNanos();
  updateEstimatedRate(rtpHeader.timestamp, hostTimeNanos);
}

void APAudioStream::processRtcpPacket(const uint8_t *buffer, size_t size) {
  LOG_VERBOSE("[{}] Processing RTCP packet: size={}", label_.c_str(), size);
  if (size < sizeof(RtcpCommonHeader)) {
    LOG_WARN("[{}] RTCP packet too small: {} bytes", label_.c_str(), size);
    return;
  }

  const RtcpCommonHeader *header =
      reinterpret_cast<const RtcpCommonHeader *>(buffer);
  uint8_t version = (header->v_p_c >> 6) & 0x03;
  uint8_t pt = header->pt;
  uint16_t length = boost::endian::big_to_native(header->length);
  size_t totalSize = (length + 1) * 4;

  if (version != kRTPVersion) {
    LOG_WARN("[{}] Invalid RTCP version: {}", label_.c_str(), version);
    return;
  }

  LOG_DEBUG("[{}] RTCP Packet Type: {}", label_.c_str(), pt);

  switch (pt) {
  case kRTCPTypeRetransmitResponse:
    processRetransmitResponse(buffer, size);
    break;
  default:
    LOG_WARN("[{}] Unsupported RTCP packet type: {} ({} bytes)", label_.c_str(),
             pt, size);
    break;
  }
}

// --- Duplicate and Loss Tracking ---

bool APAudioStream::trackDuplicate(uint16_t seq) {
  if (rtpDupsInitialized_) {
    int diff = Mod16_Cmp(seq, rtpDupLastSeq_);
    if (diff > 0) {
    } else if (diff == 0) {
      goto dup; // Exact same sequence number
    } else {    // diff < 0 (out of order or duplicate)
      if (static_cast<uint16_t>(rtpDupLastSeq_ - seq) < 32) {
        size_t index = seq % 32;
        if (rtpDupWindow_[index] == seq) {
          goto dup; // Found in window
        }
        rtpDupWindow_[index] = seq; // Record out-of-order
        return false;               // Not a duplicate yet
      } else {
        // Too old, treat as non-duplicate
        LOG_WARN("[{}] Packet seq {} is older than duplicate window (last {})",
                 label_.c_str(), seq, rtpDupLastSeq_);
        return false;
      }
    }
    // If diff > 0, update window
    size_t index = seq % 32;
    rtpDupWindow_[index] = seq;

  } else {
    // First packet, initialize window
    for (size_t i = 0; i < 32; ++i) {
      rtpDupWindow_[i] = seq;
    }
    rtpDupsInitialized_ = true;
    LOG_DEBUG("[{}] Duplicate detection initialized with seq {}",
              label_.c_str(), seq);
  }

  rtpDupLastSeq_ = seq; // Update last seen sequence number
  return false;

dup:
  // LOG_WARN("[{}] Duplicate packet detected: seq {}", label_.c_str(), seq);
  return true;
}

void APAudioStream::trackLosses(const RtpHeader &rtpHeader) {
  uint16_t seqCurr = rtpHeader.sequenceNumber;

  if (!rtpDupsInitialized_) {
    // This case should ideally be handled by the initialization in
    // trackDuplicate If we reach here, it means trackDuplicate wasn't called or
    // didn't initialize.
    LOG_WARN("[{}] trackLosses called before duplicate detection initialized "
             "(seq {})",
             label_.c_str(), seqCurr);
  }

  // Only proceed if we have received at least one packet before
  if (lastRtpSeqReceived_ != 0 && rtpDupsInitialized_) {
    uint16_t seqExpected = lastRtpSeqReceived_ + 1;

    if (seqCurr == seqExpected) {
      // Perfect case, no loss
      LOG_VERBOSE("[{}] Packet received in order: seq {}", label_.c_str(),
                  seqCurr);
    } else if (Mod16_GT(seqCurr, seqExpected)) {
      // Gap detected
      uint16_t seqLoss = seqCurr - seqExpected;
      lostPackets_ += seqLoss;
      if (seqLoss > maxBurstLoss_)
        maxBurstLoss_ = seqLoss;

      LOG_WARN("[{}] Lost packets detected: {}-{} ({} lost, total {})",
               label_.c_str(), seqExpected, static_cast<uint16_t>(seqCurr - 1),
               seqLoss, lostPackets_);

      // Notify delegate about the loss *before* requesting retransmit
      if (delegate_) {
        delegate_->onPacketLossDetected(seqExpected, seqLoss);
      }

      // Schedule retransmits if enabled
      if (!rtcpRetransmitDisabled_) {
        if (seqLoss <= retransmitMaxLoss_) {
          scheduleRetransmits(seqExpected, seqLoss);
        } else {
          LOG_WARN("[{}] Burst loss ({}) exceeds max loss ({}). Aborting "
                   "retransmits.",
                   label_.c_str(), seqLoss, retransmitMaxLoss_);
          ++bigLossCount_;
          abortAllRetransmits("BURST");
        }
      }
    } else {
      LOG_WARN("[{}] Misordered packet received: Expected {}, Got {}",
               label_.c_str(), seqExpected, seqCurr);
      // Don't update lastRtpSeqReceived for misordered packets
      // The packet will still be processed (decrypted and sent to delegate)
      return; // Skip updating lastRTPSeq/TS
    }
  } else {
    LOG_DEBUG("[{}] First packet received: seq {}", label_.c_str(), seqCurr);
  }

  // Update last received sequence number and timestamp
  lastRtpSeqReceived_ = seqCurr;
  lastRtpTsReceived_ = rtpHeader.timestamp;
}

// --- Decryption / Decoding ---

void APAudioStream::generateAad(const RtpHeader &rtpHeader,
                                std::vector<uint8_t> &aad) {
  // AAD = RTP Timestamp (4 bytes, Network Order) + SSRC (4 bytes, Network
  // Order)
  aad.resize(sizeof(uint32_t) + sizeof(uint32_t));
  uint32_t ts_be = boost::endian::native_to_big(rtpHeader.timestamp);
  uint32_t ssrc_be = boost::endian::native_to_big(rtpHeader.ssrc);
  memcpy(aad.data(), &ts_be, sizeof(ts_be));
  memcpy(aad.data() + sizeof(ts_be), &ssrc_be, sizeof(ssrc_be));
  LOG_VERBOSE("Generated AAD for TS={}, SSRC={}", rtpHeader.timestamp,
              rtpHeader.ssrc);
}

bool APAudioStream::decryptPacket(const RtpHeader &rtpHeader,
                                  const uint8_t *payloadPtr,
                                  size_t payloadSize) {
  if (!outputCryptor_.keyPresent) {
    LOG_VERBOSE("[{}] Decryption not enabled/needed for seq {}.",
                label_.c_str(), rtpHeader.sequenceNumber);
    decryptionBuffer_.resize(payloadSize);
    memcpy(decryptionBuffer_.data(), payloadPtr, payloadSize);
    return true; // No decryption needed
  }

  LOG_VERBOSE("[{}] Decrypting packet seq {}, size {}", label_.c_str(),
              rtpHeader.sequenceNumber, payloadSize);

  std::vector<uint8_t> aad;
  generateAad(rtpHeader, aad);

  size_t decryptedSize = 0;
  // Ensure decryption buffer is large enough (payloadSize should be max
  // possible size)
  if (decryptionBuffer_.size() <
      payloadSize) { // Resize slightly larger just in case? Usually decrypt is
                     // smaller/same.
    decryptionBuffer_.resize(payloadSize);
  }

  bool success = outputCryptor_.decrypt(
      aad.data(), aad.size(), payloadPtr,
      payloadSize, // Ciphertext includes nonce+tag
      reinterpret_cast<uint8_t *>(decryptionBuffer_.data()), decryptedSize,
      true);

  if (success) {
    decryptionBuffer_.resize(
        decryptedSize); // Resize buffer to actual decrypted size
    LOG_VERBOSE("[{}] ChaChaPoly decryption successful, new size {}",
                label_.c_str(), decryptedSize);
    return true;
  } else {
    LOG_WARN("[{}] ChaChaPoly decryption FAILED for seq {}.", label_.c_str(),
             rtpHeader.sequenceNumber);
    decryptionBuffer_.clear();
    return false;
  }
}

// --- Retransmission Logic ---

APAudioStream::AirTunesRetransmitNode *APAudioStream::getFreeRetransmitNode() {
  if (freeRetransmitList_.empty()) {
    LOG_WARN("[{}] No free retransmit nodes available!", label_.c_str());
    return nullptr;
  }
  AirTunesRetransmitNode *node = freeRetransmitList_.front();
  freeRetransmitList_.pop_front();
  node->isInUse = true;
  return node;
}

void APAudioStream::releaseRetransmitNode(AirTunesRetransmitNode *node) {
  if (!node)
    return;
  busyRetransmitList_.remove(node);
  node->isInUse = false;
  freeRetransmitList_.push_front(node);
}

void APAudioStream::scheduleRetransmits(uint16_t seqStart, uint16_t seqCount) {
  LOG_INFO("[{}] Scheduling retransmit requests for seq {} - {} ({} packets)",
           label_.c_str(), seqStart,
           static_cast<uint16_t>(seqStart + seqCount - 1), seqCount);

  uint64_t nowNanos = GetCurrentNanos();

  for (uint16_t i = 0; i < seqCount; ++i) {
    uint16_t seqToRequest = seqStart + i;

    // Check if already pending
    bool alreadyPending = false;
    for (const auto *busyNode : busyRetransmitList_) {
      if (busyNode->seq == seqToRequest) {
        alreadyPending = true;
        break;
      }
    }
    if (alreadyPending) {
      LOG_DEBUG("[{}] Retransmit request for seq {} already pending.",
                label_.c_str(), seqToRequest);
      continue;
    }

    AirTunesRetransmitNode *node = getFreeRetransmitNode();
    if (!node) {
      LOG_WARN(
          "[{}] Failed to get retransmit node for seq {}, dropping request.",
          label_.c_str(), seqToRequest);
      continue; // Skip this sequence number
    }

    node->seq = seqToRequest;
    node->tries = 0;
    node->startNanos = nowNanos;
    node->sentNanos = 0;
    node->nextNanos = nowNanos; // Check immediately

    busyRetransmitList_.push_back(node);
  }
}

// Just cancels the pending request if the packet arrives. RTT is updated in
// checkRetransmitTimeouts.
void APAudioStream::updateRetransmits(uint16_t receivedSeq) {
  if (rtcpRetransmitDisabled_)
    return;

  // Check if this packet fulfills an outstanding retransmit request
  auto it = std::find_if(busyRetransmitList_.begin(), busyRetransmitList_.end(),
                         [receivedSeq](const AirTunesRetransmitNode *node) {
                           return node->seq == receivedSeq;
                         });

  if (it != busyRetransmitList_.end()) {
    AirTunesRetransmitNode *foundNode = *it;
    LOG_INFO("[{}] Retransmit request for seq {} fulfilled by incoming packet.",
             label_.c_str(), receivedSeq);
    // Don't calculate RTT here, do it in checkRetransmitTimeouts when response
    // arrives
    releaseRetransmitNode(
        foundNode); // Remove from busy list, put back in free list
  }
  // If it wasn't found in busy list, it means either:
  // We never requested it (normal packet).
  // We requested it, but it arrived via retransmit *response* (handled in
  // processRetransmitResponse).
  // We requested it, but it timed out and was aborted already.
}

void APAudioStream::checkRetransmitTimeouts() {
  if (rtcpRetransmitDisabled_ || stopRequested_.load() || !isRunning_.load())
    return;

  uint64_t nowNanos = GetCurrentNanos();
  int credits = 3; // Limit number of requests sent per check

  LOG_VERBOSE("[{}] Checking retransmit timeouts ({} busy nodes)...",
              label_.c_str(), busyRetransmitList_.size());

  // Use iterator loop for safe removal
  auto it = busyRetransmitList_.begin();
  while (it != busyRetransmitList_.end()) {
    AirTunesRetransmitNode *node = *it;
    if (nowNanos >= node->nextNanos) {
      // Timeout occurred or initial check needed
      node->tries += 1;
      uint64_t ageNanos = nowNanos - node->startNanos;
      if (node->tries > 10) {
        LOG_WARN("[{}] Retransmit max tries reached for seq {}. Aborting.",
                 label_.c_str(), node->seq);
        ++unrecoveredPackets_;
        it = busyRetransmitList_.erase(it);
        releaseRetransmitNode(node);
        continue;
      }

      LOG_WARN("[{}] Retransmit timeout/check for seq {} (try {}, age {} ms)",
               label_.c_str(), node->seq, node->tries, ageNanos / 1'000'000);

      // Use current RTO for next timeout
      node->sentNanos = nowNanos;
      node->nextNanos = nowNanos + rtcpTimeoutNanos_;

      // Send request if credits available
      if (credits > 0) {
        sendRetransmitRequest(node->seq, 1);
        --credits;
      } else {
        LOG_DEBUG("[{}] Retransmit send limit reached for this check.",
                  label_.c_str());
      }
      ++it; // Move to next node
    } else {
      ++it; // Move to next node
    }
  }

  // Reschedule the timer
  retransmitTimer_.expires_after(std::chrono::nanoseconds(
      std::max(rtcpTimeoutNanos_, (int64_t)10'000'000)));
  retransmitTimer_.async_wait([this](const boost::system::error_code &ec) {
    if (!ec) {
      std::lock_guard<std::mutex> lock(stateMutex_);
      checkRetransmitTimeouts();
    } else if (ec != boost::asio::error::operation_aborted) {
      LOG_ERROR("[{}] Retransmit timer error: {}", label_.c_str(),
                ec.message());
    }
  });
}

void APAudioStream::sendRetransmitRequest(uint16_t seqStart,
                                          uint16_t seqCount) {
  LOG_DEBUG("[{}] Sending retransmit request: SeqStart={}, Count={}",
            label_.c_str(), seqStart, seqCount);

  RtcpRetransmitRequestPacket pkt;
  pkt.v_p = (kRTPVersion << 6);
  pkt.pt = kRTCPTypeRetransmitRequest;
  pkt.length = boost::endian::native_to_big(
      static_cast<uint16_t>((kRTCPRetransmitRequestPacketMinSize / 4) - 1));
  pkt.seqStart = boost::endian::native_to_big(seqStart);
  pkt.seqCount = boost::endian::native_to_big(seqCount);

  sendRtcpPacket(reinterpret_cast<uint8_t *>(&pkt),
                 kRTCPRetransmitRequestPacketMinSize);
  ++retransmitSendCount_;
}

void APAudioStream::processRetransmitResponse(const uint8_t *data,
                                              size_t size) {
  LOG_DEBUG("[{}] Processing retransmit response ({} bytes)", label_.c_str(),
            size);

  // Check for "fail" response (FUTILE)
  const size_t failPayloadSize = sizeof(RtcpRetransmitResponseFailPayload);
  const size_t failResponseSize = sizeof(RtcpCommonHeader) + failPayloadSize;
  if (size == failResponseSize) {
    const RtcpRetransmitResponseFailPayload *failPayload =
        reinterpret_cast<const RtcpRetransmitResponseFailPayload *>(
            data + sizeof(RtcpCommonHeader));
    uint16_t failedSeq = boost::endian::big_to_native(failPayload->seq);
    LOG_WARN("[{}] Received 'FUTILE' retransmit response for seq {}",
             label_.c_str(), failedSeq);
    {
      std::lock_guard<std::mutex> lock(stateMutex_);
      abortRetransmit(failedSeq, "FUTILE");
      ++retransmitFutileCount_;
    }
  } else if (size >=
             kRTPHeaderSize + sizeof(RtcpCommonHeader)) { // Contains RTP packet
    const uint8_t *rtpData = data + sizeof(RtcpCommonHeader);
    size_t rtpSize = size - sizeof(RtcpCommonHeader);
    LOG_DEBUG("[{}] Received retransmitted RTP packet within RTCP response ({} "
              "bytes)",
              label_.c_str(), rtpSize);

    // --- RTT Calculation ---
    // We need the sequence number from the RTP header inside
    if (rtpSize >= kRTPHeaderSize) {
      const RtpHeader *innerRtp = reinterpret_cast<const RtpHeader *>(rtpData);
      uint16_t receivedSeq =
          boost::endian::big_to_native(innerRtp->sequenceNumber);
      uint64_t nowNanos = GetCurrentNanos();

      std::lock_guard<std::mutex> lock(
          stateMutex_); // Lock for RTT update and list access

      // Find the original request node
      AirTunesRetransmitNode *foundNode = nullptr;
      auto it =
          std::find_if(busyRetransmitList_.begin(), busyRetransmitList_.end(),
                       [receivedSeq](const AirTunesRetransmitNode *node) {
                         return node->seq == receivedSeq;
                       });
      if (it != busyRetransmitList_.end()) {
        foundNode = *it;
        // Calculate RTT if this was the first try
        if (foundNode->tries <= 1 && foundNode->sentNanos > 0) {
          int64_t rttNanos = nowNanos - foundNode->sentNanos;
          if (rttNanos < 0)
            rttNanos = 0;

          rtcpMinRttNanos_ = std::min(rtcpMinRttNanos_, rttNanos);
          rtcpMaxRttNanos_ = std::max(rtcpMaxRttNanos_, rttNanos);

          // Update RTO using Jacobson/Karels algorithm (RFC 6298)
          if (rtcpAvgRttNanos_ == 100'000'000 &&
              rtcpDevRttNanos_ == 0) { // First measurement
            rtcpAvgRttNanos_ = rttNanos;
            rtcpDevRttNanos_ = rttNanos / 2;
          } else {
            int64_t errNanos = rttNanos - rtcpAvgRttNanos_;
            rtcpAvgRttNanos_ += errNanos / 8; // alpha = 1/8
            rtcpDevRttNanos_ +=
                (std::abs(errNanos) - rtcpDevRttNanos_) / 4; // beta = 1/4
          }
          rtcpTimeoutNanos_ = rtcpAvgRttNanos_ + 4 * rtcpDevRttNanos_;
          rtcpTimeoutNanos_ =
              std::max(rtcpTimeoutNanos_, (int64_t)10'000'000); // Min 10ms RTO?
          rtcpTimeoutNanos_ = std::min(rtcpTimeoutNanos_,
                                       (int64_t)500'000'000); // Max 500ms RTO?

          LOG_DEBUG(
              "[{}] RTT Update: RTT={} ms, SRTT={} ms, RTTVAR={} ms, RTO={} ms",
              label_.c_str(), rttNanos / 1'000'000,
              rtcpAvgRttNanos_ / 1'000'000, rtcpDevRttNanos_ / 1'000'000,
              rtcpTimeoutNanos_ / 1'000'000);
        }
        // Update overall retransmit timing stats (same as before)
        uint64_t ageNanos = nowNanos - foundNode->startNanos;
        retransmitMinNanos_ = std::min(retransmitMinNanos_, ageNanos);
        retransmitMaxNanos_ = std::max(retransmitMaxNanos_, ageNanos);
        if (ageNanos > retransmitMinNanos_ && ageNanos < retransmitMaxNanos_) {
          retransmitAvgNanos_ = ((retransmitAvgNanos_ * 63) + ageNanos) / 64;
        }
        if (foundNode->tries > 1) {
          retransmitRetryMinNanos_ =
              std::min(retransmitRetryMinNanos_, ageNanos);
          retransmitRetryMaxNanos_ =
              std::max(retransmitRetryMaxNanos_, ageNanos);
        }

        // Remove the node (fulfilled)
        busyRetransmitList_.erase(it);
        releaseRetransmitNode(foundNode); // Adds back to free list
      } else {
        // We received a retransmit we didn't ask for or already
        // fulfilled/aborted
        LOG_WARN("[{}] Received unexpected retransmitted packet seq {} in RTCP "
                 "response.",
                 label_.c_str(), receivedSeq);
        ++retransmitNotFoundCount_;
      }
    } else {
      LOG_WARN(
          "[{}] Retransmit response RTP packet too small for header ({} bytes)",
          label_.c_str(), rtpSize);
      return; // Don't process invalid inner packet
    }

    // Process the inner RTP packet (outside the lock)
    // This will decrypt and push to delegate
    processRtpPacket(rtpData, rtpSize, true); // true = isRetransmit
    {
      std::lock_guard<std::mutex> lock(stateMutex_); // Lock for stats update
      ++retransmitReceiveCount_;
    }
  } else {
    LOG_WARN("[{}] Received malformed retransmit response packet (size {})",
             label_.c_str(), size);
  }
}

void APAudioStream::abortRetransmit(uint16_t seq, const char *reason) {
  auto it = std::find_if(
      busyRetransmitList_.begin(), busyRetransmitList_.end(),
      [seq](const AirTunesRetransmitNode *node) { return node->seq == seq; });
  if (it != busyRetransmitList_.end()) {
    LOG_INFO("[{}] Aborting retransmit request for seq {} ({})", label_.c_str(),
             seq, reason);
    AirTunesRetransmitNode *node = *it;
    busyRetransmitList_.erase(it);
    releaseRetransmitNode(node);
  }
}

void APAudioStream::abortAllRetransmits(const char *reason) {
  // Assumes stateMutex_ is held
  if (!busyRetransmitList_.empty()) {
    LOG_INFO("[{}] Aborting all ({}) pending retransmit requests ({})",
             label_.c_str(), busyRetransmitList_.size(), reason);
    while (!busyRetransmitList_.empty()) {
      AirTunesRetransmitNode *node = busyRetransmitList_.front();
      busyRetransmitList_.pop_front();
      releaseRetransmitNode(node);
    }
  }
}

void APAudioStream::sendRtcpPacket(const uint8_t *data, size_t size) {
  boost::system::error_code ec;
  if (rtcpConnected_) {
    controlSocket_.async_send(
        boost::asio::buffer(data, size),
        [this](boost::system::error_code ec, std::size_t bytes_transferred) {
          if (ec) {
            LOG_ERROR("[{}] Failed to send RTCP packet: {}", label_.c_str(),
                      ec.message());
            if (ec == boost::asio::error::network_unreachable ||
                ec == boost::asio::error::host_unreachable ||
                ec == boost::asio::error::not_connected) {
              rtcpConnected_ = false;
            }
          } else {
            LOG_VERBOSE("[{}] Sent RTCP packet ({} bytes)", label_.c_str(),
                        bytes_transferred);
          }
        });
  } else {
    if (peerRtcpEndpoint_.port() == 0) {
      LOG_ERROR("[{}] Cannot send RTCP packet, peer endpoint not set.",
                label_.c_str());
      return;
    }
    controlSocket_.async_send_to(
        boost::asio::buffer(data, size), peerRtcpEndpoint_,
        [&](boost::system::error_code ec, std::size_t bytes_transferred) {
          if (ec) {
            LOG_ERROR("[{}] Failed to send RTCP packet: {}", label_.c_str(),
                      ec.message());
            if (ec == boost::asio::error::network_unreachable ||
                ec == boost::asio::error::host_unreachable ||
                ec == boost::asio::error::not_connected) {
              rtcpConnected_ = false;
            }
          } else {
            LOG_VERBOSE("[{}] Sent RTCP packet ({} bytes)", label_.c_str(),
                        bytes_transferred);
          }
        });
  }
}

// --- Timing & Rate ---

void APAudioStream::updateEstimatedRate(uint32_t sampleTime,
                                        uint64_t hostTimeNanos) {
  auto now = std::chrono::steady_clock::now();
  if (now >= rateUpdateNextTime_) {
    std::lock_guard<std::mutex> lock(zeroTimeMutex_); // Protect zeroTime_

    APTimestampTuple newSample;
    auto syncTime =
        timeSynchronizer_->getSynchronizedTimeNearTicks(hostTimeNanos);

    newSample.hostTime = syncTime.toNtpTimestamp();
    newSample.hostTimeRaw = hostTimeNanos;
    newSample.sampleTime = sampleTime;

    zeroTime_ = newSample; // Update the latest timestamp info

    rateUpdateSamples_.push_back(newSample);
    rateUpdateCount_++;

    if (rateUpdateSamples_.full() ||
        rateUpdateCount_ >= 8) { // Need enough samples
      const APTimestampTuple &oldSample =
          rateUpdateSamples_.front(); // Oldest sample in buffer

      // Calculate rate based on NTP time difference
      double hostTimeDiff =
          static_cast<double>(newSample.hostTime - oldSample.hostTime) /
          (1ULL << 32);           // NTP diff in seconds
      if (hostTimeDiff > 0.001) { // Avoid division by zero or tiny intervals
        double sampleDiff = static_cast<double>(
            Mod32_Diff(newSample.sampleTime, oldSample.sampleTime));
        double rate = sampleDiff / hostTimeDiff;

        // Update moving average
        if (rateAvg_ == 0.0) {
          rateAvg_ = rate;
        } else {
          rateAvg_ = 0.125 * rate + 0.875 * rateAvg_;
        }
        LOG_DEBUG("Estimated sample rate: {} Hz (Avg: {} Hz) for sampleTime {} "
                  "and hostTimeNanos {} (syncTime {})",
                  rate, rateAvg_, newSample.sampleTime, newSample.hostTimeRaw,
                  syncTime.toNtpTimestamp());
      }
    }
    rateUpdateNextTime_ = now + rateUpdateInterval_;
  }
}

// --- Flush ---

void APAudioStream::flush(uint32_t flushUntilTS, uint16_t flushUntilSeq) {
  LOG_INFO("[{}] Flushing audio stream: UntilTS={}, UntilSeq={}",
           label_.c_str(), flushUntilTS, flushUntilSeq);

  { // Lock state for modifying flush state, sequence numbers, retransmits
    std::lock_guard<std::mutex> lock(stateMutex_);

    flushing_ = true;
    flushUntilTs_ = flushUntilTS;
    // Calculate flush timeout
    flushTimeoutTs_ = flushUntilTS + (3 * descriptor.sr);

    // Reset sequence tracking state
    lastRtpSeqReceived_ =
        flushUntilSeq - 1; // Set last received to just before flush point
    lastRtpTsReceived_ =
        flushUntilTS - 1;       // Set last received TS just before flush point
    rtpDupsInitialized_ = true;
    rtpDupLastSeq_ = lastRtpSeqReceived_;
    std::fill(rtpDupWindow_.begin(), rtpDupWindow_.end(),
              rtpDupLastSeq_); // Clear dup window

    // Abort all pending retransmits
    abortAllRetransmits("FLUSH");

    // Reset stats related to buffering/loss counts
    lostPackets_ = 0;
    unrecoveredPackets_ = 0;
    latePackets_ = 0;
    maxBurstLoss_ = 0;
    bigLossCount_ = 0;

  } // Unlock stateMutex_

  // Notify the delegate AFTER updating internal state
  if (delegate_) {
    LOG_DEBUG("[{}] Notifying delegate of flush request.", label_.c_str());
    delegate_->onFlushRequested(flushUntilTS, flushUntilSeq);
  }

  LOG_INFO("[{}] Flush operation complete.", label_.c_str());
}

} // namespace Stream
} // namespace Session
} // namespace AirPlay