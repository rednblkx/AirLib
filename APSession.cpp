#include "APSession.hpp"
#include "APAudioCommon.hpp"
#include "APServer.hpp"
#include "APSessionScreen.hpp"
#include "APUtils.hpp"
#include "keepAliveManager.hpp"
#include "logger.hpp"
#include <boost/any.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <cstdint>
#include <exception>
#include <format>
#include <map>
#include <plistcpp/Plist.hpp>
#include <string>
#include <thread>

namespace AirPlay {
namespace Session {
APSession::APSession(Server::APServer *server,
                     Plist::dictionary_type &controlDict,
                     boost::asio::ip::address peerAddress, bool isCarPlay)
    : server(server), peerAddress(peerAddress) {
  try {
    deviceID = boost::any_cast<std::string>(controlDict["deviceID"]);
    deviceName = boost::any_cast<std::string>(controlDict["name"]);
    sourceVersion = boost::any_cast<std::string>(controlDict["sourceVersion"]);
    sessionUUID = boost::any_cast<std::string>(controlDict["sessionUUID"]);
    deviceMacAddress = boost::any_cast<std::string>(controlDict["macAddress"]);
    deviceTimingPort = boost::any_cast<int64_t>(controlDict["timingPort"]);
    if(isCarPlay)
      keepAliveSupported = boost::any_cast<bool>(controlDict["keepAliveLowPower"]);
    localTimingPort = -1;
    localKeepAlivePort = -1;
    localEventPort = -1;

    LOG_INFO("Session created for device {} ({})", deviceName, deviceID);
  } catch (const std::exception &e) {
    LOG_ERROR("Error creating session: {}", e.what());
    throw;
  }
}

APSession::~APSession() {
  LOG_INFO("Destroying session...");
  stop();
  LOG_INFO("Session destroyed.");
}


void APSession::stop() {
  // Use atomic flag to ensure stop logic runs only once
  if (stopped_.exchange(true)) {
    return;
  }
  LOG_INFO("Stopping session components...");

  // Stop network services (cancel async ops, close sockets)
  if (timeSynchronizer)
    timeSynchronizer->stop();
  if (keepAliveManager)
    keepAliveManager->stop();
  if (eventConnection)
    eventConnection->stop();
  if (m_screen_session)
    m_screen_session->stopSession();

  // Stop io_contexts (allows run() methods to return)
  timingCtx.stop();
  keepAliveCtx.stop();
  eventCtx.stop();
  screenCtx.stop();

  // Join threads
  LOG_INFO("Joining threads...");
  if (timingThread.joinable())
    timingThread.join();
  if (keepAliveThread.joinable())
    keepAliveThread.join();
  if (eventThread.joinable())
    eventThread.join();
  if (screenThread.joinable())
    screenThread.join();
  LOG_INFO("Threads joined.");
}

void APSession::setPairingSession(PairingSession *session) {
  verifySession = session;
}

void APSession::processTeardown(Plist::dictionary_type &requestPlist,
                                Plist::dictionary_type &responsePlist) {
  LOG_DEBUG("[{}] Processing TEARDOWN...", sessionUUID);
  auto streamsNode = requestPlist["streams"];
  if (streamsNode.type() == typeid(Plist::array_type)) {
    Plist::array_type streamArray =
        boost::any_cast<Plist::array_type>(streamsNode);
    for (auto &streamNode : streamArray) {
      if (streamNode.type() == typeid(Plist::dictionary_type)) {
        Plist::dictionary_type streamDict =
            boost::any_cast<Plist::dictionary_type>(streamNode);
        Plist::integer_type streamType = boost::any_cast<Plist::integer_type>(streamDict["type"]);
        if (streamType == 100) {
          LOG_INFO("[{}] Stopping main audio stream...", sessionUUID);
          // m_audio_stream->stop();
        } else if (streamType == 101) {
          LOG_INFO("[{}] Stopping alt audio stream...", sessionUUID);
          // m_audio_stream->stop();
        } else if (streamType == 102 || streamType == 96) {
          LOG_INFO("[{}] Stopping main high audio stream...", sessionUUID);
          m_audio_stream->stop();
          streamDelegate->onAudioStreamStopped(m_audio_stream);
          m_audio_stream.reset();
        } else if (streamType == 110) {
          LOG_INFO("[{}] Stopping screen stream...", sessionUUID);
          m_screen_session->stopSession();
          streamDelegate->onScreenStreamStopped(m_screen_session);
          m_screen_session.reset();
        }
      }
    }
    if (!m_audio_stream && !m_screen_session) {
      sessionIdle = true;
      if(keepAliveSupported && keepAliveManager) {
        keepAliveManager->initialize();
        keepAliveManager->start();
        if (!keepAliveThread.joinable()) {
          keepAliveThread = std::thread([this]() {
            LOG_DEBUG("KeepAlive context thread starting...");
            net::executor_work_guard<net::io_context::executor_type> work_guard(
                keepAliveCtx.get_executor());
            keepAliveCtx.run();
            LOG_DEBUG("KeepAlive context thread finished.");
          });
        }
      } else {
        LOG_INFO("[{}] Stopping session...", sessionUUID);
        stop();
      }
    }
  } else {
    LOG_WARN("[{}] No 'streams' array found in TEARDOWN request.", sessionUUID);
  }
}

void APSession::processFeedback(Plist::dictionary_type &requestPlist,
                                Plist::dictionary_type &responsePlist) {
  LOG_DEBUG("[{}] Processing FEEDBACK...", sessionUUID);
  // response streams array
  Plist::dictionary_type responseStreamDict;
  if (m_audio_stream) {
    responseStreamDict["timestamp"] = static_cast<int64_t>(m_audio_stream->getZeroTime().hostTime);
    responseStreamDict["timestampRawNs"] = static_cast<int64_t>(m_audio_stream->getZeroTime().hostTimeRaw);
    responseStreamDict["type"] = static_cast<int64_t>(102);
    responseStreamDict["sampleTime"] = static_cast<int64_t>(m_audio_stream->getZeroTime().sampleTime);
    responseStreamDict["sr"] = static_cast<Plist::real_type>(m_audio_stream->getRateAvg());
    responseStreamDict["streamConnectionID"] = static_cast<int64_t>(m_audio_stream->getConnectionID());
    responsePlist["streams"] = Plist::array_type{responseStreamDict};
  } else {
    LOG_DEBUG("[{}] No streams available for FEEDBACK", sessionUUID);
  }
}

void APSession::carPlaySetup(Plist::dictionary_type &requestPlist, Plist::dictionary_type &responsePlist){

}

void APSession::processSetup(Plist::dictionary_type &requestPlist,
                             Plist::dictionary_type &responsePlist) {
  LOG_DEBUG("[{}] Processing SETUP...", sessionUUID);
  if (!controlSetup) {
    setupControl(responsePlist);
  } else {
    LOG_DEBUG("[{}] Control already setup", sessionUUID);
  }
  try {
    auto streamsNode = requestPlist["streams"];
    if (streamsNode.type() == typeid(Plist::array_type)) {
      LOG_DEBUG("[{}] Processing streams array...", sessionUUID);
      Plist::array_type streamArray =
          boost::any_cast<Plist::array_type>(streamsNode);
      Plist::array_type resStreamsArray;
      for (auto &streamNode : streamArray) {
        if (streamNode.type() == typeid(Plist::dictionary_type)) {
          Plist::dictionary_type streamDict =
              boost::any_cast<Plist::dictionary_type>(streamNode);
            Utils::StreamType streamType = (Utils::StreamType)(boost::any_cast<Plist::integer_type>(streamDict["type"]));
  
          // Create a response dictionary for this stream
          Plist::dictionary_type responseStreamDict;
          responseStreamDict["type"] = (Plist::integer_type)streamType;
  
          if (streamType == Utils::StreamType::Screen) { // Screen Stream
            LOG_DEBUG("[{}] Screen stream found in SETUP", sessionUUID);
            sessionIdle = false; // Mark session as active
  
            if (!streamDelegate) {
              LOG_ERROR(
                  "[{}] Screen stream requested but no delegate provided!",
                  sessionUUID);
              continue; // Skip this stream
            }
            if (!timeSynchronizer) { // Check if timing is initialized
              LOG_ERROR("[{}] Screen stream requested but timing was not "
                        "initialized!",
                        sessionUUID);
              continue; // Skip this stream
            }
  
            if (m_screen_session) {
              LOG_WARN("[{}] Screen session already exists, ignoring duplicate "
                       "SETUP request for screen.",
                       sessionUUID);
              responseStreamDict["dataPort"] = static_cast<Plist::integer_type>(m_screen_session->getDataPort());
  
            } else {
              LOG_INFO("[{}] Initializing screen session...", sessionUUID);
              try {
                // Create Screen Session Manager
                m_screen_session = std::make_shared<Stream::APScreenSession>(
                    screenCtx, timeSynchronizer);
                LOG_INFO("[{}] Screen data acceptor listening on port {}",
                         sessionUUID, m_screen_session->getDataPort());
                responseStreamDict["dataPort"] =
                    static_cast<Plist::integer_type>(m_screen_session->getDataPort());
                // Configure Screen Session
                m_screen_session->setup(Stream::ScreenSessionConfig{boost::any_cast<int64_t>(streamDict["latencyMs"])});
                streamDelegate->onScreenStreamCreated(m_screen_session);
                std::vector<uint8_t> streamKeyRead;
                if (streamDict["streamConnectionID"].type() ==
                    typeid(Plist::integer_type)) {
                  uint64_t streamConnectionID = boost::any_cast<Plist::integer_type>(
                      streamDict["streamConnectionID"]);
                  LOG_DEBUG("[{}] Deriving stream key for streamConnectionID {}",
                           sessionUUID, streamConnectionID);
                  std::string streamKeySalt =
                      std::format("DataStream-Salt{}", streamConnectionID);
                  LOG_DEBUG("[{}] Stream key salt: {}", sessionUUID,
                           streamKeySalt);
                  if (verifySession) {
                    int err = verifySession->deriveKey(
                        std::string_view(streamKeySalt),
                        std::string_view(
                            "DataStream-Output-Encryption-Key",
                            sizeof("DataStream-Output-Encryption-Key") - 1),
                        32, streamKeyRead);
                    if (err != 0) {
                      LOG_ERROR("[{}] Failed to derive stream key: {}",
                                sessionUUID, err);
                      continue; // Skip this stream
                    }
                  } else {
                    LOG_ERROR("[{}] No pairing session provided!", sessionUUID);
                    continue; // Skip this stream
                  }
                } else {
                  LOG_ERROR("[{}] Screen stream requested but no "
                            "streamConnectionID found!",
                            sessionUUID);
                  continue; // Skip this stream
                }
                if (streamKeyRead.size() == 32) {
                  std::array<uint8_t, 32> streamKeyReadArray;
                  std::copy(streamKeyRead.begin(), streamKeyRead.end(),
                            streamKeyReadArray.begin());
                  m_screen_session->setChaChaSecurityKey(streamKeyReadArray);
                } else {
                  LOG_ERROR("[{}] Derived stream key is not 32 bytes! {}",
                            sessionUUID, streamKeyRead.size());
                  continue; // Skip this stream
                }
  
                // Start the screen session thread
                if (!screenThread.joinable()) {
                  screenThread = std::thread([this]() {
                    LOG_DEBUG("[{}] Screen context thread starting...",
                             sessionUUID);
                    auto work_guard = net::make_work_guard(screenCtx);
                    screenCtx.run();
                    LOG_DEBUG("[{}] Screen context thread finished.",
                             sessionUUID);
                  });
                }
                if(keepAliveSupported)
                  keepAliveManager->stop();
                timeSynchronizer->start();
                m_screen_session->startAccepting();
              } catch (const std::exception &e) {
                LOG_ERROR("[{}] Failed to initialize screen session: {}",
                          sessionUUID, e.what());
                m_screen_session.reset();
                // Don't add screen stream to response if setup failed
                continue;
              }
            }
          } else if (streamType == Utils::StreamType::CPMainHighAudio || streamType == Utils::StreamType::CPMainAudio || streamType == Utils::StreamType::CPAltAudio || streamType == Utils::StreamType::APAudio) { // Main High Audio Stream
            LOG_INFO("[{}] Audio stream found in SETUP", sessionUUID);
            sessionIdle = false;
            std::vector<uint8_t> streamKeyRead;
            if (streamDict["streamConnectionID"].type() == typeid(Plist::integer_type) || streamDict["supportsDynamicStreamID"].type() == typeid(Plist::boolean_type)) {
              uint64_t streamConnectionID;
              if(streamDict["streamConnectionID"].type() == typeid(Plist::integer_type) ){
                streamConnectionID = boost::any_cast<Plist::integer_type>(streamDict["streamConnectionID"]);
              }
              LOG_DEBUG("[{}] Deriving stream key for streamConnectionID {}",
                       sessionUUID, streamConnectionID || "N/A");
              std::string streamKeySalt =
                  std::format("DataStream-Salt{}", streamConnectionID);
              LOG_DEBUG("[{}] Stream key salt: {}", sessionUUID, streamKeySalt);
              if (verifySession) {
                int err = verifySession->deriveKey(
                    std::string_view(streamKeySalt),
                    std::string_view(
                        "DataStream-Output-Encryption-Key",
                        sizeof("DataStream-Output-Encryption-Key") - 1),
                    32, streamKeyRead);
                if (err != 0) {
                  LOG_ERROR("[{}] Failed to derive stream key: {}", sessionUUID,
                            err);
                  continue; // Skip this stream
                }
              } else {
                LOG_ERROR("[{}] No pairing session provided!", sessionUUID);
                continue; // Skip this stream
              }
              m_audio_stream = std::make_shared<Stream::APAudioStream>(audioCtx, timeSynchronizer.get());
              m_audio_stream->setDecryptionKey(streamKeyRead.data(), streamKeyRead.size());
              streamDelegate->onAudioStreamCreated(m_audio_stream);
              if (!m_audio_stream->setup(streamType, peerAddress, streamDict, responseStreamDict)) {
                  LOG_ERROR("Failed to setup AudioStreamContext");
                  continue;
              }
            } else {
              LOG_ERROR("[{}] Stream requested but no "
                        "streamConnectionID found!",
                        sessionUUID);
              continue; // Skip this stream
            }
            if (!audioThread.joinable()) {
              audioThread = std::thread([this]() {
                LOG_DEBUG("[{}] Audio context thread starting...", sessionUUID);
                auto work_guard = net::make_work_guard(audioCtx);
                audioCtx.run();
                LOG_DEBUG("[{}] Audio context thread finished.", sessionUUID);
              });
            }
            if(m_audio_stream->start()) {
              streamDelegate->onAudioStreamStarted(m_audio_stream);
            }
          } else {
            LOG_WARN("[{}] Unsupported stream type {} found", sessionUUID,
                     (int)streamType);
            // Add minimal info to response
          }
          // Add the response dict for this stream to the response array
          resStreamsArray.push_back(responseStreamDict);
        }
      }
  
      // Add the streams array to the main response plist
      if (resStreamsArray.size() > 0) {
        responsePlist["streams"] = resStreamsArray;
      }
  
    } else {
      LOG_WARN("[{}] No 'streams' array found in SETUP request.", sessionUUID);
    }
  } catch (const std::exception &e) {
    LOG_ERROR("[{}] Failed to process SETUP: {}", sessionUUID, e.what());
  }
}

void APSession::processRecord() {
  LOG_DEBUG("[{}] Processing RECORD...", sessionUUID);
  if (!sessionIdle) {
    LOG_ERROR("[{}] Session is not idle", sessionUUID);
    return;
  }
  if(isCarPlay){
    net::post(eventCtx, [conn = eventConnection]() { conn->start(); });
    if (!eventThread.joinable()) {
      eventThread = std::thread([this]() {
        LOG_DEBUG("Event context thread starting...");
        net::executor_work_guard<net::io_context::executor_type> work_guard(
            eventCtx.get_executor());
        eventCtx.run();
        LOG_DEBUG("Event context thread finished.");
      });
    }
  }
}

void APSession::processCommand(
    Plist::dictionary_type &requestPlist,
    Plist::dictionary_type &responsePlist) {
  LOG_DEBUG("Processing COMMAND...");
  if(requestPlist["type"].type() == typeid(std::string)) {
    std::string type = boost::any_cast<std::string>(requestPlist["type"]);
    if(type == "modesChanged") {
      auto paramsNode = requestPlist["params"];
      if(paramsNode.type() == typeid(Plist::dictionary_type)) {
        auto params = boost::any_cast<Plist::dictionary_type>(paramsNode);
        CPModes modesChanged;
        auto appStatesNode = params["appStates"];
        if(appStatesNode.type() == typeid(Plist::array_type)) {
          Plist::array_type appStatesArray = boost::any_cast<Plist::array_type>(appStatesNode);
          for(auto &appStateNode : appStatesArray) {
            if(appStateNode.type() == typeid(Plist::dictionary_type)) {
              Plist::dictionary_type appStateDict = boost::any_cast<Plist::dictionary_type>(appStateNode);
              CPModes::AppState appState;
              appState.appStateID = static_cast<CPModes::AppStateID>(boost::any_cast<int64_t>(appStateDict["appStateID"]));
              appState.entity = static_cast<CPModes::Entity>(boost::any_cast<int64_t>(appStateDict["entity"]));
              if(appStateDict["speechMode"].type() == typeid(int64_t)) {
                appState.speechMode = static_cast<CPModes::SpeechMode>(boost::any_cast<int64_t>(appStateDict["speechMode"]));
              }
              modesChanged.appStates.push_back(appState);
            }
          }
        }
        auto resourcesNode = params["resources"];
        if(resourcesNode.type() == typeid(Plist::array_type)) {
          Plist::array_type resourcesArray = boost::any_cast<Plist::array_type>(resourcesNode);
          for(auto &resourceNode : resourcesArray) {
            if(resourceNode.type() == typeid(Plist::dictionary_type)) {
              Plist::dictionary_type resourceDict = boost::any_cast<Plist::dictionary_type>(resourceNode);
              CPModes::Resource resource;
              resource.entity = static_cast<CPModes::Entity>(boost::any_cast<int64_t>(resourceDict["entity"]));
              resource.permanentEntity = static_cast<CPModes::Entity>(boost::any_cast<int64_t>(resourceDict["permanentEntity"]));
              resource.resourceID = static_cast<CPModes::ResourceID>(boost::any_cast<int64_t>(resourceDict["resourceID"]));
              modesChanged.resources.push_back(resource);
            }
            }
        }
        previousCPmodes = currentCPmodes;
        currentCPmodes = modesChanged;
        if(commandsDelegate)
          commandsDelegate->onModesChanged(previousCPmodes,modesChanged);
      }
    } else if (type == "disableBluetooth") {
      auto paramsNode = requestPlist["params"];
      if(paramsNode.type() == typeid(Plist::dictionary_type)){
        auto params = boost::any_cast<Plist::dictionary_type>(paramsNode);
        if(params["deviceID"].type() == typeid(Plist::string_type)){
          if(commandsDelegate)
            commandsDelegate->onDisableBluetoothReq(boost::any_cast<Plist::string_type>(params["deviceID"]));
        }
      }
    } else if (type == "requestUI"){
      if(commandsDelegate)
        commandsDelegate->onRequestUI();
    } else if (type == "performHapticFeedback"){
      try {
        auto paramsNode = requestPlist["params"];
        if(paramsNode.type() == typeid(Plist::dictionary_type)){
          auto params = boost::any_cast<Plist::dictionary_type>(paramsNode);
          if(params["uuid"].type() == typeid(Plist::string_type)){
            if(commandsDelegate)
              commandsDelegate->onHapticFeedback(boost::any_cast<Plist::string_type>(params["uuid"]));
          }
        }
      } catch (std::exception &e) {
        LOG_ERROR("An exception occured: {}", e.what());
      }
    }
  }
}

void APSession::initializeTiming(
    Plist::dictionary_type &responsePlist) {
  timeSynchronizer = std::make_shared<APTimeSync>(
      timingCtx, peerAddress, deviceTimingPort);
  localTimingPort = timeSynchronizer->getLocalPort();
  responsePlist["timingPort"] = static_cast<int64_t>(localTimingPort);
  if (!timingThread.joinable()) {
    timingThread = std::thread([this]() {
      LOG_DEBUG("Timing context thread starting...");
      auto workGuard = boost::asio::make_work_guard(timingCtx);
      timingCtx.run();
      LOG_DEBUG("Timing context thread finished.");
    });
  }
}

void APSession::initializeKeepAlive(
    Plist::dictionary_type &responsePlist) {
  keepAliveManager = std::make_shared<KeepAliveManager>(
      keepAliveCtx, udp::endpoint(boost::asio::ip::address_v4::any(), 0),
      [this]() {
        LOG_INFO("KeepAlive Session died");
        this->stop();
      });
  keepAliveManager->initialize();
  localKeepAlivePort = keepAliveManager->get_local_port();
  responsePlist["keepAlivePort"] = static_cast<int64_t>(localKeepAlivePort);
  keepAliveManager->start();
  if (!keepAliveThread.joinable()) {
    keepAliveThread = std::thread([this]() {
      LOG_DEBUG("KeepAlive context thread starting...");
      net::executor_work_guard<net::io_context::executor_type> work_guard(
          keepAliveCtx.get_executor());
      keepAliveCtx.run();
      LOG_DEBUG("KeepAlive context thread finished.");
    });
  }
}

void APSession::initializeEventConnection(
    Plist::dictionary_type &responsePlist) {
  LOG_INFO("Initializing event connection...");
  eventConnection = std::make_shared<EventConnectionBoost>(eventCtx);
  eventConnection->configure_encryption(verifySession);
  localEventPort = eventConnection->get_local_port();
  if (localEventPort == 0) { // Check for error (port 0 is invalid)
    throw std::runtime_error("Failed to initialize Event Connection Port");
  }
  LOG_INFO("Event Connection Initialized. Local Port: {}", localEventPort);
  responsePlist["eventPort"] = static_cast<int64_t>(localEventPort);
}

// Method to send a command from the session
void APSession::sendEventCommand(
    const std::vector<char> &plist_data) {
  if (eventConnection && !currentCPmodes.resources.empty()) {
    for (auto r : currentCPmodes.resources) {
      if(r.resourceID == CPModes::ResourceID::SCREEN && r.entity != CPModes::Entity::CONTROLLER){LOG_WARN("Screen not owned by the Controller, can't send HID Report"); return;}
    }
    LOG_DEBUG("APSession [{}] Sending event command...", sessionUUID);
    eventConnection->send_command_async(plist_data);
  } else {
    LOG_ERROR("APSession [{}] Cannot send command, event connection not active.", sessionUUID);
  }
}

void APSession::setupControl(Plist::dictionary_type &responsePlist) {
  LOG_DEBUG("Setting up control ports...");
  try {
    initializeTiming(responsePlist);
    if (keepAliveSupported) {
      initializeKeepAlive(responsePlist);
    }
    if(isCarPlay)
      initializeEventConnection(responsePlist);
    else
      responsePlist["eventPort"] = (int64_t)0;
    controlSetup = true;
    LOG_DEBUG("Control setup complete.");
  } catch (const std::exception &e) {
    LOG_ERROR("Error setting up control: {}", e.what());
    throw; // Rethrow for caller to handle
  }
}
} // namespace Session
} // namespace AirPlay
