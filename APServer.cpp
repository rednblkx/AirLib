#include "APServer.hpp"
#include "APSession.hpp"
#include "APUtils.hpp"
#include "MFiSAP.hpp"
#include "PairingUtils.hpp"
#include "RTSPMessage.hpp"
#include "dnssd.hpp"
#include "logger.hpp"
#include <boost/endian/conversion.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <openssl/err.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <string>
#include <vector>
#include <plistcpp/Plist.hpp>

namespace AirPlay {
namespace Server {
APServer::APServer(std::string name, boost::asio::ip::address address, uint16_t port) {
  // Initialize the server
  this->accName = name;
  this->port = port;
  server =
      std::make_shared<RTSPServer>(ioc, tcp::endpoint{address, port}, *this);
  server->setServerContext(this);
  deviceID = Utils::getPrimaryMacAddress();
  // log_thread = std::thread([this]() {auto work_guard = boost::asio::make_work_guard(log_ioc); log_ioc.run(); });
  // Logger::getInstance().init(log_ioc);
  // Logger::getInstance().setLevel(LogLevel::DEBUG);
  CPModes modes;
  CPModes::AppState defaultCallState = CPModes::AppState{CPModes::AppStateID::CALL, CPModes::Entity::NONE, CPModes::SpeechMode::NONE, false };
  CPModes::AppState defaultSpeechState = CPModes::AppState{CPModes::AppStateID::SPEECH, CPModes::Entity::NONE, CPModes::SpeechMode::NONE, false };
  CPModes::AppState defaultTurnState = CPModes::AppState{CPModes::AppStateID::TURN_BY_TURN, CPModes::Entity::NONE, CPModes::SpeechMode::NONE, false };
  modes.appStates = std::vector<CPModes::AppState>{defaultCallState, defaultSpeechState, defaultTurnState};
  CPModes::Resource defaultScreenOwnership = CPModes::Resource{CPModes::Entity::CONTROLLER, CPModes::Entity::CONTROLLER, CPModes::ResourceID::SCREEN, CPModes::TransferType::TAKE, CPModes::TransferPriority::NICE_TO_HAVE, CPModes::ResourceConstraint::ANYTIME, CPModes::ResourceConstraint::ANYTIME, CPModes::ResourceConstraint::ANYTIME};
  CPModes::Resource defaultAudioOwnership = CPModes::Resource{CPModes::Entity::CONTROLLER, CPModes::Entity::CONTROLLER, CPModes::ResourceID::AUDIO, CPModes::TransferType::TAKE, CPModes::TransferPriority::NICE_TO_HAVE, CPModes::ResourceConstraint::ANYTIME, CPModes::ResourceConstraint::ANYTIME, CPModes::ResourceConstraint::ANYTIME};
  modes.resources = std::vector<CPModes::Resource>{defaultScreenOwnership, defaultAudioOwnership};
  initialCPmodes = modes;
  LOG_INFO("APServer initialized");
}

APServer::~APServer() {
    stopServers();
  // Stop the server
  // log_ioc.stop();
  // log_thread.join();
}

void APServer::setSessionDelegate(Session::APSessionDelegate* delegate) {
  sessionDelegate = delegate;
}

void APServer::initializeServer(RTSPServer *server) {
  // Initialize the server
  LOG_INFO("Initializing server");
}

void APServer::finalizeServer(RTSPServer *server) {
  // Finalize the server
  LOG_INFO("Finalizing server");
}
void APServer::startServers() {
    startBonjour();
  if(carplayEnabled)
    airDNS->startBrowse();
  server->run();
  ioc.run();
}

void APServer::stopServers() {
    stopBonjour();
    // Stop the server
    for (auto &session : sessions) {
      session.second->stop();
      sessions.erase(session.first);
    }
    LOG_INFO("Sessions count: {}", sessions.size());
    server->stop();
    ioc.stop();
}

void APServer::startBonjour() {
    PairingDelegate d;
    const char *configPath = std::getenv("CONFIG_FOLDER_PATH");
    PairingSession s(d, PairingSession::SessionType::SetupServer, configPath ? configPath : "");
    AirFeatures1 features1 {.bytes =
    AirFeatures1::Photo |
    AirFeatures1::Slideshow |
    AirFeatures1::Unknown1 |
    AirFeatures1::Screen |
    AirFeatures1::Audio |
    AirFeatures1::Unknown2 |
    AirFeatures1::AudioRedundant |
    AirFeatures1::PhotoCaching |
    AirFeatures1::MetadataFeatureText |
    AirFeatures1::MetadataFeatureArtwork |
    AirFeatures1::MetadataFeatureProgress |
    AirFeatures1::AudioAAC_LC |
    AirFeatures1::Unknown3 |
    AirFeatures1::Unknown4 |
    AirFeatures1::AudioAES_128_SAPv1 |
    AirFeatures1::UnifiedServices
    };
    AirFeatures2 features2;
    if(carplayEnabled){
        features2.bytes = AirFeatures2::isCarplay | AirFeatures2::carPlayControl | AirFeatures2::CoreUtilsPairingAndEncryption;
    } else {
        features2.bytes = AirFeatures2::CoreUtilsPairingAndEncryption | AirFeatures2::hkPairingAndAccessControl;
    }
    airDNS = std::make_unique<AirDNS>(accName, deviceID.data(), port, features1, features2);
    airDNS->registerAP(s.loadIdentity()->identifier, s.loadIdentity()->publicKey);
}

void APServer::stopBonjour(){
    airDNS->stop();
    airDNS = nullptr;
}

std::vector<char>
APServer::decryptMessage(const std::vector<char> &encrypted_data,
                         std::any connection_context,
                         boost::system::error_code &ec) {
  LOG_DEBUG("---------------BEGIN READ & DECRYPTION---------------\n");
  ec.clear(); // Start with no error
  TransportContext *transportContext = nullptr;
  try {
    // Safely get the context for this connection
    auto ctx_ptr = std::any_cast<TransportContext *>(connection_context);
    transportContext = ctx_ptr;
  } catch (const std::bad_any_cast &e) {
    LOG_ERROR("Failed to cast connection context to TransportContext*: {}",
              e.what());
    ec = boost::system::errc::make_error_code(
        boost::system::errc::invalid_argument);
    return {};
  }
  if (!transportContext) {
    LOG_ERROR("TransportContext is null during decryption.");
    ec = boost::system::errc::make_error_code(
        boost::system::errc::invalid_argument);
    return {};
  }

  if (encrypted_data.size() < (2 + 16)) { // Header + Tag
    LOG_ERROR("Encrypted data too short.");
    ec =
        boost::system::errc::make_error_code(boost::system::errc::message_size);
    return {};
  }

  // Extract header (AAD) and payload
  uint8_t header[2];
  header[0] = encrypted_data[0];
  header[1] = encrypted_data[1];
  size_t expected_plaintext_length = boost::endian::load_little_u16(header);
  const uint8_t *encrypted_payload_ptr =
      reinterpret_cast<const uint8_t *>(encrypted_data.data() + 2);
  size_t encrypted_payload_size = encrypted_data.size() - 2;

  LOG_DEBUG("Header: {:02x}{:02x}", header[0], header[1]);
  LOG_DEBUG("Encrypted Payload Size: {}", encrypted_payload_size);
  LOG_DEBUG("Expected Plaintext Size: {}", expected_plaintext_length);

  std::vector<uint8_t> decryptedPayload(expected_plaintext_length);
  int err = crypto_aead_chacha20poly1305_ietf_decrypt(
      decryptedPayload.data(), NULL, NULL, encrypted_payload_ptr,
      encrypted_payload_size, // Pass only payload+tag
      header, 2,              // Pass header as AAD
      transportContext
          ->outputNonce, // Use OUTPUT nonce for DECRYPTING data FROM client
      transportContext->outputKey
          .data()); // Use OUTPUT key for DECRYPTING data FROM client

  if (err != 0) {
    LOG_ERROR("Decryption failed (crypto_aead_chacha20poly1305_ietf_decrypt "
              "returned {})",
              err);
    ERR_print_errors_fp(stderr); // Print OpenSSL errors if any
    ec = boost::system::errc::make_error_code(
        boost::system::errc::illegal_byte_sequence); // Or similar
    return {};
  }

  LOG_VERBOSE("Decrypted payload({:d}): \n{:x}", decryptedPayload.size(),
            decryptedPayload);

  // Increment the NONCE used for this operation
  transportContext->outputNonce[4]++;
  if (transportContext->outputNonce[4] == 0)
    transportContext->outputNonce[5]++;

  LOG_DEBUG("---------------END READ & DECRYPTION---------------\n");
  return std::vector<char>(decryptedPayload.begin(), decryptedPayload.end());
}

std::vector<char>
APServer::encryptMessage(const std::vector<char> &plaintext_payload,
                         std::any connection_context,
                         boost::system::error_code &ec) {
  LOG_DEBUG("---------------BEGIN WRITE & ENCRYPTION---------------\n");
  ec.clear();
  TransportContext *transportContext = nullptr;
  try {
    auto ctx_ptr = std::any_cast<TransportContext *>(connection_context);
    transportContext = ctx_ptr;
  } catch (const std::bad_any_cast &e) {
    LOG_ERROR("Failed to cast connection context to TransportContext*: {}",
              e.what());
    ec = boost::system::errc::make_error_code(
        boost::system::errc::invalid_argument);
    return {};
  }
  if (!transportContext) {
    LOG_ERROR("TransportContext is null during encryption.");
    ec = boost::system::errc::make_error_code(
        boost::system::errc::invalid_argument);
    return {};
  }

  if (plaintext_payload.size() > 0xFFFF) { // Check size limit for header
    LOG_ERROR("Plaintext payload too large for 16-bit length header.");
    ec = boost::system::errc::make_error_code(
        boost::system::errc::value_too_large);
    return {};
  }

  uint8_t header[2];
  boost::endian::store_little_u16(header, plaintext_payload.size());
  LOG_DEBUG("Header: {:02x}{:02x}", header[0], header[1]);

  std::vector<uint8_t> encryptedResponse(plaintext_payload.size() +
                                         16);   // Space for tag
  unsigned long long encrypted_len_written = 0; // Needed by libsodium

  int err = crypto_aead_chacha20poly1305_ietf_encrypt(
      encryptedResponse.data(), &encrypted_len_written,
      reinterpret_cast<const uint8_t *>(plaintext_payload.data()),
      plaintext_payload.size(), header, 2, // Pass header as AAD
      NULL,                                // nsec is not used
      transportContext
          ->inputNonce, // Use INPUT nonce for ENCRYPTING data TO client
      transportContext->inputKey
          .data()); // Use INPUT key for ENCRYPTING data TO client

  if (err != 0) {
    LOG_ERROR("Encryption failed (crypto_aead_chacha20poly1305_ietf_encrypt "
              "returned {})",
              err);
    ERR_print_errors_fp(stderr);
    ec = boost::system::errc::make_error_code(
        boost::system::errc::permission_denied); // Or similar
    return {};
  }

  // Ensure the length written matches expected size
  if (encrypted_len_written != encryptedResponse.size()) {
    LOG_ERROR("Error: Encrypted length mismatch. Expected {}, got {}",
              encryptedResponse.size(), encrypted_len_written);
    ec = boost::system::errc::make_error_code(
        boost::system::errc::protocol_error);
    return {};
  }

  // Increment the NONCE used for this operation
  transportContext->inputNonce[4]++;
  if (transportContext->inputNonce[4] == 0)
    transportContext->inputNonce[5]++;

  // Prepend the header to the encrypted data + tag
  std::vector<char> final_message;
  final_message.reserve(2 + encryptedResponse.size());
  final_message.insert(final_message.end(), header, header + 2);
  final_message.insert(final_message.end(), encryptedResponse.begin(),
                       encryptedResponse.end());

  LOG_VERBOSE("Encrypted response ({}): \n{}", final_message.size(),
            final_message);
  LOG_DEBUG("---------------END WRITE & ENCRYPTION---------------\n");
  return final_message;
}

void APServer::handleConnection(std::shared_ptr<RTSPConnection> connection,
                                std::any /*server_context*/) {
  LOG_INFO("Handling connection from {}",
           connection->socket().remote_endpoint().address().to_string());
}

void APServer::handleConnectionClosed(std::shared_ptr<RTSPConnection> connection,
                                const boost::system::error_code &ec) {
  LOG_INFO("Connection closed notification. Reason: {}", ec.message());
  auto context = connection->getConnectionContext();
  if (context.has_value()) {
    try {
      auto session = std::any_cast<std::shared_ptr<Session::APSession>>(context);
      if (session) {
        LOG_DEBUG("Shared pointer to APSession ownership count: {}", session.use_count());
        LOG_DEBUG("Session ID: {}", session->getSessionID());
        LOG_DEBUG("Sessions size: {}", sessions.size());
        if (sessions.find(session->getSessionID()) != sessions.end()) {
          sessions.erase(session->getSessionID());
        }
        session.reset();
        pairingVerified = false;
        setupOccurred = false;
        pairingVerifySession = nullptr;
      }
    } catch (const std::exception& e) {
      LOG_ERROR("Error casting connection context to APSession*: {}", e.what());
    }
  }
  // Clean up context, etc.
}

void APServer::handleWriteComplete(std::shared_ptr<RTSPConnection> connection,
                             std::any connection_context,
                             const boost::system::error_code &ec) {
  if (ec) {
    LOG_ERROR("Write failed for connection {}: {}",
              connection->socket().remote_endpoint().address().to_string(),
              ec.message());
  } else {
    LOG_VERBOSE("Write complete for connection {}",
              connection->socket().remote_endpoint().address().to_string());
  }
}

void APServer::configureTransport(std::shared_ptr<RTSPConnection> connection) {
  LOG_INFO("Configuring transport for connection {}",
           connection->socket().remote_endpoint().address().to_string());
  // Create context ONCE per successful pair-verify
  TransportContext *transportCtx = new TransportContext; // Use unique_ptr

  // Derive keys (ensure pairingVerifySession is valid here before reset)
  if (!pairingVerifySession) {
    LOG_ERROR("Error: pairingVerifySession is null during configureTransport!");
    return; // Or throw
  }
  pairingVerifySession->deriveKey("Control-Salt", "Control-Read-Encryption-Key",
                                  32, transportCtx->inputKey);
  pairingVerifySession->deriveKey("Control-Salt",
                                  "Control-Write-Encryption-Key", 32,
                                  transportCtx->outputKey);
  // Initialize nonces
  memset(transportCtx->inputNonce, 0, sizeof(transportCtx->inputNonce));
  memset(transportCtx->outputNonce, 0, sizeof(transportCtx->outputNonce));

  // Store the context IN THE CONNECTION using std::any
  connection->setEncryptionContext(transportCtx); // Move ownership

  // Tell the connection to use this APServer instance for encryption
  connection->enableEncryption(*this, true);
}

void APServer::handlePairSetup(const RTSPMessage &request,
                               RTSPMessage &response,
                               std::shared_ptr<RTSPConnection> connection) {
  LOG_INFO("Pairing setup received");
  PairingDelegate delegate;
  try {
    if (!pairingSetupSession) { // Use unique_ptr check
      const char *configPath = std::getenv("CONFIG_FOLDER_PATH");
      pairingSetupSession = std::make_unique<PairingSession>(
          delegate, PairingSession::SessionType::SetupServer, configPath ? configPath : "");
    }
    pairingSetupSession->setSetupCode("3939");
    auto [responseData, done] = pairingSetupSession->exchange(
        std::vector<uint8_t>(request.payload.begin(), request.payload.end()));
    response.method = request.method;
    response.uri = request.uri;
    response.headers = std::map<std::string, std::string>{
        {"Content-Type", "application/x-apple-binary-plist"},
        {"Server", "AirTunes/320.17"}};
    response.cseq = request.cseq;
    response.payload.insert(response.payload.end(), responseData.begin(),
                            responseData.end());
    response.headers["Content-Length"] = std::to_string(response.payload.size());
    response.print();
    if (done) {
      LOG_INFO("Pairing setup done");
      pairingSetupSession.reset();
    } else {
      LOG_INFO("Pairing setup not done");
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Pairing setup failed: {}", e.what());
    if (pairingSetupSession) {
      pairingSetupSession.reset();
    }
  }
}

void APServer::handlePairVerify(const RTSPMessage &request,
                                RTSPMessage &response,
                                std::shared_ptr<RTSPConnection> connection) {
  LOG_INFO("Pairing verify received");
  PairingDelegate delegate;
  try {
    if (!pairingVerifySession) {
      const char *configPath = std::getenv("CONFIG_FOLDER_PATH");
      pairingVerifySession = std::make_unique<PairingSession>(
          delegate, PairingSession::SessionType::VerifyServer, configPath ? configPath : "");
    }
    pairingVerifySession->setSetupCode("3939");
    auto [responseData, done] = pairingVerifySession->exchange(
        std::vector<uint8_t>(request.payload.begin(), request.payload.end()));
    response.method = request.method;
    response.uri = request.uri;
    response.headers = std::map<std::string, std::string>{
        {"Content-Type", "application/x-apple-binary-plist"},
        {"Server", "AirTunes/320.17"}};
    response.cseq = request.cseq;
    response.payload.insert(response.payload.end(), responseData.begin(),
                            responseData.end());
    response.headers["Content-Length"] = std::to_string(response.payload.size());
    response.print();
    if (done) {
      LOG_INFO("Pairing verify done");
      // if(carplayEnabled)
      configureTransport(connection);
      pairingVerified = true;
    } else {
      LOG_INFO("Pairing verify not done");
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Pairing verify failed: {}", e.what());
  }
}

void APServer::handleAuthSetup(const RTSPMessage &request,
                               RTSPMessage &response,
                               std::shared_ptr<RTSPConnection> connection) {
  LOG_INFO("Auth setup received");
  MFiSAP mfiSAP;
  std::vector<uint8_t> responseData;
  std::vector<uint8_t> payload(request.payload.begin(), request.payload.end());
  mfiSAP.exchange(payload, responseData);
  response.method = request.method;
  response.uri = request.uri;
  response.headers = std::map<std::string, std::string>{
      {"Content-Type", "application/octet-stream"},
      {"Server", "AirTunes/320.17"},
      {"Content-Length", std::to_string(responseData.size())}};
  response.cseq = request.cseq;
  response.payload.insert(response.payload.end(), responseData.begin(),
                          responseData.end());

  response.print();
}

void APServer::handleSetup(const RTSPMessage &request, RTSPMessage &response,
                           std::shared_ptr<RTSPConnection> connection) {
  uint64_t sessionID = std::stoul(request.uri.substr(
      (std::string("rtsp://") +
       connection->socket().local_endpoint().address().to_string() + "/")
          .size()), 0, 10);
  LOG_INFO("Setup received for session {}", sessionID);
  if (request.headers.find("Content-Type") != request.headers.end() &&
      request.headers.at("Content-Type") ==
          "application/x-apple-binary-plist") {
    std::map<std::string, boost::any> plistRootNode;
    Plist::readPlist(request.payload.data(), request.payload.size(), plistRootNode);
    boost::asio::ip::address address =
        connection->socket().remote_endpoint().address();
    std::map<std::string, boost::any> responsePlist;
    if (!plistRootNode.empty()) {
      LOG_DEBUG("Setup plist root node: \n{}", plistRootNode);
      if (sessions.find(sessionID) == sessions.end()) {
        auto session = std::make_shared<Session::APSession>(
            this, plistRootNode, address, carplayEnabled);
        session->isCarPlay = carplayEnabled;
        sessions[sessionID] = session;
        if (sessionDelegate) {
          sessionDelegate->onSessionCreated(session);
        }
        if (pairingVerifySession) {
          session->setPairingSession(pairingVerifySession.get());
        }
        connection->setConnectionContext(session);
      }
      sessions[sessionID]->processSetup(plistRootNode, responsePlist);
      LOG_DEBUG("Response plist: \n{}", responsePlist);
      std::vector<char> responsePayload;
      Plist::writePlistBinary(responsePayload, responsePlist);
      response.payload.insert(response.payload.end(), responsePayload.begin(),
                              responsePayload.end());
      response.headers["Content-Type"] = "application/x-apple-binary-plist";
      response.headers["Content-Length"] =
          std::to_string(responsePayload.size());
      response.headers["Server"] = "AirTunes/320.17";
      response.statusCode = 200;
      response.reasonPhrase = "OK";
      response.cseq = request.cseq;
      setupOccurred = true;
    } else {
      LOG_ERROR("APServer: Unhandled RTSP message: {}", request.method);
      response.statusCode = 400;
      response.reasonPhrase = "Bad Request";
      response.headers["Content-Length"] = "0";
    }
  } else {
    LOG_ERROR("APServer: Unhandled RTSP message: {}", request.method);
    response.statusCode = 501;
    response.reasonPhrase = "Not Found";
    response.headers["Content-Length"] = "0";
  }
}

void APServer::handleInfo(const RTSPMessage &request, RTSPMessage &response,
                          std::shared_ptr<RTSPConnection> connection) {
  LOG_INFO("Info received");
  try{
    std::map<std::string, boost::any> requestPlist;
    if(request.payload.size() > 0){
      Plist::readPlist(request.payload.data(), request.payload.size(), requestPlist);
      LOG_DEBUG("INFO Request Plist: {}", requestPlist);
    }
    std::map<std::string, boost::any> responsePlist;
    responsePlist["sourceVersion"] = std::string("320.17");
    if(carplayEnabled){
      responsePlist["features"] = 0x615653AEE2;
    } else {
      responsePlist["features"] = 0x40405653AEE2;
    }
    responsePlist["statusFlags"] = 4;
    responsePlist["model"] = accModel;
    responsePlist["manufacturer"] = accMfg;
    responsePlist["deviceid"] = std::format(
                                      "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                      deviceID[0], deviceID[1], deviceID[2],
                                      deviceID[3], deviceID[4], deviceID[5]);
    responsePlist["name"] = accName;
    responsePlist["rightHandDrive"] = rightHandDrive;
    responsePlist["keepAliveLowPower"] = true;
    responsePlist["keepAliveSendStatsAsBody"] = false;
    std::map<std::string, boost::any> modesDict;
    std::vector<boost::any> resourcesArray;
    std::map<std::string, boost::any> resourceDict;
    for (auto r : initialCPmodes.resources) {
      resourceDict["resourceID"] = static_cast<Plist::integer_type>(r.resourceID);
      resourceDict["transferType"] = static_cast<Plist::integer_type>(r.transferType);
      resourceDict["transferPriority"] = static_cast<Plist::integer_type>(r.transferPriority);
      resourceDict["takeConstraint"] = static_cast<Plist::integer_type>(r.takeConstraint);
      resourceDict["borrowConstraint"] = static_cast<Plist::integer_type>(r.borrowConstraint);
      resourceDict["unborrowConstraint"] = static_cast<Plist::integer_type>(r.unborrowConstraint);
      resourcesArray.push_back(resourceDict);
    }
    std::vector<boost::any> appStatesArray;
    std::map<std::string, boost::any> appStatesDict;
    for (auto a : initialCPmodes.appStates) {
      appStatesDict["appStateID"] = static_cast<Plist::integer_type>(a.appStateID);
      if(a.appStateID == CPModes::AppStateID::CALL || a.appStateID == CPModes::AppStateID::TURN_BY_TURN){
        appStatesDict["state"] = static_cast<Plist::boolean_type>(a.state);
      }
      if(a.appStateID == CPModes::AppStateID::SPEECH){
        appStatesDict["speechMode"] = static_cast<Plist::integer_type>(a.speechMode);
      }
      appStatesArray.push_back(appStatesDict);
    }
    modesDict["resources"] = resourcesArray;
    modesDict["appStates"] = appStatesArray;
    std::vector<boost::any> audioLatenciesArray;
    std::map<std::string, boost::any> audioLatenciesDict;
    audioLatenciesDict["inputLatencyMicros"] = 0;
    audioLatenciesDict["type"] = 100;
    audioLatenciesDict["outputLatencyMicros"] = 0;
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["audioType"] = std::string("default");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["audioType"] = std::string("media");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["audioType"] = std::string("telephony");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["audioType"] = std::string("speechRecognition");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["audioType"] = std::string("alert");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["type"] = 101;
    audioLatenciesDict.erase("audioType");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["audioType"] = std::string("default");
    audioLatenciesArray.push_back(audioLatenciesDict);
    audioLatenciesDict["type"] = 102;
    audioLatenciesArray.push_back(audioLatenciesDict);

    std::vector<boost::any> audioFormatsArray;
    std::map<std::string, boost::any> audioFormatsDict;

    audioFormatsDict["audioInputFormats"] = 0x54;
    audioFormatsDict["audioOutputFormats"] = 0x8854;
    audioFormatsDict["audioType"] = std::string("compatibility");
    audioFormatsDict["type"] = 100;
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict["type"] = 101;
    audioFormatsDict.erase("audioInputFormats");
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict["audioInputFormats"] = 0xC000000;
    audioFormatsDict["audioOutputFormats"] = 0xC004550;
    audioFormatsDict["audioType"] = std::string("default");
    audioFormatsDict["type"] = 100;
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict.erase("audioInputFormats");
    audioFormatsDict["audioOutputFormats"] = 0x183000000;
    audioFormatsDict["audioType"] = std::string("alert");
    audioFormatsArray.push_back(audioFormatsDict);
    
    audioFormatsDict["audioOutputFormats"] = 0xC004550;
    audioFormatsDict["audioType"] = std::string("media");
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict["audioInputFormats"] = 0xC000000;
    audioFormatsDict["audioOutputFormats"] = 0xC000000;
    audioFormatsDict["audioType"] = std::string("telephony");
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict["audioType"] = std::string("speechRecognition");
    audioFormatsDict["audioInputFormats"] = 0x8000000;
    audioFormatsDict["audioOutputFormats"] = 0x8000000;
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict.erase("audioInputFormats");
    audioFormatsDict["audioOutputFormats"] = 0x183000000;
    audioFormatsDict["audioType"] = std::string("default");
    audioFormatsDict["type"] = 101;
    audioFormatsArray.push_back(audioFormatsDict);

    audioFormatsDict["audioOutputFormats"] = 0xC00000;
    audioFormatsDict["audioType"] = std::string("media");
    audioFormatsDict["type"] = 102;
    audioFormatsArray.push_back(audioFormatsDict);

    std::vector<boost::any> displaysArray;
    std::map<std::string, boost::any> displaysDict;
    displaysDict["widthPixels"] = static_cast<Plist::integer_type>(display.widthPixels);
    displaysDict["heightPixels"] = static_cast<Plist::integer_type>(display.heightPixels);
    displaysDict["primaryInputDevice"] = static_cast<Plist::integer_type>(display.primaryInputDevice);
    displaysDict["heightPhysical"] = static_cast<Plist::integer_type>(display.heightPhysicalMM);
    displaysDict["widthPhysical"] = static_cast<Plist::integer_type>(display.widthPhysicalMM);
    displaysDict["uuid"] = display.uuid;
    displaysDict["maxFPS"] = static_cast<Plist::integer_type>(display.maxFPS);
    displaysDict["features"] = static_cast<Plist::integer_type>(display.features);
    displaysArray.push_back(displaysDict);

    std::vector<boost::any> extendedFeaturesArray;
    extendedFeaturesArray.push_back(std::string("vocoderInfo"));
    extendedFeaturesArray.push_back(std::string("enhancedRequestCarUI"));

    std::vector<boost::any> hidDevicesArray;
    std::map<std::string, boost::any> hidDevicesDict;
    
    for (auto h : hidDevices) {
      hidDevicesDict["hidProductID"] = static_cast<Plist::integer_type>(h.hidProductID);
      hidDevicesDict["hidCountryCode"] = static_cast<Plist::integer_type>(h.hidCountryCode);
      hidDevicesDict["uuid"] = h.uuid;
      hidDevicesDict["hidDescriptor"] = h.hidDescriptor;
      hidDevicesDict["displayUUID"] = h.displayUuid;
      hidDevicesDict["hidVendorID"] = static_cast<Plist::integer_type>(h.hidVendorID);
      hidDevicesDict["name"] = h.name;
      hidDevicesArray.push_back(hidDevicesDict);
    }

    responsePlist["modes"] = modesDict;
    responsePlist["audioLatencies"] = audioLatenciesArray;
    responsePlist["audioFormats"] = audioFormatsArray;
    responsePlist["extendedFeatures"] = extendedFeaturesArray;
    responsePlist["displays"] = displaysArray;
    responsePlist["hidDevices"] = hidDevicesArray;
    std::vector<char> responsePayload;
    Plist::writePlistBinary(responsePayload, responsePlist);
    response.payload.insert(response.payload.end(), responsePayload.begin(),
                            responsePayload.end());
    response.headers["Content-Type"] = "application/x-apple-binary-plist";
    response.headers["Content-Length"] = std::to_string(responsePayload.size());
    response.headers["Server"] = "AirTunes/320.17";
    response.statusCode = 200;
    response.reasonPhrase = "OK";
  } catch(std::exception& e) {
    LOG_ERROR("Error occured constructing the INFO message: {}", e.what());
  }
}

void APServer::handleRecord(const RTSPMessage &request, RTSPMessage &response,
                            std::shared_ptr<RTSPConnection> connection) {
  uint64_t sessionID = std::stoul(request.uri.substr(
      (std::string("rtsp://") +
       connection->socket().local_endpoint().address().to_string() + "/")
          .size()), 0, 10);
  LOG_INFO("Record received for session {}", sessionID);
  if (sessions.find(sessionID) == sessions.end()) {
    LOG_ERROR("APServer: Session not found");
    response.statusCode = 404;
    response.reasonPhrase = "Not Found";
    response.headers["Content-Length"] = "0";
    return;
  }
  sessions[sessionID]->processRecord();
  activeSessionID = sessionID;
  // response.headers["Content-Type"] = "application/x-apple-binary-plist";
  // response.headers["Content-Length"] = "0";
  response.headers["Server"] = "AirTunes/320.17";
  response.cseq = request.cseq;
  response.statusCode = 200;
  response.reasonPhrase = "OK";
}

void APServer::handleCommand(const RTSPMessage &request, RTSPMessage &response,
                             std::shared_ptr<RTSPConnection> connection) {
  LOG_DEBUG("Command received");
  std::map<std::string, boost::any> plistRootNode;
  Plist::readPlist(request.payload.data(), request.payload.size(), plistRootNode);
  LOG_DEBUG("Command plist root node: \n{}", plistRootNode);
  std::map<std::string, boost::any> responsePlist;
  if (!plistRootNode.empty()) {
    sessions[activeSessionID]->processCommand(plistRootNode, responsePlist);
    std::vector<char> responsePayload;
    Plist::writePlistBinary(responsePayload, responsePlist);
    response.payload.insert(response.payload.end(), responsePayload.begin(),
                            responsePayload.end());
    response.headers["Content-Type"] = "application/x-apple-binary-plist";
    response.headers["Content-Length"] = responsePayload.size();
    response.headers["Server"] = "AirTunes/320.17";
    response.cseq = request.cseq;
    response.statusCode = 200;
    response.reasonPhrase = "OK";
  } else {
    LOG_ERROR("APServer: Unhandled RTSP message: {}", request.method);
  }
}

void APServer::handleFeedback(const RTSPMessage &request, RTSPMessage &response,
                              std::shared_ptr<RTSPConnection> connection) {
  LOG_DEBUG("Feedback received");
  try {
    std::any context = connection->getConnectionContext();
  if (context.type() == typeid(std::shared_ptr<Session::APSession>)) {
    std::shared_ptr<Session::APSession> session =
        std::any_cast<std::shared_ptr<Session::APSession>>(context);
    std::map<std::string, boost::any> requestPlist;
    std::map<std::string, boost::any> responsePlist;
    session->processFeedback(requestPlist, responsePlist);
    // std::vector<char> responsePayload;
    // Plist::writePlistBinary(responsePayload, responsePlist);
    // response.payload.insert(response.payload.end(), responsePayload.begin(),
    //                         responsePayload.end());
    // response.headers["Content-Type"] = "application/x-apple-binary-plist";
    // response.headers["Content-Length"] = responsePayload.size();
    response.headers["Audio-Jack-Status"] = "connected; type=digital";
    response.headers["Server"] = "AirTunes/320.17";
    response.cseq = request.cseq;
    response.statusCode = 200;
    response.reasonPhrase = "OK";
  } else {
    LOG_ERROR("APServer: Unhandled RTSP message: {}", request.method);
  }
  } catch (const std::bad_any_cast &e) {
    LOG_ERROR("APServer: Exception: {}", e.what());
    response.statusCode = 500;
    response.reasonPhrase = "Internal Server Error";
    response.headers["Content-Length"] = "0";
    response.headers["Server"] = "AirTunes/320.17";
    response.cseq = request.cseq;
  }
}

void APServer::handleTeardown(const RTSPMessage &request, RTSPMessage &response,
                              std::shared_ptr<RTSPConnection> connection) {
  LOG_INFO("Teardown received");
  uint64_t sessionID = std::stoul(request.uri.substr(
      (std::string("rtsp://") +
       connection->socket().local_endpoint().address().to_string() + "/")
          .size()), 0, 10);
  LOG_INFO("Teardown received for session {}", sessionID);
  if (sessions.find(sessionID) == sessions.end()) {
    LOG_ERROR("APServer: Session not found");
    response.statusCode = 404;
    response.reasonPhrase = "Not Found";
    response.headers["Content-Length"] = "0";
    return;
  } else {
    std::map<std::string, boost::any> requestPlist;
    Plist::readPlist(request.payload.data(), request.payload.size(), requestPlist);
    LOG_DEBUG("requestPlist: {}", requestPlist);
    std::map<std::string, boost::any> responsePlist;
    auto streamsNode = requestPlist["streams"];
    if (streamsNode.type() == typeid(Plist::array_type)) {
      sessions[sessionID]->processTeardown(requestPlist, responsePlist);
    } else {
      sessions[sessionID]->stop();
      sessions.erase(sessionID);
    }
    // std::vector<char> responsePayload;
    // Plist::writePlistBinary(responsePayload, responsePlist);
    // LOG_DEBUG("responsePlist: {}", responsePlist);
    // response.payload.insert(response.payload.end(), responsePayload.begin(),
    //                         responsePayload.end());
    // response.headers["Content-Type"] = "application/x-apple-binary-plist";
    // response.headers["Content-Length"] = responsePayload.size();
    response.headers["Server"] = "AirTunes/320.17";
    response.headers["Connection"] = "close";
    response.headers["Audio-Jack-Status"] = "connected; type=digital";
    response.cseq = request.cseq;
    response.statusCode = 200;
    response.reasonPhrase = "OK";
  }
}
void APServer::handleMessage(const RTSPMessage &request, RTSPMessage &response,
                             std::shared_ptr<RTSPConnection> connection,
                             std::any connection_context) {
  request.print();

  // Dispatch based on method and URI
  if (request.method == "POST") {
    if (request.uri == "/pair-setup") {
      return handlePairSetup(request, response, connection);
    } else if (request.uri == "/pair-verify") {
      return handlePairVerify(request, response, connection);
    } else if (request.uri == "/auth-setup") {
      return handleAuthSetup(request, response, connection);
    } else if (request.uri == "/command") {
      return handleCommand(request, response, connection);
    } else if (request.uri == "/feedback") {
      return handleFeedback(request, response, connection);
    }
  } else if (request.method == "SETUP") {
    return handleSetup(request, response, connection);
  } else if (request.method == "GET") {
    if (request.uri == "/info") {
      if(setupOccurred)
        return handleInfo(request, response, connection);
      else{
        response.headers["Server"] = "AirTunes/320.17";
        response.headers["Content-Length"] = "0";
        response.cseq = request.cseq;
        response.statusCode = 455;
        return;
      }
    }
  } else if (request.method == "RECORD") {
    return handleRecord(request, response, connection);
  } else if (request.method == "TEARDOWN") {
    return handleTeardown(request, response, connection);
  } else if (request.method == "OPTIONS") {
    response.headers["Public"] = "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, POST, GET, PUT, GET_PARAMETER, SET_PARAMETER";
    response.cseq = request.cseq;
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    return;
  } else if (request.method == "SET_PARAMETER") {
    response.headers["Server"] = "AirTunes/320.17";
    response.headers["Audio-Jack-Status"] = "connected; type=digital";
    response.cseq = request.cseq;
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    return;
  } else if (request.method == "GET_PARAMETER") {
    response.headers["Server"] = "AirTunes/320.17";
    response.headers["Audio-Jack-Status"] = "connected; type=digital";
    response.headers["Content-Type"] = "text/parameters";
    std::string volume = "volume: 0.0\r\n";
    response.payload = std::vector<char>(volume.begin(), volume.end());
    response.cseq = request.cseq;
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.print();
    return;
  }
  LOG_ERROR("APServer: Unhandled RTSP message: {}", request.method);
  response.statusCode = 501;
  response.reasonPhrase = "Not Implemented";
  response.headers["Content-Length"] = "0";
  response.headers["Server"] = "AirTunes/320.17";
}
} // namespace Server
} // namespace AirPlay
