#include "APSession.hpp"
#include "PairingUtils.hpp"
#include "RTSPMessage.hpp"
#include "cp_conf.hpp"
#include "dnssd/dnssd.hpp"
#include "server.hpp"
#include <array>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <vector>

namespace AirPlay {
namespace Server {
struct TransportContext {
  std::vector<uint8_t> inputKey;
  std::vector<uint8_t> outputKey;
  uint8_t inputNonce[12];
  uint8_t outputNonce[12];
};

class APServer : public RTSPServerDelegate, public EncryptionDelegate {
public:
  APServer(
      std::string name = "AirLib", 
      boost::asio::ip::address address = boost::asio::ip::address_v6::any(),
      uint16_t port = 7000);
  ~APServer();
  std::array<uint8_t, 6> getDeviceID() { return deviceID; }
  void startServers();
  void stopServers();
  void startBonjour();
  void stopBonjour();
  void setSessionDelegate(Session::APSessionDelegate* delegate);
  void setInitialCPModes(CPModes modes){initialCPmodes = modes;};
  CPModes getInitialCPModes(){return initialCPmodes;};
  void addHIDDevice(HIDDevice hidDevice){hidDevices.push_back(hidDevice);};
  void addDisplay(DisplayDescriptor display){this->display = display;};
  bool carplayEnabled = true;
private:
  std::string accModel = "AppleTV3,2";
  std::string accMfg = "Misterio";
  std::string accName;
  bool setupOccurred = false;
  std::array<uint8_t, 6> bluetoothID{0xE8,0x48,0xB8,0xC8,0x20, 0x00};
  bool rightHandDrive = false;
  std::vector<HIDDevice> hidDevices;
  DisplayDescriptor display;
  CPModes initialCPmodes;
  std::array<uint8_t, 6> deviceID;
  std::unique_ptr<AirDNS> airDNS;
  boost::asio::ip::address address;
  unsigned short port;
  boost::asio::io_context ioc;
//  boost::asio::io_context log_ioc;
//  std::thread log_thread;
  std::unique_ptr<PairingSession> pairingSetupSession;
  std::unique_ptr<PairingSession> pairingVerifySession;
  std::shared_ptr<RTSPServer> server;
  std::map<uint64_t, std::shared_ptr<Session::APSession>> sessions;
  uint64_t activeSessionID;
  bool pairingVerified{false};
  Session::APSessionDelegate* sessionDelegate{nullptr};
  void initializeServer(RTSPServer *server) override;
  void finalizeServer(RTSPServer *server) override;
  void handleConnection(std::shared_ptr<RTSPConnection> connection,
                        std::any context) override;
  void handleConnectionClosed(std::shared_ptr<RTSPConnection> connection,
                        const boost::system::error_code &ec) override;
  void handleMessage(const RTSPMessage &request, RTSPMessage &response,
                     std::shared_ptr<RTSPConnection> connection,
                     std::any context) override;
  void configureTransport(std::shared_ptr<RTSPConnection> connection);
  void handlePairSetup(const RTSPMessage &request, RTSPMessage &response,
                       std::shared_ptr<RTSPConnection> connection);
  void handlePairVerify(const RTSPMessage &request, RTSPMessage &response,
                        std::shared_ptr<RTSPConnection> connection);
  void handleAuthSetup(const RTSPMessage &request, RTSPMessage &response,
                       std::shared_ptr<RTSPConnection> connection);
  void handleSetup(const RTSPMessage &request, RTSPMessage &response,
                   std::shared_ptr<RTSPConnection> connection);
  void handleInfo(const RTSPMessage &request, RTSPMessage &response,
                  std::shared_ptr<RTSPConnection> connection);
  void handleRecord(const RTSPMessage &request, RTSPMessage &response,
                    std::shared_ptr<RTSPConnection> connection);
  void handleCommand(const RTSPMessage &request, RTSPMessage &response,
                     std::shared_ptr<RTSPConnection> connection);
  void handleFeedback(const RTSPMessage &request, RTSPMessage &response,
                      std::shared_ptr<RTSPConnection> connection);
  void handleTeardown(const RTSPMessage &request, RTSPMessage &response,
                      std::shared_ptr<RTSPConnection> connection);
  std::vector<char> decryptMessage(const std::vector<char> &encrypted_data,
                                   std::any connection_context,
                                   boost::system::error_code &ec) override;
  std::vector<char> encryptMessage(const std::vector<char> &plaintext_payload,
                                   std::any connection_context,
                                   boost::system::error_code &ec) override;
  void handleWriteComplete(std::shared_ptr<RTSPConnection> connection,
                     std::any connection_context,
                     const boost::system::error_code &ec) override;
  friend class RTSPServer;
  friend class APSession;
};
} // namespace Server
} // namespace AirPlay