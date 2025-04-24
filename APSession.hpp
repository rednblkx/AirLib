#pragma once
#include "APAudioStream.hpp"
#include "APSessionScreen.hpp"
#include "APTimeSync.hpp"
#include "PairingUtils.hpp"
#include "eventConnection.hpp"
#include "keepAliveManager.hpp"
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <cstdint>
#include <string>
#include <thread>
#include "cp_conf.hpp"

namespace AirPlay {
namespace Server {
class APServer;
} // namespace Server
} // namespace AirPlay

namespace AirPlay {
namespace Session {

class APSessionDelegate {
public:
  virtual void onSessionCreated(std::shared_ptr<APSession> session) = 0;
  virtual void onSessionDestroyed(std::shared_ptr<APSession> session) = 0;
};

struct APSessionStreamDelegate {
  virtual void onScreenStreamCreated(std::shared_ptr<Stream::APScreenSession> session){};
  virtual void onScreenStreamDestroyed(std::shared_ptr<Stream::APScreenSession> session){};
  virtual void onScreenStreamStarted(std::shared_ptr<Stream::APScreenSession> session){};
  virtual void onScreenStreamStopped(std::shared_ptr<Stream::APScreenSession> session){};
  virtual void onAudioStreamCreated(std::shared_ptr<Stream::APAudioStream> session){};
  virtual void onAudioStreamDestroyed(std::shared_ptr<Stream::APAudioStream> session){};
  virtual void onAudioStreamStarted(std::shared_ptr<Stream::APAudioStream> session){};
  virtual void onAudioStreamStopped(std::shared_ptr<Stream::APAudioStream> session){};
};

struct CPCommandsDelegate {
  virtual void onModesChanged(CPModes previous, CPModes current){};
  virtual void onDisableBluetoothReq(std::string macAddress){};
  virtual void onRequestUI(){};
  virtual void onHapticFeedback(std::string uuid){};
};

class APSession {
public:
  APSession(Server::APServer *server, std::map<std::string, boost::any> &controlData,
            boost::asio::ip::address peerAddress, bool isCarPlay = false);
  ~APSession();
  void setPairingSession(PairingSession *session);
  void processSetup(std::map<std::string, boost::any> &requestPlist,
                    std::map<std::string, boost::any> &responsePlist);
  void processRecord();
  void processTeardown(std::map<std::string, boost::any> &requestPlist,
                       std::map<std::string, boost::any> &responsePlist);
  void processCommand(std::map<std::string, boost::any> &requestPlist,
                      std::map<std::string, boost::any> &responsePlist);
  void processFeedback(std::map<std::string, boost::any> &requestPlist,
                       std::map<std::string, boost::any> &responsePlist);
  // Method to send a command via the event connection
  void sendEventCommand(const std::vector<char> &plist_data);
  void stop();
  void setStreamDelegate(APSessionStreamDelegate* delegate){streamDelegate = delegate;};
  void setCommandsDelegate(CPCommandsDelegate* delegate){commandsDelegate = delegate;};
  uint64_t getSessionID(){std::string id = sessionUUID; id.erase(std::remove(id.begin(), id.end(), '-'), id.end()); id.resize(16); return std::stoull(id, nullptr, 16);}
  bool isStopped(){return stopped_.load();};
  APTimeSync *getTimeSynchronizer(){return timeSynchronizer.get();}
  bool isCarPlay{false};
private:
  void setupControl(std::map<std::string, boost::any> &responsePlist);
  void carPlaySetup(Plist::dictionary_type &requestPlist, Plist::dictionary_type &responsePlist);
  std::atomic<bool> stopped_{false}; // Flag to indicate session stop initiated
  bool controlSetup{false};
  bool sessionIdle{true};
  CPModes previousCPmodes;
  CPModes currentCPmodes;

  boost::asio::io_context timingCtx;
  boost::asio::io_context keepAliveCtx;
  boost::asio::io_context eventCtx;
  boost::asio::io_context screenCtx; // Context for screen session
  boost::asio::io_context audioCtx; // Context for audio session
  std::thread keepAliveThread;
  std::thread timingThread;
  std::thread eventThread;
  std::thread screenThread;
  std::thread audioThread;
  Server::APServer *server; // Non-owning pointer to parent server

  // Timing Port Members
  int64_t deviceTimingPort; // Port reported by device
  uint16_t localTimingPort; // Port we allocated
  std::shared_ptr<APTimeSync>
      timeSynchronizer; // Replace with TimingPortBoost if applicable

  // Keep Alive Members
  uint16_t localKeepAlivePort; // Port we allocated
  bool keepAliveSupported{false};     // Did device request keep alive?
  std::shared_ptr<KeepAliveManager>
      keepAliveManager; // Replace with KeepAlivePortBoost

  // Event Connection Members
  uint16_t localEventPort; // Port we allocated
  std::shared_ptr<EventConnectionBoost> eventConnection;

  // --- Screen Session ---
  std::shared_ptr<Stream::APScreenSession>
      m_screen_session; // The screen session manager
  std::shared_ptr<Stream::APAudioStream> m_audio_stream; // The audio stream manager
  APSessionStreamDelegate* streamDelegate;
  CPCommandsDelegate* commandsDelegate;
  // Other session members
  boost::asio::ip::address peerAddress;
  std::string deviceID;
  std::string deviceMacAddress;
  std::string deviceName;
  std::string sessionUUID;
  std::string sourceVersion;

  PairingSession *verifySession;

  void initializeTiming(std::map<std::string, boost::any> &responsePlist);
  void initializeKeepAlive(std::map<std::string, boost::any> &responsePlist);
  void initializeEventConnection(std::map<std::string, boost::any> &responsePlist);
};
} // namespace Session
} // namespace AirPlay
