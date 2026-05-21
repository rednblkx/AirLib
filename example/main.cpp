#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <string>
#include "APServer.hpp"
#include "APSession.hpp"
#include "GStreamerAudioReceiver.hpp"
#include "GStreamerReceiver.hpp"
#include "cp_conf.hpp"
#include "logger.hpp"

class AppClass : public AirPlay::Session::APSessionDelegate, public AirPlay::Session::APSessionStreamDelegate, public AirPlay::Session::CPCommandsDelegate {
public:
  AppClass() {
    apServer = std::make_unique<AirPlay::Server::APServer>();
    apServer->carplayEnabled = true;
    apServer->setSessionDelegate(this);
    DisplayDescriptor display;
    display.features = DisplayDescriptor::HIGH_TOUCH;
    display.widthPhysicalMM = 0;
    display.heightPhysicalMM = 0;
    display.widthPixels = 540;
    display.heightPixels = 960;
    apServer->addDisplay(display);
    HIDTouchscreenSingle singleTouch(0, display.widthPixels, 0, display.heightPixels);
    singleTouch.displayUuid = display.uuid;
    apServer->addHIDDevice(singleTouch);
  }
  void start() {
    apServer->startServers();
  }
  void onSessionCreated(std::shared_ptr<AirPlay::Session::APSession> session) override {
    LOG_INFO("Session created {}", session->getSessionID());
    session->setStreamDelegate(this);
    session->setCommandsDelegate(this);
    this->session = session.get();
  }
  void onSessionDestroyed(std::shared_ptr<AirPlay::Session::APSession> session) override {
    LOG_INFO("Session destroyed {}", session->getSessionID());
  }
  void onScreenStreamCreated(std::shared_ptr<AirPlay::Session::Stream::APScreenSession> screenSession) override {
    LOG_INFO("Screen stream created");
    screenReceiver = std::make_unique<AirPlay::GStreamerScreenReceiver>(session);
    screenSession->setDelegate(screenReceiver.get());
  }
  void onScreenStreamDestroyed(std::shared_ptr<AirPlay::Session::Stream::APScreenSession> session) override {
    LOG_INFO("Screen stream destroyed");
  }
  void onScreenStreamStarted(std::shared_ptr<AirPlay::Session::Stream::APScreenSession> session) override {
    LOG_INFO("Screen stream started");
  }
  void onScreenStreamStopped(std::shared_ptr<AirPlay::Session::Stream::APScreenSession> session) override {
    LOG_INFO("Screen stream stopped");
    screenReceiver = nullptr;
  }
  void onAudioStreamCreated(std::shared_ptr<AirPlay::Session::Stream::APAudioStream> session) override {
    gstreamerAudio = std::make_unique<AirPlay::Session::Stream::GStreamerAudioReceiver>();
    session->setDelegate(gstreamerAudio.get());
  }
  void onAudioStreamDestroyed(std::shared_ptr<AirPlay::Session::Stream::APAudioStream> session) override {
    LOG_INFO("Audio stream destroyed");
  }
  void onAudioStreamStarted(std::shared_ptr<AirPlay::Session::Stream::APAudioStream> session) override {
    LOG_INFO("Audio stream started");
  }
  void onAudioStreamStopped(std::shared_ptr<AirPlay::Session::Stream::APAudioStream> session) override {
    LOG_INFO("Audio stream stopped");
    gstreamerAudio->stop();
  }

  void onModesChanged(CPModes previous, CPModes currentModes) override {
    LOG_INFO("Modes Changed: ");
    LOG_INFO("\tAppState:");
    for (auto m : currentModes.appStates) {
      LOG_INFO("\t\tappStateID: {}", m.appStateID == CPModes::AppStateID::SPEECH ? "SPEECH" : CPModes::AppStateID::CALL == m.appStateID ? "CALL" : "TURN_BY_TURN");
      LOG_INFO("\t\tentity: {}", m.entity == CPModes::Entity::ACCESSORY ? "ACCESSORY" : CPModes::Entity::CONTROLLER == m.entity ? "CONTROLLER" : "NONE");
      LOG_INFO("\t\tspeechMode: {}", m.speechMode == CPModes::SpeechMode::SPEAKING ? "SPEAKING" : CPModes::SpeechMode::LISTENING == m.speechMode ? "LISTENING" : "NONE");
    }
    LOG_INFO("\tResources:");
    for (auto m : currentModes.resources) {
      LOG_INFO("\t\tentity: {}", m.entity == CPModes::Entity::ACCESSORY ? "ACCESSORY" : CPModes::Entity::CONTROLLER == m.entity ? "CONTROLLER" : "NONE");
      LOG_INFO("\t\tresourceId: {}", m.resourceID == CPModes::ResourceID::AUDIO ? "AUDIO" : CPModes::ResourceID::SCREEN == m.resourceID ? "SCREEN" : "UNKNOWN");
    }
  };

  void onDisableBluetoothReq(std::string macAddress) override {
    LOG_INFO("Request to disable Bluetooth connection for {}", macAddress);
  }

  void onRequestUI() override {
    LOG_INFO("UI Requested");
  }

  void stop() {
    apServer->stopServers();
  }
private:
  std::unique_ptr<AirPlay::Server::APServer> apServer;
  AirPlay::Session::APSession* session;
  std::unique_ptr<AirPlay::GStreamerScreenReceiver> screenReceiver;
  std::unique_ptr<AirPlay::Session::Stream::GStreamerAudioReceiver> gstreamerAudio;
};

void handle_signals(AppClass& thing) {
    net::io_context ioc;
    net::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](error_code /*ec*/, int /*signo*/) {
        LOG_INFO("Shutdown signal received.");
        thing.stop();
        ioc.stop();
    });
    ioc.run();
}

int main() {
  try {
    AppClass thing;
    std::thread t(handle_signals, std::ref(thing));
    thing.start();
    t.join();
  } catch (const std::exception &e) {
    LOG_ERROR("Error: {}", e.what());
    return 1;
  }
  return 0;
}
