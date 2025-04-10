#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct CPModes {
    enum class SpeechMode {
      NONE = -1,
      SPEAKING = 1,
      LISTENING = 2
    };
    enum class AppStateID {
      SPEECH = 1,
      CALL = 2,
      TURN_BY_TURN = 3
    };
    enum class Entity {
      NONE = 0,
      CONTROLLER = 1,
      ACCESSORY = 2
    };
    enum class ResourceID {
      SCREEN = 1,
      AUDIO = 2
    };
    struct AppState {
      AppStateID appStateID;
      Entity entity;
      SpeechMode speechMode;
      bool state; // Required for PhoneCall or TurnByTurn
    };
    std::vector<AppState> appStates;
    enum class TransferType {
      TAKE = 1,
      UNTAKE = 2,
      BORROW = 3,
      UNBORROW = 4
    };
    enum class TransferPriority {
      NICE_TO_HAVE = 100,
      USER_INITIATED = 500
    };
    enum class ResourceConstraint {
      ANYTIME = 100,
      USER_INITIATED = 500,
      NEVER = 1000
    };
    struct Resource {
      /* Device -> Accessory */
      Entity entity;
      Entity permanentEntity;
      /* ------------------- */
      ResourceID resourceID;
      /* ------------------- */
      /* Accessory -> Device */
      TransferType transferType;
      TransferPriority transferPriority; // Required if take or borrow
      ResourceConstraint takeConstraint;
      ResourceConstraint borrowConstraint;
      ResourceConstraint unborrowConstraint;
    };
    std::vector<Resource> resources;
  };

  struct HIDDevice {
    std::vector<char> hidDescriptor;
    std::string uuid = "0";
    std::string name = "HID";
    uint16_t hidProductID = 1;
    uint16_t hidCountryCode = 0;
    uint16_t hidVendorID = 2;
    std::string displayUuid = "1";
  };

  struct HIDTouchscreenSingle : HIDDevice {
    uint16_t x_minimum = 0;
    uint16_t x_maximum = 1280;
    uint16_t y_minimum = 0;
    uint16_t y_maximum = 720;
    HIDTouchscreenSingle(uint16_t x_minimum, uint16_t x_maximum, uint16_t y_minimum, uint16_t y_maximum) : x_minimum(x_minimum), x_maximum(x_maximum), y_minimum(y_minimum), y_maximum(y_maximum) {
        hidDescriptor = {
            0x05,0x0d, // Digitizer page
            0x09,0x04, // TouchScreen
            static_cast<char>(0xa1),0x01, // Application collection
            0x05,0x0d, // Digitizer page
            0x09,0x22, // Finger
            static_cast<char>(0xa1),0x02, // Logical collection
            0x05,0x0d, // Digitizer Page
            0x09,0x33, // Touch
            0x15,0x00, // Minimum
            0x25,0x01, // Maximum
            0x75,0x01, // Size
            static_cast<char>(0x95),0x01, //Count
            static_cast<char>(0x81),0x02, // Data
            0x75,0x07, // Size
            static_cast<char>(0x95),0x01, // Count
            static_cast<char>(0x81),0x01, // Constant
            0x05,0x01, // Generic Desktop page
            0x09,0x30, // X
            0x15,static_cast<char>(x_minimum & 0xff), static_cast<char>(x_minimum >> 8), // Minimum
            0x26,static_cast<char>(x_maximum & 0xff), static_cast<char>(x_maximum >> 8), // Maximum
            0x75,0x10, // Size
            static_cast<char>(0x95),0x01, // Count
            static_cast<char>(0x81),0x02, // Data
            0x09,0x31, // Y
            0x15,static_cast<char>(y_minimum & 0xff), static_cast<char>(y_minimum >> 8), // Minimum
            0x26,static_cast<char>(y_maximum & 0xff), static_cast<char>(y_maximum >> 8), // Maximum
            0x75,0x10, // Size
            static_cast<char>(0x95),0x01, // Count
            static_cast<char>(0x81),0x02, // Data
            static_cast<char>(0xc0), // Collection end
            static_cast<char>(0xc0) // Collection end
        };
    }
  };

struct DisplayDescriptor {
    uint16_t widthPixels = 1280;
    uint16_t heightPixels = 720;
    uint16_t heightPhysicalMM = 90;
    uint16_t widthPhysicalMM = 150;
    std::string uuid = "1";
    uint16_t maxFPS = 60;
    enum Features {
        KNOBS = 0x02,
        LOW_TOUCH = 0x04,
        HIGH_TOUCH = 0x08,
        TOUCHPAD = 0x10
    } features = LOW_TOUCH; // Bitfield
    enum PrimaryInput{
        I_TOUCHSCREEN,
        I_TOUCHPAD,
        I_KNOB
    } primaryInputDevice = I_TOUCHSCREEN;
};