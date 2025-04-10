#ifndef I_SCREEN_RECEIVER_DELEGATE_HPP
#define I_SCREEN_RECEIVER_DELEGATE_HPP

#include <cstdint>
#include <vector>
#include "logger.hpp"
namespace AirPlay {


typedef union
{
	char		c[ 8 ];
	uint8_t		u8[ 8 ];
	int8_t		s8[ 8 ];
	uint16_t	u16[ 4 ];
	int16_t		s16[ 4 ];
	uint32_t	u32[ 2 ];
	int32_t		s32[ 2 ];
	uint64_t	u64;
	int64_t		s64;
	float		f32[ 2 ];
	double		f64;
}	Value64;

typedef struct
{
	uint32_t		bodySize;
	uint8_t			opcode;
	uint8_t			smallParam[ 3 ];
	Value64			params[ 15 ];
}	APSHeader;

/**
 * @brief Delegate interface for receiving screen data and events.
 *
 * Implement this interface to handle data processed by
 * APSessionScreen.
 */
class IScreenStreamDelegate {
  public:
    virtual ~IScreenStreamDelegate() = default;

    /**
     * @brief Called when a video configuration frame is received.
     *
     * @param header The full AirPlayScreenHeader for context.
     * @param width The display width.
     * @param height The display height.
     * @param avccData Pointer to the AVCC configuration data (if any).
     * @param avccSize Size of the AVCC data.
     */
    virtual void onVideoConfig(const APSHeader& header, float width,
                               float height, std::vector<uint8_t>& avccData) {
        LOG_INFO("onVideoConfig: width={} height={} avccSize={}", width, height, avccData.size());
    }

    /**
     * @brief Called when decrypted video frame data is ready.
     *
     * @param header The full AirPlayScreenHeader for context.
     * @param data Pointer to the decrypted video frame data.
     * @param size Size of the video frame data.
     * @param displayTimestamp The calculated display timestamp in host ticks.
     */
    virtual void onVideoData(const APSHeader& header,
                             std::vector<uint8_t>& data,
                             uint64_t displayTimestamp) {
        LOG_INFO("onVideoData: size={} displayTimestamp={}", data.size(), displayTimestamp);
    }

    /**
     * @brief Called when the AirPlay screen session is stopped (normally or due to error).
     */
    virtual void onSessionStopped() {
        LOG_INFO("onSessionStopped");
    }
};

} // namespace AirPlay

#endif // I_SCREEN_RECEIVER_DELEGATE_HPP
