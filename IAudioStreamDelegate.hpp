#pragma once

#include "APAudioCommon.hpp" // For ASBD, RtpHeader etc.
#include <span> // For std::span

namespace AirPlay {
namespace Session {
namespace Stream {

// Forward declaration
class APAudioStream;

class IAudioStreamDelegate {
public:
    virtual ~IAudioStreamDelegate() = default;

    /**
     * @brief Called once after the stream is successfully set up, providing the
     *        format of the *decrypted* audio packets that will be delivered.
     * @param format The basic description of the audio format (e.g., PCM, AAC).
     */
    virtual void onStreamFormatReady(AudioStreamDescriptor &format) = 0;

    /**
     * @brief Called whenever a decrypted audio packet is ready.
     *        The delegate is responsible for decoding (if necessary), buffering,
     *        and rendering this data. This call happens on the io_context
     *        thread, so the delegate should process it quickly or offload work.
     * @param rtpHeader The parsed RTP header of the packet (host byte order).
     * @param decryptedPayload A span containing the decrypted payload data.
     *                         The underlying buffer is temporary and owned by
     *                         APAudioStream; the delegate must copy the data
     *                         if it needs to persist beyond this call.
     */
    virtual void onDecryptedPacketReady(
        const RtpHeader& rtpHeader,
        std::span<const std::byte> decryptedPayload) = 0;

    /**
     * @brief Called when a flush command is received from the source.
     *        The delegate should discard any buffered audio data up to the
     *        specified sequence number and timestamp and reset its decoder/renderer state.
     * @param flushUntilTS RTP timestamp up to which data should be flushed (exclusive).
     * @param flushUntilSeq RTP sequence number up to which data should be flushed (exclusive).
     */
    virtual void onFlushRequested(uint32_t flushUntilTS, uint16_t flushUntilSeq) = 0;

    /**
     * @brief Optional: Called when a gap in sequence numbers is detected,
     *        *before* a retransmit is requested (if applicable).
     *        The delegate might use this to prepare for potential silence or concealment.
     * @param seqStart The first sequence number detected as missing.
     * @param seqCount The number of consecutive sequence numbers missing.
     */
    virtual void onPacketLossDetected(uint16_t seqStart, uint16_t seqCount) {
        // Default implementation does nothing
        (void)seqStart;
        (void)seqCount;
    }
};

} // namespace Stream
} // namespace Session
} // namespace AirPlay