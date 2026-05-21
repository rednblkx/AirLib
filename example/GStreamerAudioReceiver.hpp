#pragma once
#include "APAudioCommon.hpp"
#include "APSession.hpp"
#include "glib.h"
#include "logger.hpp"
#include <cstddef>
#include <gst/app/gstappsrc.h>
#include <gst/gst.h>

#include <atomic>
#include <stdexcept>
#include <thread>

namespace AirPlay::Session::Stream {
    class GStreamerAudioReceiver : public IAudioStreamDelegate {
    struct GstObjectDeleter {
      void operator()(GstObject *obj) const {
        if (obj) {
          gst_object_unref(obj);
        }
      }
    };
    using GstObjectUniquePtr = std::unique_ptr<GstObject, GstObjectDeleter>;
    
    struct GstElementDeleter {
      void operator()(GstElement *elem) const {
        if (elem) {
          gst_object_unref(GST_OBJECT(elem));
        }
      }
    };
    using GstElementUniquePtr = std::unique_ptr<GstElement, GstElementDeleter>;
    
    struct GMainLoopDeleter {
      void operator()(GMainLoop *loop) const {
        if (loop) {
          g_main_loop_unref(loop);
        }
      }
    };
    using GMainLoopUniquePtr = std::unique_ptr<GMainLoop, GMainLoopDeleter>;
    public:
  GStreamerAudioReceiver() {
    gst_init(nullptr, nullptr);
    GstClock *clock = gst_system_clock_obtain();
    g_object_set(clock, "clock-type", GST_CLOCK_TYPE_REALTIME, NULL);
    const char *pipeline_desc = "appsrc name=airaudio_src"
                                " ! faad ! audioconvert ! "
                                "audioresample !"
                                "pulsesink sync=false";

    GError *error = nullptr;
    pipeline_.reset(gst_parse_launch(pipeline_desc, &error));

    if (!pipeline_) {
      LOG_ERROR("Failed to create pipeline: {}", (error ? error->message : "Unknown error"));
      if (error)
        g_error_free(error);
      throw std::runtime_error("Failed to create GStreamer pipeline");
    }
    gst_pipeline_use_clock(GST_PIPELINE_CAST(pipeline_.get()), clock);
    GstElement *appsrc_elem =
        gst_bin_get_by_name(GST_BIN(pipeline_.get()), "airaudio_src");
    if (!appsrc_elem) {
      throw std::runtime_error("Failed to get appsrc element from pipeline");
    }
    appsrc_ = GST_APP_SRC(appsrc_elem);

    g_object_unref(clock);
    main_loop_.reset(g_main_loop_new(nullptr, FALSE));
    main_loop_thread_ = std::thread(&GStreamerAudioReceiver::runMainLoop, this);
    LOG_INFO("GStreamerAudioReceiver initialized.");
  };
  ~GStreamerAudioReceiver() override {

  };

  GStreamerAudioReceiver(const GStreamerAudioReceiver &) = delete;
  GStreamerAudioReceiver &operator=(const GStreamerAudioReceiver &) = delete;
  GStreamerAudioReceiver(GStreamerAudioReceiver &&) = delete;
  GStreamerAudioReceiver &operator=(GStreamerAudioReceiver &&) = delete;

  void onStreamFormatReady(AudioStreamDescriptor &format) override {
    if (session_stopped_)
      return;
    GstCaps *caps = NULL;
    if(format.audioFormat == AudioStreamDescriptor::AudioFormat::AAC_LC){
        static const char aac_lc_caps[] = "audio/mpeg,mpegversion=(int)4,channnels=(int)2,rate=(int)44100,stream-format=raw,codec_data=(buffer)1210";
        caps =  gst_caps_from_string(aac_lc_caps);
        g_object_set(appsrc_, "caps", caps, "stream-type", 0, "is-live", TRUE, "format", GST_FORMAT_TIME, NULL);
        gst_caps_unref(caps);
        if (gst_element_set_state(pipeline_.get(), GST_STATE_PLAYING) ==
            GST_STATE_CHANGE_FAILURE) {
          LOG_ERROR("Failed to set pipeline to PLAYING state." );
        } else {
          pipeline_ready_ = true;
        }
      } else if (format.audioFormat == AudioStreamDescriptor::AudioFormat::AAC_ELD) {
        static const char aac_eld_caps[] ="audio/mpeg,mpegversion=(int)4,channnels=(int)2,rate=(int)44100,stream-format=raw,codec_data=(buffer)f8e85000"; 
        caps =  gst_caps_from_string(aac_eld_caps);
        g_object_set(appsrc_, "caps", caps, "stream-type", 0, "is-live", TRUE, "format", GST_FORMAT_TIME, NULL);
        gst_caps_unref(caps);
        if (gst_element_set_state(pipeline_.get(), GST_STATE_PLAYING) ==
            GST_STATE_CHANGE_FAILURE) {
          LOG_ERROR("Failed to set pipeline to PLAYING state." );
        } else {
          pipeline_ready_ = true;
        }
      
    }
  };

  void
  onDecryptedPacketReady(const RtpHeader &rtpHeader,
                         std::span<const std::byte> decryptedPayload) override {
    if (!pipeline_ready_ || decryptedPayload.empty()) {
      return;
    }

    if(session_stopped_){

    }
    GstBuffer *buffer = gst_buffer_new_allocate(nullptr, decryptedPayload.size(), nullptr);
    if (!buffer) {
      LOG_ERROR("Failed to allocate GstBuffer for video data" );
      return;
    }

    gst_buffer_fill(buffer, 0, decryptedPayload.data(), decryptedPayload.size());

    GstFlowReturn ret = gst_app_src_push_buffer(GST_APP_SRC(appsrc_), buffer);

    if (ret != GST_FLOW_OK) {
      LOG_ERROR("Error pushing buffer to appsrc: {}", gst_flow_get_name(ret));
      if (ret == GST_FLOW_FLUSHING || ret == GST_FLOW_EOS) {
        pipeline_ready_ = false;
      }
    }
  };

  void onFlushRequested(uint32_t flushUntilTS,
                        uint16_t flushUntilSeq) override {

  };

  void onPacketLossDetected(uint16_t seqStart, uint16_t seqCount) override {

  };

  void stop() {
    pipeline_ready_ = false;

    if (appsrc_) {
      GstFlowReturn ret = gst_app_src_end_of_stream(appsrc_);
      if (ret != GST_FLOW_OK) {
        LOG_ERROR("Failed to send EOS to appsrc: {}", gst_flow_get_name(ret));
      } else {
        LOG_DEBUG("EOS sent to appsrc.");
      }
    }

    if (session_stopped_.exchange(true)) {
      return;
    }
    if (main_loop_) {
      g_main_loop_quit(main_loop_.get());
    }
    LOG_INFO("AirPlay session stopped.");
    if (main_loop_thread_.joinable()) {
      main_loop_thread_.join();
    }
  }
private:
  static gboolean busCallback(GstBus *bus, GstMessage *msg, gpointer data) {
    GStreamerAudioReceiver *self = static_cast<GStreamerAudioReceiver *>(data);

    switch (GST_MESSAGE_TYPE(msg)) {
    case GST_MESSAGE_ERROR: {
      GError *err = nullptr;
      gchar *dbg_info = nullptr;
      gst_message_parse_error(msg, &err, &dbg_info);
      LOG_ERROR("GStreamer Error: {}", err->message);
      LOG_ERROR("Debugging info: {}", (dbg_info ? dbg_info : "none"));
      g_error_free(err);
      g_free(dbg_info);
      self->stop();
      break;
    }
    case GST_MESSAGE_EOS:
      LOG_INFO("GStreamer End-Of-Stream received on bus.");
      if (self->main_loop_) {
        g_main_loop_quit(self->main_loop_.get());
      }
      break;
    case GST_MESSAGE_STATE_CHANGED:
      if (GST_MESSAGE_SRC(msg) == GST_OBJECT(self->pipeline_.get())) {
        GstState old_state, new_state, pending_state;
        gst_message_parse_state_changed(msg, &old_state, &new_state,
                                        &pending_state);
      }
      break;
    default:
      break;
    }

    return TRUE;
  }
  void runMainLoop() {
    LOG_INFO("GStreamer main loop starting...");
    if (main_loop_) {
      GstBus *bus = gst_element_get_bus(pipeline_.get());
      if (bus) {
        gst_bus_add_watch(bus, busCallback, this);
        gst_object_unref(bus);
      } else {
        LOG_ERROR("Failed to get pipeline bus.");
      }
      g_main_loop_run(main_loop_.get());
    }
    LOG_INFO("GStreamer main loop finished.");

    if (pipeline_) {
      gst_element_set_state(pipeline_.get(), GST_STATE_NULL);
    }
  }
  GstElementUniquePtr pipeline_;
  GstAppSrc *appsrc_;
  GMainLoopUniquePtr main_loop_;
  std::thread main_loop_thread_;

  std::atomic<bool> pipeline_ready_;
  std::atomic<bool> session_stopped_;
  Session::APSession *session_;
};
} // namespace AirPlay::Session::Stream
