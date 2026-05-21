#include "APSession.hpp"
#include "IScreenStreamDelegate.hpp"
#include "glib.h"
#include "gst/gstelement.h"
#include "gst/video/videooverlay.h"
#include "logger.hpp"

#include <SDL3/SDL_init.h>
#include <SDL3/SDL_oldnames.h>
#include <SDL3/SDL_video.h>
#include <X11/X.h>
#include <cstdint>
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>

#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

#include <SDL3/SDL.h>

struct SDLWindowDeleter {
    void operator()(SDL_Window* window) const {
        if (window) SDL_DestroyWindow(window);
    }
};

using SDLWindowUniquePtr = std::unique_ptr<SDL_Window, SDLWindowDeleter>;

struct GstObjectDeleter {
    void operator()(GstObject* obj) const {
        if (obj) {
            gst_object_unref(obj);
        }
    }
};
using GstObjectUniquePtr = std::unique_ptr<GstObject, GstObjectDeleter>;

struct GstElementDeleter {
    void operator()(GstElement* elem) const {
        if (elem) {
            gst_object_unref(GST_OBJECT(elem));
        }
    }
};
using GstElementUniquePtr = std::unique_ptr<GstElement, GstElementDeleter>;

struct GMainLoopDeleter {
    void operator()(GMainLoop* loop) const {
        if (loop) {
            g_main_loop_unref(loop);
        }
    }
};
using GMainLoopUniquePtr = std::unique_ptr<GMainLoop, GMainLoopDeleter>;

namespace AirPlay {

class GStreamerScreenReceiver : public IScreenStreamDelegate {
  public:
    GStreamerScreenReceiver(Session::APSession* session) : pipeline_ready_(false), session_stopped_(false), session_(session) {
        gst_init(nullptr, nullptr);
        if (SDL_Init(SDL_INIT_VIDEO) < 0) {
            throw std::runtime_error(std::string("SDL_Init failed: ") + SDL_GetError());
        }

        sdl_window_.reset(SDL_CreateWindow("AirPlay", width, height, SDL_WINDOW_BORDERLESS | SDL_WINDOW_TRANSPARENT | SDL_WINDOW_HIDDEN));
        const char* pipeline_desc =
            "appsrc name=airscreen_src format=time is-live=true ! queue ! "
            "h264parse ! avdec_h264 ! videoconvert ! ximagesink name=sdlsink sync=false";

        GError* error = nullptr;
        pipeline_.reset(gst_parse_launch(pipeline_desc, &error));

        if (!pipeline_) {
            LOG_ERROR("Failed to create pipeline: {}", (error ? error->message : "Unknown error"));
            if (error) g_error_free(error);
            throw std::runtime_error("Failed to create GStreamer pipeline");
        }

        GstElement* appsrc_elem =
            gst_bin_get_by_name(GST_BIN(pipeline_.get()), "airscreen_src");
        if (!appsrc_elem) {
            throw std::runtime_error("Failed to get appsrc element from pipeline");
        }
        appsrc_ = GST_APP_SRC(appsrc_elem);

        gst_app_src_set_stream_type(appsrc_, GST_APP_STREAM_TYPE_STREAM);
        g_object_set(G_OBJECT(appsrc_), "max-bytes", (guint64)0, nullptr);
        g_object_set(G_OBJECT(appsrc_), "do-timestamp", TRUE, nullptr);
        g_object_set(G_OBJECT(appsrc_), "format", GST_FORMAT_TIME, nullptr);
        g_object_set(G_OBJECT(appsrc_), "is-live", TRUE, nullptr);

        sdl_sink_ = gst_bin_get_by_name(GST_BIN(pipeline_.get()), "sdlsink");
        if (!sdl_sink_) {
            throw std::runtime_error("Failed to get the video sink element.");
        }

        GstBus* bus = gst_element_get_bus(pipeline_.get());
        if (!bus) {
            throw std::runtime_error("Failed to get pipeline bus");
        }
        gst_bus_set_sync_handler(bus, (GstBusSyncHandler)syncBusCallback, this, nullptr); // Sync handler
        gst_object_unref(bus);
        main_loop_.reset(g_main_loop_new(nullptr, FALSE));
        main_loop_thread_ = std::thread(&GStreamerScreenReceiver::runMainLoop, this);

        LOG_INFO("GStreamerScreenReceiver initialized.");
    }

    ~GStreamerScreenReceiver() override {
        LOG_INFO("GStreamerScreenReceiver shutting down...");
        cleanup();
        LOG_INFO("GStreamerScreenReceiver finished cleanup.");
    }

    static GstBusSyncReply syncBusCallback(GstBus* bus, GstMessage* msg, gpointer data) {
        GStreamerScreenReceiver* self = static_cast<GStreamerScreenReceiver*>(data);

        if (self->sdl_sink_ &&
            GST_MESSAGE_SRC(msg) == GST_OBJECT(self->sdl_sink_) &&
            gst_is_video_overlay_prepare_window_handle_message(msg))
        {
            if (!self->sdl_window_) {
                LOG_ERROR("Error: prepare-window-handle received but SDL window is null!");
                return GST_BUS_PASS;
            }

           LOG_DEBUG("Received prepare-window-handle from video_sink (xvimagesink).");

            guintptr handle = 0;
            Window xwindow = 0;

            #if defined(SDL_PLATFORM_LINUX) || defined(SDL_PLATFORM_FREEBSD) || defined(SDL_PLATFORM_OPENBSD)
                const char* video_driver = SDL_GetCurrentVideoDriver();
                if (video_driver && SDL_strcmp(video_driver, "x11") == 0) {
                    SDL_PropertiesID props = SDL_GetWindowProperties(self->sdl_window_.get());
                    if (props != 0) {
                        xwindow = (Window)SDL_GetNumberProperty(props, SDL_PROP_WINDOW_X11_WINDOW_NUMBER, 0);
                        if (xwindow != 0) {
                            handle = (guintptr)xwindow;
                            LOG_DEBUG("SDL3/X11: Providing Window ID: {}", handle);
                        } else {
                            LOG_ERROR("SDL3/X11: Failed to get {}", SDL_PROP_WINDOW_X11_WINDOW_NUMBER);
                        }
                    } else {
                        LOG_ERROR("Error: SDL_GetWindowProperties failed!");
                    }
                } else {
                    LOG_ERROR("Error: xvimagesink requires the SDL X11 video driver, but current driver is: {}", (video_driver ? video_driver : "null"));
                    return GST_BUS_PASS;
                }
            #else
                LOG_ERROR("Error: xvimagesink is only supported on X11 platforms (Linux/BSD).");
                return GST_BUS_PASS;
            #endif

            if (handle != 0) {
                gst_video_overlay_set_window_handle(GST_VIDEO_OVERLAY(self->sdl_sink_), handle);
                gst_message_unref(msg);
                return GST_BUS_DROP;
            } else {
                LOG_ERROR("Failed to get valid X11 window handle via SDL3 properties." );
                return GST_BUS_PASS;
            }
        } // End of prepare-window-handle check

        return GST_BUS_PASS;
    }

    GStreamerScreenReceiver(const GStreamerScreenReceiver&) = delete;
    GStreamerScreenReceiver& operator=(const GStreamerScreenReceiver&) = delete;
    GStreamerScreenReceiver(GStreamerScreenReceiver&&) = delete;
    GStreamerScreenReceiver& operator=(GStreamerScreenReceiver&&) = delete;


     void onVideoConfig(const APSHeader& header, float width,
                       float height, std::vector<uint8_t>& avccData) override {
        LOG_INFO("param[1][0]: {}", header.params[1].f32[0]);
        LOG_INFO("param[1][1]: {}", header.params[1].f32[1]);
        LOG_INFO("param[4][0]: {}", header.params[4].f32[0]);
        LOG_INFO("param[4][1]: {}", header.params[4].f32[1]);
        LOG_INFO("param[5][0]: {}", header.params[5].f32[0]);
        LOG_INFO("param[5][1]: {}", header.params[5].f32[1]);
        LOG_INFO("param[6][0]: {}", header.params[6].f32[1]);
        LOG_INFO("param[6][1]: {}", header.params[6].f32[1]);
        if (session_stopped_) return;
        if(width != this->width && height != this->height){
            SDL_SetWindowSize(sdl_window_.get(), width, height);
            if (!sdl_window_) {
                throw std::runtime_error(std::string("SDL_CreateWindow failed: ") + SDL_GetError());
            }
            GstCaps* caps = gst_caps_new_simple("video/x-h264",
                                                "width", G_TYPE_INT, (int)width,
                                                "height", G_TYPE_INT, (int)height,
                                                "stream-format", G_TYPE_STRING, "avc",
                                                "alignment", G_TYPE_STRING, "au",
                                                nullptr);
            if (!caps) {
                 LOG_ERROR("Failed to create GstCaps");
                 return;
            }
    
    
            if (!avccData.empty()) {
                GstBuffer* codec_buf =
                    gst_buffer_new_allocate(nullptr, avccData.size(), nullptr);
    
                if (codec_buf) {
                     gst_buffer_fill(codec_buf, 0, avccData.data(), avccData.size());
    
                     GValue codec_value = G_VALUE_INIT;
                     g_value_init(&codec_value, GST_TYPE_BUFFER);
                     gst_value_set_buffer(&codec_value, codec_buf);
    
                     gst_caps_set_value(caps, "codec_data", &codec_value);
    
                     g_value_unset(&codec_value);
    
                } else {
                     LOG_ERROR("Failed to allocate GstBuffer for codec_data");
                     gst_caps_unref(caps);
                     return;
                }
            }
    
            gst_app_src_set_caps(appsrc_, caps);
            gst_caps_unref(caps);
    
            // Set pipeline to PLAYING state now that caps are set
            if (gst_element_set_state(pipeline_.get(), GST_STATE_PLAYING) ==
                GST_STATE_CHANGE_FAILURE) {
                LOG_ERROR("Failed to set pipeline to PLAYING state.");
            } else {
                SDL_ShowWindow(sdl_window_.get());
                pipeline_ready_ = true;
                this->width = width;
                this->height = height;
            }
            SDL_SyncWindow(sdl_window_.get());
        } else {
            LOG_DEBUG("nothing to do");
        }
    }

    void onVideoData(const APSHeader& header,
                     std::vector<uint8_t>& data,
                     uint64_t displayTimestamp) override {
        if (!pipeline_ready_ || session_stopped_ || data.empty()) {
            return;
        }

        GstBuffer* buffer = gst_buffer_new_allocate(nullptr, data.size(), nullptr);
        if (!buffer) {
            LOG_ERROR("Failed to allocate GstBuffer for video data");
            return;
        }

        gst_buffer_fill(buffer, 0, data.data(), data.size());

        GST_BUFFER_PTS(buffer) = displayTimestamp;
        GST_BUFFER_DTS(buffer) = GST_CLOCK_TIME_NONE; // Let parser handle DTS if needed
        GST_BUFFER_DURATION(buffer) = GST_CLOCK_TIME_NONE; // Unknown duration

        GstFlowReturn ret = gst_app_src_push_buffer(appsrc_, buffer);

        if (ret != GST_FLOW_OK) {
            LOG_ERROR("Error pushing buffer to appsrc: {}", gst_flow_get_name(ret)
                    );
            if (ret == GST_FLOW_FLUSHING || ret == GST_FLOW_EOS) {
                pipeline_ready_ = false;
            }
        }
    }

    void onSessionStopped() override {
        if (appsrc_) {
            GstFlowReturn ret = gst_app_src_end_of_stream(appsrc_);
            if (ret != GST_FLOW_OK) {
                LOG_ERROR("Failed to send EOS to appsrc: {}", gst_flow_get_name(ret));
            } else {
                LOG_DEBUG("EOS sent to appsrc.");
            }
        }
        if (main_loop_) {
            g_main_loop_quit(main_loop_.get());
        }
        gst_bus_set_flushing(gst_element_get_bus(pipeline_.get()), true);
        gst_element_set_state (pipeline_.get(), GST_STATE_NULL);
        g_main_loop_quit( (GMainLoop *) main_loop_.get());
        gst_object_unref(appsrc_);
        pipeline_ready_ = false;
        if (session_stopped_.exchange(true)) {
            return;
        }
        LOG_INFO("AirPlay session stopped.");
    }

  private:
    void runMainLoop() {
        LOG_INFO("GStreamer main loop starting...");
        if (main_loop_) {
            GstBus* bus = gst_element_get_bus(pipeline_.get());
            if (bus) {
                gst_bus_add_watch(bus, busCallback, this);
                gst_object_unref(bus);
            } else {
                 LOG_ERROR("Failed to get pipeline bus.");
            }

            SDL_Event event;
            if(session_->isCarPlay){
                while(!session_stopped_.load()){
                    if (SDL_WaitEventTimeout(&event, 16) == 0) {
                        g_main_context_iteration(g_main_loop_get_context(main_loop_.get()), false);
                        continue;
                    }
                    switch(event.type){
                        case SDL_EVENT_WINDOW_CLOSE_REQUESTED:
                            LOG_DEBUG("SDL Event: {}", event.type);
                            break;
                        case SDL_EVENT_MOUSE_MOTION:
                        if(pipeline_ready_){
                            float x,y;
                            uint32_t buttonBitMask = SDL_GetMouseState(&x, &y);
                            if(SDL_BUTTON_LMASK ==  SDL_BUTTON_MASK(buttonBitMask)){
                                LOG_VERBOSE("Mouse LEFT clicked at: {}, {}", x, y);
                                std::map<std::string, boost::any> requestPlist;
                                requestPlist["uuid"] = static_cast<Plist::string_type>("0");
                                requestPlist["type"] = std::string("hidSendReport");
                                Plist::data_type report;
                                report.push_back(true);
                                report.push_back(static_cast<uint16_t>(x));
                                report.push_back(static_cast<uint16_t>(x) >> 8);
                                report.push_back(static_cast<uint16_t>(y));
                                report.push_back(static_cast<uint16_t>(y) >> 8);
                                requestPlist["hidReport"] = report;
                                std::vector<char> plistData;
                                Plist::writePlistBinary(plistData, requestPlist);
                                session_->sendEventCommand(plistData);
                            }
                        }
                        break;
                        case SDL_EVENT_MOUSE_BUTTON_DOWN:{
                            uint32_t buttonBitMask = event.button.button;
                            float x = event.button.x;
                            float y = event.button.y;
                            LOG_VERBOSE("Mouse button down: {}", buttonBitMask);
                            if(SDL_BUTTON_LMASK ==  SDL_BUTTON_MASK(buttonBitMask)){
                                LOG_VERBOSE("Mouse LEFT clicked down at: {}, {}", x, y);
                                std::map<std::string, boost::any> requestPlist;
                                requestPlist["uuid"] = static_cast<Plist::string_type>("0");
                                requestPlist["type"] = std::string("hidSendReport");
                                Plist::data_type report;
                                report.push_back(true);
                                report.push_back(static_cast<uint16_t>(x));
                                report.push_back(static_cast<uint16_t>(x) >> 8);
                                report.push_back(static_cast<uint16_t>(y));
                                report.push_back(static_cast<uint16_t>(y) >> 8);
                                requestPlist["hidReport"] = report;
                                std::vector<char> plistData;
                                Plist::writePlistBinary(plistData, requestPlist);
                                session_->sendEventCommand(plistData);
                            }
                            break;
                        }
                        case SDL_EVENT_MOUSE_BUTTON_UP:{
                            float x,y;
                            uint32_t buttonBitMask = event.button.button;
                            x = event.button.x;
                            y = event.button.y;
                            LOG_VERBOSE("Mouse button up: {}", buttonBitMask);
                            if(SDL_BUTTON_LMASK ==  SDL_BUTTON_MASK(buttonBitMask)){
                                LOG_VERBOSE("Mouse LEFT clicked up at: {}, {}", x, y);
                                std::map<std::string, boost::any> requestPlist;
                                requestPlist["uuid"] = static_cast<Plist::string_type>("0");
                                requestPlist["type"] = std::string("hidSendReport");
                                Plist::data_type report;
                                report.push_back(false);
                                report.push_back(static_cast<uint16_t>(x));
                                report.push_back(static_cast<uint16_t>(x) >> 8);
                                report.push_back(static_cast<uint16_t>(y));
                                report.push_back(static_cast<uint16_t>(y) >> 8);
                                requestPlist["hidReport"] = report;
                                std::vector<char> plistData;
                                Plist::writePlistBinary(plistData, requestPlist);
                                session_->sendEventCommand(plistData);
                            }
                            break;
                        }
                        default:
                            break;
                    }
                    g_main_context_iteration(g_main_loop_get_context(main_loop_.get()), false);
                }
            } else g_main_loop_run(main_loop_.get());
            SDL_DestroyWindow(sdl_window_.get());
            SDL_Quit();
        }
        LOG_INFO("GStreamer main loop finished.");

        if (pipeline_) {
            gst_element_set_state(pipeline_.get(), GST_STATE_NULL);
        }
    }

    static gboolean busCallback(GstBus* bus, GstMessage* msg, gpointer data) {
        GStreamerScreenReceiver* self =
            static_cast<GStreamerScreenReceiver*>(data);

        switch (GST_MESSAGE_TYPE(msg)) {
        case GST_MESSAGE_ERROR: {
            GError* err = nullptr;
            gchar* dbg_info = nullptr;
            gst_message_parse_error(msg, &err, &dbg_info);
            LOG_ERROR("GStreamer Error: {}", err->message);
            LOG_ERROR("Debugging info: {}", (dbg_info ? dbg_info : "none"));
            g_error_free(err);
            g_free(dbg_info);
            self->onSessionStopped();
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
                 gst_message_parse_state_changed(msg, &old_state, &new_state, &pending_state);
             }
             break;
        default:
            break;
        }

        return TRUE;
    }


    void cleanup() {
         onSessionStopped();
         if (main_loop_thread_.joinable()) {
             main_loop_thread_.join();
         }
    }

    GstElementUniquePtr pipeline_;
    GstAppSrc* appsrc_;
    GMainLoopUniquePtr main_loop_;
    std::thread main_loop_thread_;

    std::atomic<bool> pipeline_ready_{false};
    std::atomic<bool> session_stopped_;
    SDLWindowUniquePtr sdl_window_;
    GstElement* sdl_sink_;
    Session::APSession* session_;
    float width = 0;
    float height = 0;
};

} // namespace AirPlay
