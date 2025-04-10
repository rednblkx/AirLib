#ifndef LOGGER_H
#define LOGGER_H

#include <atomic>
#include <chrono>
#include <format>
#include <iostream>
#include <memory> // For std::unique_ptr
#include <mutex>  // Re-include for synchronous fallback
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

// Boost.Asio includes (only needed if initialized)
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>

#include "formatters.hpp"

// Define Log Levels
enum class LogLevel { VERBOSE = 0, DEBUG = 1, INFO = 2, WARNING = 3, ERROR = 4 };

class Logger {
  public:
    // Delete copy/move constructors and assignment operators
    Logger(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger& operator=(Logger&&) = delete;

    // Get the singleton instance
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    // Initialize the logger with the Asio context for asynchronous logging.
    // If not called, the logger will operate synchronously.
    void init(boost::asio::io_context& ioc) {
        if (m_initialized.load()) {
            // Log a warning or just return if already initialized
            log(LogLevel::WARNING, std::source_location::current(),
                "Logger::init called multiple times. Ignoring subsequent calls.");
            return;
        }
        m_ioc = &ioc;
        // Create the strand associated with the provided io_context
        m_log_strand = std::make_unique<boost::asio::strand<
            boost::asio::io_context::executor_type>>(ioc.get_executor());
        m_initialized.store(true); // Enable asynchronous mode

        // Log initialization message (can be sync or async now)
        log(LogLevel::INFO, std::source_location::current(),
            "Logger initialized for asynchronous operation.");
    }

    // Set the minimum log level to output
    void setLevel(LogLevel level) { m_level.store(level); }

    // Get the current log level
    LogLevel getLevel() const { return m_level.load(); }

    // The core logging function (handles both sync and async)
    template <typename... Args>
    void log(LogLevel level,
             std::source_location location = std::source_location::current(),
             std::format_string<Args...> fmt = "",
             Args&&... args) {
        // --- Check level first ---
        if (level < m_level.load()) {
            return;
        }

        // --- Format the message (common to both paths) ---
        std::string message;
        try {
            message = std::format(fmt, std::forward<Args>(args)...);
        } catch (const std::format_error& e) {
            // Format error message itself synchronously to avoid recursion issues
            std::string error_msg = std::format(
                "!!! Formatting Error: {} !!! Original format string: {}",
                e.what(), fmt.get());
            logSync(LogLevel::ERROR, location, "{}", error_msg); // Use sync for errors
            return;
        }

        auto now = std::chrono::system_clock::now();
        // Using ISO 8601-like format for better sorting/parsing
        std::string timestamp = std::format("{:%Y-%m-%d %H:%M:%S}", now);
        std::string_view caller_name = trimFunctionName(location.function_name());
        std::string level_str = levelToString(level);
        bool is_multiline = (message.find('\n') != std::string::npos);

        // Create the final string payload
        std::string output = std::format(
            "[{}] [{}] [{}] {}{}", timestamp, level_str, caller_name,
            (is_multiline ? "\n" : " "), message);

        // --- Choose execution path ---
        if (m_initialized.load()) {
            // Asynchronous Path (Asio initialized)
            if (m_log_strand) {
                // Post the actual I/O to the Asio strand
                boost::asio::post(*m_log_strand, [out = std::move(output)]() {
                    // This runs on the Asio thread(s) within the strand
                    std::cout << out << std::endl;
                });
            } else {
                // This case should ideally not happen if m_initialized is true,
                // but fallback to sync just in case.
                logSyncRaw(output);
                logSync(LogLevel::ERROR, std::source_location::current(),
                        "Logger state error: Initialized but strand is null. "
                        "Logged synchronously.");
            }
        } else {
            // Synchronous Path (Asio not initialized - fallback)
            logSyncRaw(output);
        }
    }

  private:
    Logger() : m_level(LogLevel::INFO), m_initialized(false), m_ioc(nullptr) {}

    ~Logger() = default; // Note: Doesn't automatically wait for posted logs

    // --- Synchronous Logging Helpers ---

    // Logs a pre-formatted string synchronously using the mutex
    void logSyncRaw(const std::string& output) {
        std::lock_guard<std::mutex> lock(m_output_mutex);
        std::cout << output << std::endl;
    }

    // Formats and logs synchronously
    template <typename... Args>
    void logSync(LogLevel level,
                 std::source_location location,
                 std::format_string<Args...> fmt,
                 Args&&... args) {
        if (level < m_level.load()) return;

        std::string message;
        try {
             message = std::format(fmt, std::forward<Args>(args)...);
        } catch (const std::format_error& e) {
             message = std::format("!!! Internal Formatting Error: {} !!!", e.what());
        }

        auto now = std::chrono::system_clock::now();
        std::string timestamp = std::format("{:%Y-%m-%d %H:%M:%S}", now);
        std::string_view caller_name = trimFunctionName(location.function_name());
        std::string level_str = levelToString(level);
        bool is_multiline = (message.find('\n') != std::string::npos);
        std::string output = std::format(
            "[{}] [{}] [{}] {}{}", timestamp, level_str, caller_name,
            (is_multiline ? "\n" : " "), message);

        logSyncRaw(output); // Use the raw sync helper
    }


    // --- Helper Functions ---

    // Helper to trim function name
    static std::string_view
    trimFunctionName(std::string_view full_name) noexcept {
        // ... (implementation remains the same)
        size_t params_pos = full_name.find('(');
        if (params_pos == std::string_view::npos) {
            params_pos = full_name.length();
        }
        std::string_view name_and_prefix = full_name.substr(0, params_pos);
        size_t last_space_pos = name_and_prefix.rfind(' ');
        std::string_view candidate =
            (last_space_pos == std::string_view::npos)
                ? name_and_prefix
                : name_and_prefix.substr(last_space_pos + 1);
        size_t last_colon_pos = candidate.rfind("::");
        if (last_colon_pos == std::string_view::npos) {
            return candidate;
        }
        size_t prev_colon_pos = (last_colon_pos > 0)
                                    ? candidate.rfind("::", last_colon_pos - 1)
                                    : std::string_view::npos;
        if (prev_colon_pos == std::string_view::npos) {
            return candidate;
        } else {
            return candidate.substr(prev_colon_pos + 2);
        }
    }

    // Helper to convert level to string (same as before)
    static std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::VERBOSE: return "VERBOSE";
            default: return "UNKNOWN";
        }
    }

    // --- Member Variables ---
    std::atomic<LogLevel> m_level;
    std::atomic<bool> m_initialized; // Flag to check if init was called

    // Asio components (only used if initialized)
    boost::asio::io_context* m_ioc;
    std::unique_ptr<boost::asio::strand<
        boost::asio::io_context::executor_type>> m_log_strand;

    // Mutex for synchronous fallback logging
    std::mutex m_output_mutex;
};

// --- Convenience Macros (Unchanged) ---
#define LOG_VERBOSE(fmt, ...)                                                    \
    Logger::getInstance().log(LogLevel::VERBOSE, std::source_location::current(), \
                              fmt __VA_OPT__(, ) __VA_ARGS__)
#define LOG_DEBUG(fmt, ...)                                                    \
    Logger::getInstance().log(LogLevel::DEBUG, std::source_location::current(), \
                              fmt __VA_OPT__(, ) __VA_ARGS__)
#define LOG_INFO(fmt, ...)                                                     \
    Logger::getInstance().log(LogLevel::INFO, std::source_location::current(), \
                              fmt __VA_OPT__(, ) __VA_ARGS__)
#define LOG_WARN(fmt, ...)                                                     \
    Logger::getInstance().log(LogLevel::WARNING,                               \
                              std::source_location::current(),                 \
                              fmt __VA_OPT__(, ) __VA_ARGS__)
#define LOG_ERROR(fmt, ...)                                                    \
    Logger::getInstance().log(LogLevel::ERROR,                                 \
                              std::source_location::current(),                 \
                              fmt __VA_OPT__(, ) __VA_ARGS__)

#endif // LOGGER_H