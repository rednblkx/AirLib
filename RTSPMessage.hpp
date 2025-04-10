#pragma once

#include "logger.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <sstream>
#include <string>
#include <vector>

inline std::string trim_whitespace(const std::string &s) {
  auto start = std::find_if_not(
      s.begin(), s.end(), [](unsigned char ch) { return std::isspace(ch); });
  auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char ch) {
               return std::isspace(ch);
             }).base();
  return (start < end ? std::string(start, end) : std::string());
}

class RTSPMessage {
public:
  // Request parts
  std::string method;
  std::string uri;
  std::string version = "RTSP/1.0";

  // Response parts
  int statusCode = 0;       // e.g., 200, 404
  std::string reasonPhrase; // e.g., "OK", "Not Found"

  // Common parts
  std::map<std::string, std::string> headers;
  std::vector<char> payload;
  int cseq = 0; // Sequence number

private:
  size_t parsedContentLength_ = 0;

public:
  RTSPMessage() = default;

  // --- State Management ---

  // Clears the message state to parse a new one
  void clear() {
    method.clear();
    uri.clear();
    version = "RTSP/1.0"; // Reset to default
    statusCode = 0;
    reasonPhrase.clear();
    headers.clear();
    payload.clear();
    cseq = 0;
    parsedContentLength_ = 0;
  }

  // --- Parsing Methods ---

  // Parses only the headers (request line + header fields)
  // Input string should contain everything up to (but not including)
  // the final empty line (\r\n).
  bool parseRequestHeader(const std::string &headers_part) {
    clear(); // Start fresh
    std::istringstream iss(headers_part);
    std::string line;

    // Parse Request Line (e.g., "SETUP rtsp://... RTSP/1.0")
    if (!std::getline(iss, line)) {
      LOG_ERROR("Error: Empty headers part.");
      return false;
    }
    // Remove trailing '\r' if present
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    std::stringstream requestLineStream(line);
    if (!(requestLineStream >> method >> uri >> version)) {
      LOG_ERROR("Error: Invalid RTSP request line format: {}", line);
      return false;
    }

    // Basic validation (can be extended)
    if (version.find("RTSP/") != 0) {
      LOG_ERROR("Error: Invalid RTSP version: {}", version);
      return false;
    }

    // Parse Header Fields
    while (std::getline(iss, line)) {
      // Remove trailing '\r' if present
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      // Stop if we hit an empty line (shouldn't happen with correct input)
      if (line.empty()) {
        break;
      }

      size_t colonPos = line.find(':');
      if (colonPos != std::string::npos) {
        std::string headerName = trim_whitespace(line.substr(0, colonPos));
        std::string headerValue = trim_whitespace(line.substr(colonPos + 1));

        if (!headerName.empty()) {
          headers[headerName] = headerValue;

          // Special handling for important headers
          if (headerName == "CSeq") {
            try {
              cseq = std::stoi(headerValue);
            } catch (const std::exception &e) {
              LOG_ERROR("Error: Invalid CSeq value '{}': {}", headerValue,
                        e.what());
              return false; // CSeq is mandatory and must be valid
            }
          } else if (headerName == "Content-Length") {
            try {
              parsedContentLength_ = std::stoull(headerValue);
            } catch (const std::exception &e) {
              LOG_ERROR("Error: Invalid Content-Length value '{}': {}",
                        headerValue, e.what());
              // Allow parsing to continue, but content length is invalid
              parsedContentLength_ = 0; // Treat as 0 if invalid
            }
          }
        }
      } else {
        LOG_WARN("Warning: Malformed header line (no colon): {}", line);
      }
    }

    // Check if CSeq was found (it's mandatory for requests)
    if (cseq == 0 && headers.find("CSeq") == headers.end()) {
      LOG_ERROR("Error: Mandatory CSeq header missing.");
      return false;
    }

    return true;
  }

  bool parseResponseHeader(const std::string &headers_part) {
    clear();
    std::istringstream iss(headers_part);
    std::string line;

    // Parse Status Line (e.g., "RTSP/1.0 200 OK")
    if (!std::getline(iss, line)) {
      LOG_ERROR("Error: Empty headers part.");
      return false;
    }

    // Remove trailing '\r' if present
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    std::stringstream statusLineStream(line);
    if (!(statusLineStream >> version >> statusCode >> reasonPhrase)) {
      LOG_ERROR("Error: Invalid RTSP response line format: {}", line);
      return false;
    }

    // Basic validation
    if (version.find("RTSP/") != 0) {
      LOG_ERROR("Error: Invalid RTSP version: {}", version);
      return false;
    }

    // Parse Header Fields
    while (std::getline(iss, line)) {
      // Remove trailing '\r' if present
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      // Stop if we hit an empty line (shouldn't happen with correct input)
      if (line.empty()) {
        break;
      }

      size_t colonPos = line.find(':');
      if (colonPos != std::string::npos) {
        std::string headerName = trim_whitespace(line.substr(0, colonPos));
        std::string headerValue = trim_whitespace(line.substr(colonPos + 1));

        if (!headerName.empty()) {
          headers[headerName] = headerValue;

          // Special handling for important headers
          if (headerName == "CSeq") {
            try {
              cseq = std::stoi(headerValue);
            } catch (const std::exception &e) {
              LOG_ERROR("Error: Invalid CSeq value '{}': {}", headerValue,
                        e.what());
              return false; // CSeq is mandatory and must be valid
            }
          } else if (headerName == "Content-Length") {
            try {
              parsedContentLength_ = std::stoull(headerValue);
            } catch (const std::exception &e) {
              LOG_ERROR("Error: Invalid Content-Length value '{}': {}",
                        headerValue, e.what());
              // Allow parsing to continue, but content length is invalid
              parsedContentLength_ = 0; // Treat as 0 if invalid
            }
          }
        }
      } else {
        LOG_WARN("Warning: Malformed header line (no colon): {}", line);
      }
    }

    // // Check if CSeq was found
    // if (cseq == 0 && headers.find("CSeq") == headers.end()) {
    //     LOG_ERROR("Error: CSeq header missing.");
    //     return false;
    // }
    return true;
  }

  // Parses the body based on previously parsed Content-Length
  bool parseBody(const std::vector<char> &body_data) {
    LOG_DEBUG("DEBUG: Entering parseBody. Body size: {}", body_data.size());
    // Check if the provided data size matches the expected size
    if (body_data.size() != parsedContentLength_) {
      LOG_WARN("Warning: Body size mismatch. Expected {} bytes, got {} bytes.",
               parsedContentLength_, body_data.size());
    }

    payload = body_data;
    return true;
  }

  // Parses a complete RTSP request from a raw buffer
  bool parseRequest(const std::vector<char> &raw_message) {
    clear(); // Reset the object state

    // Define the header separator sequence
    const char *header_separator = "\r\n\r\n";
    const size_t separator_len = 4;

    // Search for the separator in the raw message
    auto separator_it =
        std::search(raw_message.begin(), raw_message.end(), header_separator,
                    header_separator + separator_len);

    // Check if the separator was found
    if (separator_it == raw_message.end()) {
      LOG_ERROR("Error: Header separator (\\r\\n\\r\\n) not found in message.");
      return false;
    }

    // Extract the headers part as a string
    std::string header_part(raw_message.begin(), separator_it);

    LOG_DEBUG("DEBUG: Headers part: {}", header_part);

    // Parse the headers using the existing method
    if (!parseRequestHeader(header_part)) {
      LOG_ERROR("Error: Failed to parse headers section.");
      return false; // Header parsing failed
    }

    // Calculate the start of the body data
    auto body_start_it = separator_it + separator_len;
    size_t body_size = std::distance(body_start_it, raw_message.end());

    // Check if the actual body size matches the Content-Length header
    if (body_size != parsedContentLength_) {
      LOG_WARN("Warning: Actual body size ({}) does not match Content-Length "
               "header ({}).",
               body_size, parsedContentLength_);
    }

    // Extract the body payload
    payload.assign(body_start_it, raw_message.end());

    return true;
  }

  bool parseResponse(const std::vector<char> &raw_message) {
    clear(); // Reset the object state

    // Define the header separator sequence
    const char *header_separator = "\r\n\r\n";
    const size_t separator_len = 4;

    // Search for the separator in the raw message
    auto separator_it =
        std::search(raw_message.begin(), raw_message.end(), header_separator,
                    header_separator + separator_len);

    // Check if the separator was found
    if (separator_it == raw_message.end()) {
      LOG_ERROR("Error: Header separator (\\r\\n\\r\\n) not found in message.");
      return false;
    }

    // Extract the headers part as a string
    std::string headers_part(raw_message.begin(), separator_it);

    // Parse the headers using the existing method
    if (!parseResponseHeader(headers_part)) {
      LOG_ERROR("Error: Failed to parse headers section.");
      return false; // Header parsing failed
    }

    // Calculate the start of the body data
    auto body_start_it = separator_it + separator_len;
    size_t body_size = std::distance(body_start_it, raw_message.end());

    // Check if the actual body size matches the Content-Length header
    if (body_size != parsedContentLength_) {
      LOG_WARN("Warning: Actual body size ({}) does not match Content-Length "
               "header ({}).",
               body_size, parsedContentLength_);
    }

    // Extract the body payload
    payload.assign(body_start_it, raw_message.end());

    return true; // Parsing successful
  }

  // Returns the expected content length parsed from headers
  size_t getExpectedContentLength() const { return parsedContentLength_; }

  // --- Construction Method ---

  // Method to construct an RTSP response vector<char>
  std::vector<char> constructResponse() {
    std::stringstream oss;

    // Status Line (e.g., "RTSP/1.0 200 OK")
    if (statusCode == 0) { // Default to 200 OK if not set
      statusCode = 200;
      reasonPhrase = "OK";
    }
    if (reasonPhrase.empty()) { // Try to provide default phrases
      switch (statusCode) {
      case 200:
        reasonPhrase = "OK";
        break;
      case 400:
        reasonPhrase = "Bad Request";
        break;
      case 401:
        reasonPhrase = "Unauthorized";
        break;
      case 404:
        reasonPhrase = "Not Found";
        break;
      case 454:
        reasonPhrase = "Session Not Found";
        break;
      case 455:
        reasonPhrase = "Method Not Valid In This State";
        break;
      case 500:
        reasonPhrase = "Internal Server Error";
        break;
      case 501:
        reasonPhrase = "Not Implemented";
        break;
      default:
        reasonPhrase = "Unknown Status";
        break; // Fallback
      }
    }
    oss << "RTSP/1.0" << " " << statusCode << " " << reasonPhrase << "\r\n";

    // Headers
    // Ensure CSeq is present (it's mandatory in responses)
    headers["CSeq"] = std::to_string(cseq);
    // Ensure Content-Length matches the actual payload size
    if(!payload.empty())
      headers["Content-Length"] = std::to_string(payload.size());

    for (const auto &[key, value] : headers) {
      oss << key << ": " << value << "\r\n";
    }

    // End of Headers
    oss << "\r\n";
    
    // Get the header string
    std::string header_str = oss.str();

    // Combine headers and payload
    std::vector<char> response_vec;
    response_vec.reserve(header_str.length() + payload.size());
    response_vec.insert(response_vec.end(), header_str.begin(),
                        header_str.end());
    response_vec.insert(response_vec.end(), payload.begin(), payload.end());

    return response_vec;
  }

  // Method to construct an RTSP request vector<char>
  std::vector<char> constructRequest() {
    std::ostringstream oss;

    oss << method << " " << uri << " " << version << "\r\n";

    headers["Content-Length"] = std::to_string(payload.size());
    for (const auto &[key, value] : headers) {
      oss << key << ": " << value << "\r\n";
    }
    oss << "\r\n";

    // Get the header string
    std::string header_str = oss.str();

    // Combine headers and payload
    std::vector<char> request_vec;
    request_vec.reserve(header_str.length() + payload.size());
    request_vec.insert(request_vec.end(), header_str.begin(), header_str.end());
    request_vec.insert(request_vec.end(), payload.begin(), payload.end());

    return request_vec;
  }

  // --- Utility Method ---

  // Method to print the RTSP message (useful for debugging)
  void print() const {
    if (!method.empty()) { // Likely a request
      LOG_DEBUG("--- RTSP Request ---");
      LOG_DEBUG("{} {} {}", method, uri, version);
    } else if (statusCode != 0) { // Likely a response
      LOG_DEBUG("--- RTSP Response ---");
      LOG_DEBUG("{} {} {}", version, statusCode, reasonPhrase);
    } else {
      LOG_DEBUG("--- RTSP Message (Undetermined Type) ---");
    }

    for (const auto &[key, value] : headers) {
      LOG_DEBUG("{}: {}", key, value);
    }

    if (!payload.empty()) {
      LOG_DEBUG("Content-Length: {} (Actual)", payload.size());
      LOG_DEBUG("{:16xL128}", payload);
    } else {
      LOG_DEBUG("Payload: (empty)");
    }
    LOG_DEBUG("----------------");
  }
};