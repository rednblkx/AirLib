#pragma once

#include "TLV8.hpp"
#include <cctype>      // For std::isprint
#include <cstddef>     // For size_t, SIZE_MAX
#include <cstdint>     // For uint8_t
#include <format>      // For std::formatter, std::format_to
#include <iterator>    // For std::back_inserter
#include <string>      // For std::string
#include <vector>      // For std::vector
#include <algorithm>   // For std::min

#include "external/plistcpp/Plist.hpp"

// --- Helper Namespace ---
namespace detail {

// Common hexdump formatting logic for byte-like vectors
template <typename ByteType, typename FormatContext>
auto format_byte_vector_hexdump(const std::vector<ByteType>& data,
                                FormatContext& ctx,
                                size_t width,
                                char presentation,
                                size_t limit) { // Added limit parameter
    auto out = ctx.out();
    if (data.empty()) {
        return std::format_to(out, "[empty vector]");
    }

    // Only implement hexdump for now
    if (presentation != 'x' && presentation != 'X') {
        return std::format_to(out, "[vector<ByteType> size={}]", data.size());
    }

    const size_t bytes_per_line = width;
    const size_t bytes_to_display = std::min(data.size(), limit); // Apply limit
    std::string ascii_repr;
    ascii_repr.reserve(bytes_per_line);

    for (size_t i = 0; i < bytes_to_display; ++i) { // Loop up to limit
        // Cast to uint8_t for consistent formatting and checking
        const uint8_t byte_value = static_cast<uint8_t>(data[i]);

        // Start of a new line: print offset
        if (i % bytes_per_line == 0) {
            if (i > 0) {
                // Print ASCII part of the previous line and newline
                out = std::format_to(out, " |{}|\n", ascii_repr);
                ascii_repr.clear();
            }
            // Offset (adjust format as needed, e.g., {:08X})
            out = std::format_to(out, "{:04X}: ", i);
        }

        // Print hex byte (using the casted value)
        out = std::format_to(out, "{:02X} ", byte_value);

        // Build ASCII representation (using the casted value)
        ascii_repr += (std::isprint(byte_value) ? static_cast<char>(byte_value)
                                                : '.');

        // Handle end of *displayed* data or end of line
        if (i == bytes_to_display - 1) {
            // Add padding if the last displayed line is not full
            size_t remaining_in_line =
                bytes_per_line - (i % bytes_per_line) - 1;
            for (size_t j = 0; j < remaining_in_line; ++j) {
                out = std::format_to(out, "   "); // 3 spaces for padding
            }
            // Print final ASCII part
            out = std::format_to(out, " |{}|", ascii_repr);
        }
    }

    // Add the summary line if data was truncated
    if (bytes_to_display < data.size()) {
        size_t remaining_bytes = data.size() - bytes_to_display;
        // Add newline before the summary if needed (if any bytes were printed)
        if (bytes_to_display > 0) {
             out = std::format_to(out, "\n");
        }
        out = std::format_to(out, "({} bytes left)", remaining_bytes);
    }

    return out;
}

// Common parsing logic
inline constexpr auto parse_hexdump_format_spec(std::format_parse_context& ctx,
                                                size_t& width,
                                                char& presentation,
                                                size_t& limit) { // Added limit
    auto it = ctx.begin(), end = ctx.end();
    limit = SIZE_MAX; // Default to no limit

    // Check if a width is specified
    if (it != end && *it >= '0' && *it <= '9') {
        size_t w = 0;
        do {
            w = w * 10 + (*it - '0');
            ++it;
        } while (it != end && *it >= '0' && *it <= '9');
        if (w > 0) { // Only accept positive width
            width = w;
        }
    }

    // Check for presentation format specifier
    if (it != end && (*it == 'x' || *it == 'X')) {
        presentation = *it;
        ++it;
    }

    // Check for limit specifier 'L'
    if (it != end && (*it == 'l' || *it == 'L')) {
        ++it; // Consume 'L'
        if (it != end && *it >= '0' && *it <= '9') {
            size_t lim_val = 0;
            do {
                lim_val = lim_val * 10 + (*it - '0');
                ++it;
            } while (it != end && *it >= '0' && *it <= '9');
            limit = lim_val; // Set the parsed limit
        } else {
            // Found 'L' but no digits followed
            throw std::format_error(
                "invalid limit specifier: 'L' must be followed by digits");
        }
    }

    // Check if reached the end of the format string
    if (it != end && *it != '}') {
        throw std::format_error("invalid format specifier for byte vector");
    }

    return it; // Return the iterator past the parsed specifiers
}

} // namespace detail

// --- std::formatter specializations ---
namespace std {

// Base struct to hold common members (optional, but reduces repetition)
struct byte_vector_formatter_base {
    char presentation = 'x';
    size_t width = 16;
    size_t limit = SIZE_MAX; // Use SIZE_MAX from <cstddef> for no limit

    constexpr auto parse(format_parse_context& ctx) {
        return detail::parse_hexdump_format_spec(ctx, width, presentation,
                                                 limit);
    }
};


// Specialization for std::vector<uint8_t>
template <>
struct formatter<std::vector<uint8_t>> : public byte_vector_formatter_base {
    template <typename FormatContext>
    auto format(const std::vector<uint8_t>& data, FormatContext& ctx) const {
        return detail::format_byte_vector_hexdump(data, ctx, width,
                                                  presentation, limit);
    }
};

// Specialization for std::vector<char>
template <>
struct formatter<std::vector<char>> : public byte_vector_formatter_base {
    template <typename FormatContext>
    auto format(const std::vector<char>& data, FormatContext& ctx) const {
        // Delegate to the common helper function
        return detail::format_byte_vector_hexdump(data, ctx, width,
                                                  presentation, limit);
    }
};

// --- std::formatter specialization for TLV ---
// Supports:
//   {}        - Default format (all bytes)
//   {L<N>}    - Limit total value bytes printed to N. Shows remaining count.

template <>
struct formatter<TLV8> : std::formatter<std::string_view> {
private:
    size_t byte_limit = std::numeric_limits<size_t>::max();

public:
    // Parse the format specifier (e.g., L100, <, >, ^, width, fill)
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx) {
        // Iterator for the format specifier range
        auto it = ctx.begin();
        auto end = ctx.end();

        // Default: no limit
        byte_limit = std::numeric_limits<size_t>::max();

        // Check specifically for 'L' at the current position
        if (it != end && *it == 'L') {
            ++it; // Consume 'L'
            if (it == end || !std::isdigit(static_cast<unsigned char>(*it))) {
                throw std::format_error(
                    "TLV format specifier 'L' must be followed by a number."
                );
            }

            // Use std::from_chars for safe integer parsing
            // We need a non-constexpr context for from_chars usually,
            // but parsing happens before formatting.
            const char* start_ptr = &(*it);
            // Find the end of the number sequence or the end of the specifier
            const char* num_end_ptr = start_ptr;
            while (num_end_ptr != &(*end) && std::isdigit(static_cast<unsigned char>(*num_end_ptr))) {
                ++num_end_ptr;
            }

            auto result = std::from_chars(start_ptr, num_end_ptr, byte_limit);

            if (result.ec == std::errc::invalid_argument) {
                throw std::format_error("Invalid number after 'L' specifier.");
            }
            if (result.ec == std::errc::result_out_of_range) {
                throw std::format_error("Byte limit number out of range.");
            }

            // Advance the main iterator past the parsed number
            auto distance = result.ptr - start_ptr;
            if (distance == 0) {
                 throw std::format_error("No digits found after 'L' specifier.");
            }
            std::advance(it, distance);
        }

        // Update the parse context to start from the current iterator position
        // (after potentially consuming 'L<N>')
        ctx.advance_to(it);
        // Call the base class's parse function to handle alignment, width, fill etc.
        return std::formatter<std::string_view>::parse(ctx);
    }

    // The format function performs the actual formatting.
    template <typename FormatContext>
    auto format(const TLV8& tlv, FormatContext& ctx) const {
        // --- Step 1: Build the TLV string representation internally ---
        // We'll format into a temporary string first, respecting byte_limit.
        std::string temp_output;
        // Reserve some space to potentially avoid reallocations
        temp_output.reserve(tlv.size() * 30); // Rough estimate

        // Use std::format_to with std::back_inserter to append to the string
        auto str_out_it = std::back_inserter(temp_output);

        size_t bytes_printed_count = 0;
        bool limit_hit = false;

        for (auto item_it = tlv.cbegin(); item_it != tlv.cend(); ++item_it) {
            const auto& item = *item_it;

            // Print Tag

            str_out_it = std::format_to(str_out_it, "Tag(0x{:02X})", item.tag);

            // Print Length
            str_out_it = std::format_to(str_out_it, "({}) ", item.length());

            // Print Value (respecting limit)
            if (limit_hit) {
                str_out_it = std::format_to(str_out_it, "...");
            } else {
                size_t bytes_available = (byte_limit == std::numeric_limits<size_t>::max())
                                             ? item.length()
                                             : byte_limit - bytes_printed_count;
                size_t bytes_to_print = std::min(item.length(), bytes_available);

                for (size_t i = 0; i < bytes_to_print; ++i) {
                    str_out_it = std::format_to(str_out_it, "{:02X}", item.value[i]);
                }
                bytes_printed_count += bytes_to_print;

                if (bytes_printed_count >= byte_limit) {
                     limit_hit = true; // Set limit_hit regardless of remaining bytes now
                     size_t remaining_in_current = item.length() - bytes_to_print;
                     size_t total_remaining = remaining_in_current;

                     // Calculate total remaining in subsequent items
                     for (auto next_it = std::next(item_it); next_it != tlv.cend(); ++next_it) {
                         total_remaining += next_it->length();
                     }

                     // Add summary only if there actually are remaining bytes
                     if (total_remaining > 0) {
                         str_out_it = std::format_to(
                             str_out_it,
                             " ... ({} byte{} follow)",
                             total_remaining,
                             (total_remaining == 1 ? "" : "s")
                         );
                     }
                }
            }

            // Add newline (append directly to string for simplicity here)
            temp_output += '\n';
        }

        // Remove trailing newline if the list wasn't empty
        if (!temp_output.empty() && temp_output.back() == '\n') {
            temp_output.pop_back();
        }

        // Use the base class's format function to apply standard formatting
        // to the string we just built.
        return std::formatter<std::string_view>::format(temp_output, ctx);
    }
};
} // namespace std

namespace Plist {
    // Forward declare the helper function (implementation below)
    template <typename FormatContext>
    typename FormatContext::iterator
    format_plist_any_recursive(const boost::any& value,
                               FormatContext& ctx,
                               int indent_level);
} // namespace Plist


namespace std {
    template <> struct formatter<Plist::dictionary_type>;
    template <> struct formatter<Plist::array_type>;
    template <> struct formatter<boost::any>;
} // namespace std

// --- Recursive Helper Implementation ---
namespace Plist {
    // --- Helper function for string escaping ---
    inline std::string escape_plist_string(const std::string& s) {
        std::string result;
        result.reserve(s.length());
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                default: result += c; break;
            }
        }
        return result;
    }

    template <typename FormatContext>
    typename FormatContext::iterator // Corrected return type
    format_plist_any_recursive(const boost::any& value,
                               FormatContext& ctx,
                               int indent_level) {
        auto out = ctx.out(); // Get the output iterator (type is FormatContext::iterator)

        if (value.empty()) {
            return std::format_to(out, "<empty>");
        }

        const std::type_info& type = value.type();
        const std::string current_indent(indent_level * 2, ' ');
        const std::string next_indent( (indent_level + 1) * 2, ' ');

        // --- Handle Plist Types ---
        if (type == typeid(Plist::string_type)) {
            return std::format_to(
                out, "\"{}\"",
                escape_plist_string(boost::any_cast<Plist::string_type>(value)));
        } else if (type == typeid(Plist::integer_type)) {
            return std::format_to(
                out, "{}", boost::any_cast<Plist::integer_type>(value));
        } else if (type == typeid(Plist::real_type)) {
            return std::format_to(out, "{}",
                                  boost::any_cast<Plist::real_type>(value));
        } else if (type == typeid(Plist::boolean_type)) {
            return std::format_to(
                out, "{}",
                boost::any_cast<Plist::boolean_type>(value) ? "true" : "false");
        } else if (type == typeid(Plist::date_type)) {
            try {
                return std::format_to(
                    out, "\"{}\"",
                    boost::any_cast<Plist::date_type>(value).timeAsEpoch());
            } catch (const std::exception&) {
                return std::format_to(out, "<date>");
            }
        } else if (type == typeid(Plist::data_type)) {
            const auto& data = boost::any_cast<Plist::data_type>(value);
             return std::format_to(out, "<data {} bytes>", data.size());
        } else if (type == typeid(Plist::array_type)) {
            const auto& arr = boost::any_cast<Plist::array_type>(value);
            if (arr.empty()) {
                return std::format_to(out, "[]");
            }
            out = std::format_to(out, "[\n");
            for (size_t i = 0; i < arr.size(); ++i) {
                out = std::format_to(out, "{}", next_indent);
                ctx.advance_to(out); // Update context's iterator position
                // Recursive call - result is assigned back to 'out'
                out = Plist::format_plist_any_recursive(arr[i], ctx, indent_level + 1);
                if (i < arr.size() - 1) {
                    out = std::format_to(out, ",\n");
                } else {
                    out = std::format_to(out, "\n");
                }
            }
            out = std::format_to(out, "{}]", current_indent);
            return out; // Return the final iterator position
        } else if (type == typeid(Plist::dictionary_type)) {
            const auto& dict = boost::any_cast<Plist::dictionary_type>(value);
            if (dict.empty()) {
                return std::format_to(out, "{{}}");
            }
            out = std::format_to(out, "{{\n");
            size_t count = 0;
            for (const auto& pair : dict) {
                out = std::format_to(out, "{}\"{}\": ", next_indent,
                                     escape_plist_string(pair.first));
                ctx.advance_to(out); // Update context's iterator position
                // Recursive call - result is assigned back to 'out'
                out = Plist::format_plist_any_recursive(pair.second, ctx, indent_level + 1);
                if (++count < dict.size()) {
                    out = std::format_to(out, ",\n");
                } else {
                    out = std::format_to(out, "\n");
                }
            }
            out = std::format_to(out, "{}}}", current_indent);
            return out; // Return the final iterator position
        } else {
            // --- Handle Unknown Types ---
            return std::format_to(out, "<unknown type: {}>", type.name());
        }
    }

} // namespace Plist

// --- Formatter Specializations ---
namespace std {

    // Formatter for Plist Dictionary
    template <>
    struct formatter<Plist::dictionary_type> {
        template <typename ParseContext>
        constexpr auto parse(ParseContext& ctx) {
             auto it = ctx.begin();
             while (it != ctx.end() && *it != '}') ++it;
             return it;
        }

        template <typename FormatContext>
        auto format(const Plist::dictionary_type& dict, FormatContext& ctx) const {
            auto out = ctx.out(); // Type is FormatContext::iterator
            if (dict.empty()) {
                return std::format_to(out, "{{}}");
            }

            out = std::format_to(out, "{{\n");
            const std::string indent(1 * 2, ' ');
            size_t count = 0;
            for (const auto& pair : dict) {
                out = std::format_to(out, "{}\"{}\": ", indent,
                                     Plist::escape_plist_string(pair.first));
                ctx.advance_to(out);
                out = Plist::format_plist_any_recursive(pair.second, ctx, 1);
                if (++count < dict.size()) {
                    out = std::format_to(out, ",\n");
                } else {
                    out = std::format_to(out, "\n");
                }
            }
            out = std::format_to(out, "}}");
            return out; // Return final iterator position
        }
    };

    // Formatter for Plist Array
    template <>
    struct formatter<Plist::array_type> {
        template <typename ParseContext>
        constexpr auto parse(ParseContext& ctx) {
             auto it = ctx.begin();
             while (it != ctx.end() && *it != '}') ++it;
             return it;
        }

        template <typename FormatContext>
        auto format(const Plist::array_type& arr, FormatContext& ctx) const {
            auto out = ctx.out(); // Type is FormatContext::iterator
            if (arr.empty()) {
                return std::format_to(out, "[]");
            }

            out = std::format_to(out, "[\n");
            const std::string indent(1 * 2, ' ');
            for (size_t i = 0; i < arr.size(); ++i) {
                out = std::format_to(out, "{}", indent);
                ctx.advance_to(out);
                // Call helper - result is assigned back to 'out'
                out = Plist::format_plist_any_recursive(arr[i], ctx, 1);
                if (i < arr.size() - 1) {
                    out = std::format_to(out, ",\n");
                } else {
                    out = std::format_to(out, "\n");
                }
            }
            out = std::format_to(out, "]");
            return out; // Return final iterator position
        }
    };

    // Formatter for boost::any
    template <>
    struct formatter<boost::any> {
        template <typename ParseContext>
        constexpr auto parse(ParseContext& ctx) {
             auto it = ctx.begin();
             while (it != ctx.end() && *it != '}') ++it;
             return it;
        }

        template <typename FormatContext>
        auto format(const boost::any& p, FormatContext& ctx) const {
            return Plist::format_plist_any_recursive(p, ctx, 0);
        }
    };

    template <>
    struct formatter<span<const unsigned char>> {
     template <typename ParseContext>
     constexpr auto parse(ParseContext& ctx) {
     return ctx.begin();
     }
    
   
     template <typename FormatContext>
     auto format(const span<const unsigned char>& span, FormatContext& ctx) const {
     auto out = ctx.out();
     for (const auto& byte : span) {
     out = format_to(out, "{:02X}", byte);
     }
     return out;
     }
    };


    template <size_t N>
    struct formatter<array<uint8_t, N>> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx) {
    return ctx.begin();
    }
    

    template <typename FormatContext>
    auto format(const array<uint8_t, N>& arr, FormatContext& ctx) const {
    auto out = ctx.out();
    for (const auto& byte : arr) {
    out = format_to(out, "{:02X}", byte);
    }
    return out;
    }
    };
} // namespace std

