#pragma once

#include "ethernetip/safety/safety_types.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ethernetip::safety {

/// Result of decoding a safety frame.
struct SafetyDecodeResult {
    std::vector<uint8_t> actual_data;
    ModeByte mode{};
    uint16_t timestamp = 0;
    bool crc_valid = false;
    std::optional<std::string> error_message;

    [[nodiscard]] static SafetyDecodeResult make_error(std::string msg) {
        SafetyDecodeResult r;
        r.error_message = std::move(msg);
        return r;
    }
};

namespace frame_codec {

/// Total wire size for a safety frame given the actual data length.
[[nodiscard]] int wire_size(int data_length, SafetyFormat format);

/// Encode a safety data frame into output. Returns bytes written.
int encode(std::span<uint8_t> output, std::span<const uint8_t> actual_data,
            SafetyFormat format, ModeByte mode, uint16_t timestamp,
            uint8_t pid_seed_s1, uint16_t pid_seed_s3, uint32_t pid_seed_s5,
            uint16_t rollover_count = 0);

/// Extract the wire timestamp without CRC validation. Used by the consumer to
/// track the originator's rollover BEFORE the CRC check (which depends on it).
[[nodiscard]] uint16_t extract_timestamp(std::span<const uint8_t> input,
                                          int actual_data_length,
                                          SafetyFormat format);

/// Decode a safety data frame.
[[nodiscard]] SafetyDecodeResult decode(std::span<const uint8_t> input,
                                          int actual_data_length,
                                          SafetyFormat format,
                                          uint8_t pid_seed_s1, uint16_t pid_seed_s3,
                                          uint32_t pid_seed_s5,
                                          uint16_t rollover_count = 0);

/// Encode a Base-format TCOO (6 bytes). Returns 6.
int encode_time_coordination(std::span<uint8_t> output,
                              uint8_t ping_count_reply,
                              uint16_t consumer_time_value,
                              uint16_t cid_seed_s3);

/// Encode an Extended-format TCOO (6 bytes). Returns 6.
int encode_time_coordination_extended(std::span<uint8_t> output,
                                       uint8_t ping_count_reply,
                                       uint16_t consumer_time_value,
                                       uint32_t pid_seed_s5);

} // namespace frame_codec

} // namespace ethernetip::safety
