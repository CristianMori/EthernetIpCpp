#pragma once

#include "ethernetip/safety/safety_types.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace ethernetip::safety {

/// Safety Network Segment (0x50) parser/encoder for Forward Open paths.
/// Wire layout:  [0x50] [DataLengthWords] [Format] [SegmentData...]
/// Formats:
///   0x00 = Target Format (56 bytes total, 27 words data)
///   0x01 = Router Format (14 bytes total,  6 words data)
///   0x02 = Extended Format (62 bytes total, 30 words data)
struct SafetyNetworkSegment {
    static constexpr uint8_t SegmentType = 0x50;

    uint8_t  format = 0;
    uint32_t sccrc = 0;
    std::array<uint8_t, 6> scts{};
    uint32_t time_correction_epi = 0;
    uint16_t time_correction_params = 0;
    UniqueNetworkId tunid{};
    UniqueNetworkId ounid{};
    uint16_t ping_interval_multiplier = 0;
    uint16_t time_coord_msg_min_multiplier = 0;
    uint16_t network_time_expectation_multiplier = 0;
    uint8_t  timeout_multiplier = 0;
    uint8_t  max_consumer_number = 0;
    uint32_t cpcrc = 0;
    uint32_t time_correction_connection_id = 0;

    // Extended Format (0x02) only:
    uint16_t max_fault_number = 0;
    uint16_t initial_time_stamp = 0;
    uint16_t initial_rollover_value = 0;

    [[nodiscard]] int wire_size() const noexcept;

    /// Parse a safety segment starting at the 0x50 byte. Returns (segment, bytes_consumed).
    /// Throws std::invalid_argument on bad input.
    [[nodiscard]] static std::pair<SafetyNetworkSegment, int>
        parse(std::span<const uint8_t> data);

    /// Encode Target (0x00) or Extended (0x02) format. Returns bytes written.
    int encode(std::span<uint8_t> output) const;
};

} // namespace ethernetip::safety
