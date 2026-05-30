#include "ethernetip/safety/safety_network_segment.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <cstring>
#include <stdexcept>

namespace ethernetip::safety {

namespace ser = ethernetip::cip::serializer;

int SafetyNetworkSegment::wire_size() const noexcept {
    switch (format) {
        case 0x00: return 56;
        case 0x01: return 14;
        case 0x02: return 62;
        default:   return 2;
    }
}

std::pair<SafetyNetworkSegment, int>
SafetyNetworkSegment::parse(std::span<const uint8_t> data) {
    if (data.size() < 3 || data[0] != SegmentType) {
        throw std::invalid_argument("Not a safety network segment");
    }
    uint8_t data_len_words = data[1];
    size_t  total = 2u + static_cast<size_t>(data_len_words) * 2;
    uint8_t format = data[2];

    if (data.size() < total) {
        throw std::invalid_argument("Safety segment buffer too small");
    }

    SafetyNetworkSegment seg;
    seg.format = format;

    if (format == 0x01) {  // Router format
        seg.time_correction_connection_id = ser::read_udint(data.subspan(4));
        seg.time_correction_epi           = ser::read_udint(data.subspan(8));
        seg.time_correction_params        = ser::read_uint (data.subspan(12));
        return {seg, static_cast<int>(total)};
    }

    // Target (0x00) and Extended (0x02) share the base layout.
    size_t off = 4;  // type + length + format + reserved pad
    seg.sccrc = ser::read_udint(data.subspan(off)); off += 4;
    std::memcpy(seg.scts.data(), data.data() + off, 6); off += 6;
    seg.time_correction_epi    = ser::read_udint(data.subspan(off)); off += 4;
    seg.time_correction_params = ser::read_uint (data.subspan(off)); off += 2;
    seg.tunid = UniqueNetworkId::parse(data.subspan(off)); off += UniqueNetworkId::Size;
    seg.ounid = UniqueNetworkId::parse(data.subspan(off)); off += UniqueNetworkId::Size;
    seg.ping_interval_multiplier             = ser::read_uint(data.subspan(off)); off += 2;
    seg.time_coord_msg_min_multiplier        = ser::read_uint(data.subspan(off)); off += 2;
    seg.network_time_expectation_multiplier  = ser::read_uint(data.subspan(off)); off += 2;
    seg.timeout_multiplier = data[off++];
    seg.max_consumer_number = data[off++];

    if (format == 0x02) {
        seg.max_fault_number = ser::read_uint(data.subspan(off)); off += 2;
    }
    seg.cpcrc                       = ser::read_udint(data.subspan(off)); off += 4;
    seg.time_correction_connection_id = ser::read_udint(data.subspan(off)); off += 4;
    if (format == 0x02) {
        seg.initial_time_stamp     = ser::read_uint(data.subspan(off)); off += 2;
        seg.initial_rollover_value = ser::read_uint(data.subspan(off)); off += 2;
    }

    return {seg, static_cast<int>(total)};
}

int SafetyNetworkSegment::encode(std::span<uint8_t> output) const {
    bool is_extended = (format == 0x02);
    uint8_t data_len_words = is_extended ? 0x1E : 0x1B;  // 30 or 27 words

    size_t off = 0;
    output[off++] = SegmentType;
    output[off++] = data_len_words;
    output[off++] = format;
    output[off++] = 0;  // reserved pad

    ser::write_udint(output.subspan(off), sccrc); off += 4;
    std::memcpy(output.data() + off, scts.data(), 6); off += 6;
    ser::write_udint(output.subspan(off), time_correction_epi); off += 4;
    ser::write_uint (output.subspan(off), time_correction_params); off += 2;
    tunid.copy_to(output.subspan(off)); off += UniqueNetworkId::Size;
    ounid.copy_to(output.subspan(off)); off += UniqueNetworkId::Size;
    ser::write_uint(output.subspan(off), ping_interval_multiplier); off += 2;
    ser::write_uint(output.subspan(off), time_coord_msg_min_multiplier); off += 2;
    ser::write_uint(output.subspan(off), network_time_expectation_multiplier); off += 2;
    output[off++] = timeout_multiplier;
    output[off++] = max_consumer_number;

    if (is_extended) {
        ser::write_uint(output.subspan(off), max_fault_number); off += 2;
    }
    ser::write_udint(output.subspan(off), cpcrc); off += 4;
    ser::write_udint(output.subspan(off), time_correction_connection_id); off += 4;
    if (is_extended) {
        ser::write_uint(output.subspan(off), initial_time_stamp); off += 2;
        ser::write_uint(output.subspan(off), initial_rollover_value); off += 2;
    }
    return static_cast<int>(off);
}

} // namespace ethernetip::safety
