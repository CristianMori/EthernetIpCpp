#include "ethernetip/connections/forward_open_request.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <stdexcept>

namespace ethernetip::connections {

NetworkConnectionParams NetworkConnectionParams::parse_16(uint16_t raw) {
    return {
        .redundant_owner = (raw & 0x8000) != 0,
        .connection_type = static_cast<uint8_t>((raw >> 13) & 0x03),
        .priority        = static_cast<uint8_t>((raw >> 10) & 0x03),
        .is_variable     = (raw & 0x0200) != 0,
        .connection_size = static_cast<uint16_t>(raw & 0x01FF),
    };
}

NetworkConnectionParams NetworkConnectionParams::parse_32(uint32_t raw) {
    return {
        .redundant_owner = (raw & 0x80000000u) != 0,
        .connection_type = static_cast<uint8_t>((raw >> 29) & 0x03),
        .priority        = static_cast<uint8_t>((raw >> 26) & 0x03),
        .is_variable     = (raw & 0x02000000u) != 0,
        .connection_size = static_cast<uint16_t>(raw & 0xFFFFu),
    };
}

ForwardOpenRequest ForwardOpenRequest::parse(std::span<const uint8_t> data, bool is_large) {
    namespace ser = ethernetip::cip::serializer;
    const size_t min_size = is_large ? 40u : 36u;
    if (data.size() < min_size) {
        throw std::invalid_argument("Forward Open: data too short");
    }

    ForwardOpenRequest req;
    req.is_large_forward_open = is_large;

    size_t off = 0;
    req.priority_time_tick           = data[off++];
    req.timeout_ticks                = data[off++];
    req.oto_t_connection_id          = ser::read_udint(data.subspan(off)); off += 4;
    req.tto_o_connection_id          = ser::read_udint(data.subspan(off)); off += 4;
    req.connection_serial_number     = ser::read_uint(data.subspan(off));  off += 2;
    req.originator_vendor_id         = ser::read_uint(data.subspan(off));  off += 2;
    req.originator_serial_number     = ser::read_udint(data.subspan(off)); off += 4;
    req.connection_timeout_multiplier = data[off++];
    off += 3;                                       // 3 reserved bytes

    req.oto_t_rpi = ser::read_udint(data.subspan(off)); off += 4;

    if (is_large) {
        uint32_t ot_raw = ser::read_udint(data.subspan(off)); off += 4;
        req.oto_t_params = NetworkConnectionParams::parse_32(ot_raw);
        req.tto_o_rpi    = ser::read_udint(data.subspan(off)); off += 4;
        uint32_t to_raw  = ser::read_udint(data.subspan(off)); off += 4;
        req.tto_o_params = NetworkConnectionParams::parse_32(to_raw);
    } else {
        uint16_t ot_raw = ser::read_uint(data.subspan(off)); off += 2;
        req.oto_t_params = NetworkConnectionParams::parse_16(ot_raw);
        req.tto_o_rpi    = ser::read_udint(data.subspan(off)); off += 4;
        uint16_t to_raw  = ser::read_uint(data.subspan(off)); off += 2;
        req.tto_o_params = NetworkConnectionParams::parse_16(to_raw);
    }

    req.transport_class_trigger    = data[off++];
    req.connection_path_size_words = data[off++];
    size_t path_bytes = static_cast<size_t>(req.connection_path_size_words) * 2;

    if (off + path_bytes > data.size()) {
        throw std::invalid_argument("Forward Open: connection path truncated");
    }
    req.connection_path.assign(data.begin() + off,
                                data.begin() + off + path_bytes);

    // Raw service data covers offsets 0 .. (off + path_bytes), capturing the
    // exact wire bytes the PLC's CPCRC was computed over.
    req.raw_service_data.assign(data.begin(), data.begin() + off + path_bytes);

    return req;
}

} // namespace ethernetip::connections
