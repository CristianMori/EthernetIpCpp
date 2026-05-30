#pragma once

#include "ethernetip/connections/io_connection.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace ethernetip::connections {

/// Parsed network connection parameters word/dword from a Forward Open.
///
/// 16-bit layout:
///   Bit 15: redundant owner
///   Bits 14-13: connection type (0=Null, 1=Multicast, 2=P2P)
///   Bits 12-10: priority
///   Bit 9: fixed(0) / variable(1)
///   Bits 8-0: connection size in bytes
///
/// 32-bit layout (Large Forward Open):
///   Bit 31: redundant owner
///   Bits 30-29: connection type
///   Bits 28-26: priority
///   Bit 25: fixed/variable
///   Bits 15-0: connection size in bytes
struct NetworkConnectionParams {
    bool     redundant_owner = false;
    uint8_t  connection_type = 0;
    uint8_t  priority = 0;
    bool     is_variable = false;
    uint16_t connection_size = 0;

    [[nodiscard]] bool is_null() const noexcept { return connection_type == 0; }

    [[nodiscard]] static NetworkConnectionParams parse_16(uint16_t raw);
    [[nodiscard]] static NetworkConnectionParams parse_32(uint32_t raw);
};

/// Parsed Forward Open / Large Forward Open request.
struct ForwardOpenRequest {
    uint8_t  priority_time_tick = 0;
    uint8_t  timeout_ticks = 0;
    uint32_t oto_t_connection_id = 0;
    uint32_t tto_o_connection_id = 0;
    uint16_t connection_serial_number = 0;
    uint16_t originator_vendor_id = 0;
    uint32_t originator_serial_number = 0;
    uint8_t  connection_timeout_multiplier = 0;
    uint32_t oto_t_rpi = 0;
    NetworkConnectionParams oto_t_params;
    uint32_t tto_o_rpi = 0;
    NetworkConnectionParams tto_o_params;
    uint8_t  transport_class_trigger = 0;
    uint8_t  connection_path_size_words = 0;
    std::vector<uint8_t> connection_path;
    bool     is_large_forward_open = false;

    /// Raw service-data bytes (priority/tick through end of path). Used by
    /// SafetyDevice for CPCRC validation — must reflect exact wire bytes.
    std::vector<uint8_t> raw_service_data;

    [[nodiscard]] TransportClass transport_class() const noexcept {
        return static_cast<TransportClass>(transport_class_trigger & 0x0F);
    }

    /// Parse a Forward Open request from the service data buffer.
    /// Throws std::invalid_argument if the buffer is too short.
    [[nodiscard]] static ForwardOpenRequest parse(std::span<const uint8_t> data,
                                                    bool is_large = false);
};

} // namespace ethernetip::connections
