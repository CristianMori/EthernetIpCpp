#pragma once

#include "ethernetip/connections/forward_open_request.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ethernetip::connections {

/// Result of parsing a Forward Open connection path. Carries the assembly
/// instance IDs needed for I/O setup plus the raw safety segment (if any).
struct ConnectionPathResult {
    std::optional<uint32_t> config_assembly_instance;
    std::optional<uint32_t> consumed_assembly_instance;   ///< O->T target instance
    std::optional<uint32_t> produced_assembly_instance;   ///< T->O target instance
    bool has_electronic_key = false;
    /// Raw 0x50 safety segment bytes (header + payload), or empty if not present.
    std::vector<uint8_t> safety_segment;
    /// Bytes from the Simple Data Segment (0x80), aka Connection Data. For a
    /// Generic Ethernet Module Forward Open these are the config assembly
    /// contents the PLC is pushing at connection setup.
    std::vector<uint8_t> config_data;
};

/// Parse the application portion of a Forward Open connection path.
///
/// Handles:
///  - Logix Emulate wrapper (class 0x04FC + connection point 0x01) — stripped automatically
///  - Electronic key segments (0x34) — skipped
///  - Standard assembly shortcut: 20 04 24 xx 2C yy 2C zz
///  - Safety 3-instance form: three class/instance pairs (config, OT, TO)
///  - Port, data, and network segments — skipped (except safety 0x50, which is captured)
[[nodiscard]] ConnectionPathResult
    parse_connection_path(std::span<const uint8_t> path,
                            const ForwardOpenRequest& request);

} // namespace ethernetip::connections
