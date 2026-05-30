#pragma once

#include "ethernetip/safety/safety_types.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace ethernetip::safety {

/// Configuration for one direction of a CIP Safety connection — fed to
/// build_safety_forward_open(). Mirrors the C# SafetyForwardOpenConfig.
struct SafetyForwardOpenConfig {
    // Assembly references on the target side.
    uint32_t consumed_assembly = 0;
    uint32_t produced_assembly = 0;
    uint32_t config_assembly = 0;

    // Application data sizes (BEFORE safety framing).
    uint16_t consumed_data_size = 0;
    uint16_t produced_data_size = 0;

    // RPI (microseconds). rpi is the default, override per direction if needed.
    uint32_t rpi = 10000;
    uint32_t oto_t_rpi = 0;
    uint32_t tto_o_rpi = 0;

    SafetyFormat format = SafetyFormat::Base;

    UniqueNetworkId tunid{};
    UniqueNetworkId ounid{};
    SafetyConfigurationId scid{};

    uint16_t ping_interval_multiplier = 100;
    uint16_t time_coord_msg_min_multiplier = 50;
    uint16_t network_time_expectation_multiplier = 200;
    uint8_t  timeout_multiplier = 2;
    uint16_t max_fault_number = 2;

    uint16_t initial_timestamp = 0xFFFF;
    uint16_t initial_rollover_value = 0xFFFF;

    /// Forward-Open-level timeout multiplier (separate from the safety
    /// segment one). Default 1 → 8x.
    uint8_t connection_timeout_multiplier = 1;
    uint8_t priority_time_tick = 0x05;
    uint8_t timeout_ticks = 156;

    /// If non-zero, overrides the auto-computed wire size for that direction.
    uint16_t oto_t_connection_size = 0;
    uint16_t tto_o_connection_size = 0;
};

/// Standard Connection Manager request path (class 0x06, instance 1).
constexpr uint8_t CmPath[] = {0x20, 0x06, 0x24, 0x01};

/// Output of build_safety_forward_open.
struct SafetyForwardOpenWire {
    /// Forward Open service data (priority/tick through end of path,
    /// with CPCRC patched in).
    std::vector<uint8_t> service_data;
    /// Connection Manager request path (always {0x20, 0x06, 0x24, 0x01}).
    std::vector<uint8_t> cm_path;
};

/// Build the Forward Open service data for a safety connection. Uses the
/// "assembly shortcut" application path when `app_path` is empty.
///
///   transport_class_trigger: 0xA0 = server (target is consumer of our O->T data),
///                            0x20 = client (target is producer of T->O data).
///   route_prefix:           Port-segment bytes for routing (NOT included in CPCRC).
///   app_path:               Electronic key + assembly path (included in CPCRC).
///                            If empty, the standard 8-byte shortcut is used.
[[nodiscard]] SafetyForwardOpenWire
    build_safety_forward_open(const SafetyForwardOpenConfig& config,
                                uint16_t conn_serial,
                                uint16_t orig_vendor,
                                uint32_t orig_serial,
                                uint8_t  transport_class_trigger,
                                std::span<const uint8_t> route_prefix = {},
                                std::span<const uint8_t> app_path = {});

} // namespace ethernetip::safety
