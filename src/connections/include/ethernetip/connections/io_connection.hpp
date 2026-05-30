#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ethernetip::connections {

/// State of an I/O connection.
enum class ConnectionState {
    NonExistent,
    Established,
    TimedOut,
};

/// CIP transport class for I/O connections.
enum class TransportClass : uint8_t {
    Class0 = 0,
    Class1 = 1,
    Class6 = 6,   ///< CIP Safety transport
};

/// A single I/O connection established via Forward Open. Public fields are
/// mutable runtime state owned by the connection manager and the device.
struct IoConnection {
    // ---- Connection identity (the "connection triad") ----
    uint16_t connection_serial_number = 0;
    uint16_t originator_vendor_id = 0;
    uint32_t originator_serial_number = 0;

    // ---- Connection IDs on the wire ----
    uint32_t oto_t_connection_id = 0;   ///< O->T (scanner writes UDP to us with this ID)
    uint32_t tto_o_connection_id = 0;   ///< T->O (we write UDP to scanner with this ID)

    // ---- Assembly references ----
    uint32_t consumed_assembly_instance = 0;
    uint32_t produced_assembly_instance = 0;
    uint32_t config_assembly_instance = 0;

    /// Connection data from the Forward Open path's Simple Data Segment (0x80).
    /// Empty if the originator didn't include one. For a Generic Ethernet
    /// Module this is the config-assembly payload the PLC ships at FwdOpen.
    std::vector<uint8_t> config_data;

    // ---- Connection parameters ----
    uint32_t oto_t_rpi = 0;              ///< microseconds
    uint32_t tto_o_rpi = 0;              ///< microseconds
    uint16_t oto_t_size = 0;             ///< bytes on wire (includes seq count for Class 1)
    uint16_t tto_o_size = 0;
    TransportClass transport_class = TransportClass::Class1;
    uint8_t  timeout_multiplier = 0;     ///< 0=x4, 1=x8, ... 7=x512

    // ---- Network ----
    std::string remote_host;             ///< Originator's IPv4 dotted-decimal
    uint16_t    remote_port = 0;
    bool        remote_endpoint_set = false;

    // ---- Sequence tracking ----
    uint32_t encapsulation_sequence_number = 1;
    uint16_t cip_sequence_count = 0;

    // ---- Safety state (used only when is_safety = true) ----
    bool is_safety = false;
    uint8_t  safety_format = 0;          ///< 0=Base, 2=Extended (from safety segment byte)
    std::vector<uint8_t> safety_segment_data;

    // CRC seeds — precomputed once at FwdOpen time.
    uint8_t  safety_pid_seed_s1 = 0;
    uint16_t safety_pid_seed_s3 = 0;
    uint32_t safety_pid_seed_s5 = 0;
    uint8_t  safety_originator_pid_seed_s1 = 0;
    uint16_t safety_originator_pid_seed_s3 = 0;
    uint32_t safety_originator_pid_seed_s5 = 0;
    uint16_t safety_cid_seed_s3 = 0;
    uint32_t safety_cid_seed_s5 = 0;

    // Producer-side runtime state.
    bool     safety_consumer_active = false;
    uint16_t safety_timestamp = 0;
    uint16_t safety_rollover_count = 0;
    uint16_t safety_initial_timestamp = 0;
    uint16_t safety_initial_rollover_value = 0;
    uint16_t safety_last_produced_timestamp = 0;
    int64_t  safety_last_sent_ticks = 0;
    int64_t  safety_last_frame_sent_ticks = 0;
    int64_t  safety_production_start_ticks = 0;

    // Time-correction.
    uint16_t safety_connection_correction_constant = 0;
    uint16_t safety_consumer_time_correction_value = 0;
    uint16_t safety_consumer_time_correction_goal  = 0;
    bool     safety_time_correction_initialized = false;

    // Ping cadence.
    uint8_t  safety_ping_count = 0;
    uint8_t  safety_last_ping_count = 0xFF;     ///< 0xFF = unset sentinel
    int64_t  safety_ping_interval_us = 0;
    int64_t  safety_last_ping_change_ticks = 0;

    // Consumer-side runtime state.
    uint16_t safety_originator_rollover_count = 0;
    uint16_t safety_originator_last_ts = 0;
    bool     safety_originator_rollover_initialized = false;
    bool     safety_plc_running = false;

    // Diagnostics.
    int64_t  safety_startup_trace_until_ticks = 0;
    bool     safety_need_time_coordination = false;
    uint16_t safety_validator_instance_id = 0;

    // ---- State ----
    ConnectionState state = ConnectionState::Established;
    std::chrono::steady_clock::time_point last_received =
        std::chrono::steady_clock::now();

    /// Map a timeout multiplier code to its actual value (4, 8, 16, ..., 512).
    [[nodiscard]] static int multiplier_value(uint8_t code) noexcept;

    /// Computed connection timeout in microseconds (oto_t_rpi * multiplier).
    [[nodiscard]] int64_t connection_timeout_us() const noexcept;

    /// Mark the connection as closed.
    void close() noexcept { state = ConnectionState::NonExistent; }
};

} // namespace ethernetip::connections
