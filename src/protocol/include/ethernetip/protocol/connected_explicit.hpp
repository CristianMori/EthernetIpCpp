#pragma once

#include "ethernetip/cip/cip_service.hpp"

#include <atomic>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ethernetip::protocol {

class EipScanner;  // forward

/// A Class 3 connected explicit messaging connection from the scanner side.
/// Backed by a Forward Open to the target's Message Router; subsequent
/// requests travel over TCP via SendUnitData (encap 0x70) instead of
/// SendRRData. The TagClient already uses UCMM for everything; this handle
/// exists for callers that want the connected-messaging behavior (longer
/// session lifetime, slightly different timeout semantics, and required for
/// some adapters that only accept Class 3 traffic post-FwdOpen).
class ConnectedExplicit {
public:
    ~ConnectedExplicit();
    ConnectedExplicit(const ConnectedExplicit&)            = delete;
    ConnectedExplicit& operator=(const ConnectedExplicit&) = delete;

    /// Send a request addressed by class + instance (+ optional attribute).
    /// Builds the EPATH for you via cip::build_path. For paths that need an
    /// element segment or symbolic name, drop to send_raw.
    cip::CipServiceResponse send(uint8_t service_code,
                                   uint32_t class_id, uint32_t instance_id,
                                   std::optional<uint16_t> attribute_id = {},
                                   std::span<const uint8_t> data = {});

    /// Send a request with an already-encoded EPATH (e.g. an ANSI symbolic
    /// segment or a multi-element logical path).
    cip::CipServiceResponse send_raw(uint8_t service_code,
                                       std::span<const uint8_t> path_bytes,
                                       std::span<const uint8_t> data = {});

    /// Close the underlying Class 3 connection (sends Forward Close).
    void close();

    [[nodiscard]] bool is_open() const noexcept { return open_.load(); }

    // ---- Internal API for EipScanner ----
    ConnectedExplicit(EipScanner& scanner,
                       uint32_t oto_t_connection_id,
                       uint32_t tto_o_connection_id,
                       uint16_t connection_serial,
                       uint16_t originator_vendor,
                       uint32_t originator_serial);

private:
    EipScanner& scanner_;
    uint32_t oto_t_connection_id_;
    uint32_t tto_o_connection_id_;
    uint16_t connection_serial_;
    uint16_t originator_vendor_;
    uint32_t originator_serial_;
    std::atomic<uint16_t> seq_count_{0};
    std::atomic<bool>     open_{true};
};

} // namespace ethernetip::protocol
