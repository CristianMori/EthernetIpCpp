#pragma once

#include "ethernetip/connections/forward_open_request.hpp"
#include "ethernetip/connections/io_connection.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace ethernetip::connections {

/// Hook implemented by SafetyDevice and attached to ConnectionManagerObject.
/// The connection manager defers safety-specific validation and configuration
/// to this interface so the connections layer stays oblivious to safety
/// internals.
class ISafetyConnectionHandler {
public:
    virtual ~ISafetyConnectionHandler() = default;

    /// Target identity emitted in the safety Application Reply.
    [[nodiscard]] virtual uint16_t vendor_id()    const = 0;
    [[nodiscard]] virtual uint32_t serial_number() const = 0;

    /// Validate a safety Forward Open before accepting.
    /// Returns std::nullopt to accept, or a CIP extended status code to reject.
    [[nodiscard]] virtual std::optional<uint16_t>
        validate_safety_open(std::span<const uint8_t> safety_segment,
                              const ForwardOpenRequest& fwd_open) = 0;

    /// Compute CRC seeds, validator-instance assignment, time-correction
    /// constant, and any other safety fields on the new connection.
    virtual void configure_safety_connection(IoConnection& conn,
                                              const ForwardOpenRequest& fwd_open) = 0;
};

} // namespace ethernetip::connections
