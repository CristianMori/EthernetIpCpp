#pragma once

#include <cstdint>
#include <span>

namespace ethernetip::cip {

/// Encapsulation command codes sent over TCP port 44818.
enum class EncapsulationCommand : uint16_t {
    Nop               = 0x0000,
    ListServices      = 0x0004,
    ListIdentity      = 0x0063,
    ListInterfaces    = 0x0064,
    RegisterSession   = 0x0065,
    UnregisterSession = 0x0066,
    SendRRData        = 0x006F,
    SendUnitData      = 0x0070,
};

/// Encapsulation status codes returned in the header.
enum class EncapsulationStatus : uint32_t {
    Success                    = 0x0000,
    InvalidCommand             = 0x0001,
    InsufficientMemory         = 0x0002,
    IncorrectData              = 0x0003,
    InvalidSessionHandle       = 0x0064,
    InvalidLength              = 0x0065,
    UnsupportedProtocolVersion = 0x0069,
};

/// 24-byte EtherNet/IP encapsulation header — all fields little-endian.
///
/// Wire layout:
///   0-1   Command
///   2-3   Length (bytes of payload following this header)
///   4-7   Session Handle
///   8-11  Status
///   12-19 Sender Context (opaque, echoed by target)
///   20-23 Options (must be 0)
struct EncapsulationHeader {
    static constexpr int Size = 24;

    EncapsulationCommand command       = EncapsulationCommand::Nop;
    uint16_t             length        = 0;
    uint32_t             session_handle = 0;
    EncapsulationStatus  status        = EncapsulationStatus::Success;
    uint64_t             sender_context = 0;
    uint32_t             options       = 0;

    /// Parse a 24-byte buffer. Throws std::invalid_argument if too short.
    [[nodiscard]] static EncapsulationHeader parse(std::span<const uint8_t> data);

    /// Write to a 24-byte buffer. Returns 24.
    int write_to(std::span<uint8_t> dst) const;
};

} // namespace ethernetip::cip
