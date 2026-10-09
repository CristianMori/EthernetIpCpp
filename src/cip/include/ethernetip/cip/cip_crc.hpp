#pragma once

#include <cstdint>
#include <span>

namespace ethernetip::cip {

/// CIP 16-bit CRC (polynomial 0xA001, initial 0, right-shift with XOR-back).
/// Same math as CRC-16/ARC (reversed 0x8005). Matches the reference
/// implementation in the CIP spec and passes its test vectors:
///   calc([A2 03 C7 C2 C3])                 = 0x5159
///   calc([A2 07 C7 A2 03 C7 C2 C3 C3])     = 0x26C7
[[nodiscard]] uint16_t cip_crc16(std::span<const uint8_t> data) noexcept;

} // namespace ethernetip::cip
