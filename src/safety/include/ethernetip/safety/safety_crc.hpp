#pragma once

#include <cstdint>
#include <span>

namespace ethernetip::safety {

/// CIP Safety CRC computation routines. Five algorithms with precomputed
/// lookup tables. Runtime CRCs (S1, S2, S3, S5) are seeded by the
/// Producer/Consumer Identifier (PID/CID). Configuration CRCs (S4) use
/// fixed seeds (0xFFFFFFFF). Lookup tables match the HMS/IXXAT CSS
/// reference implementation.
namespace crc {

/// 8-bit, poly 0x37. Used for actual data CRC and timestamp CRC in base format.
[[nodiscard]] uint8_t  compute_s1(std::span<const uint8_t> data, uint8_t preset);

/// 8-bit, poly 0x3B. Used for complement data CRC in base format short packets.
[[nodiscard]] uint8_t  compute_s2(std::span<const uint8_t> data, uint8_t preset);

/// 16-bit, poly 0x080F. Used for base-format long data CRC and time coordination.
[[nodiscard]] uint16_t compute_s3(std::span<const uint8_t> data, uint16_t preset);
[[nodiscard]] uint16_t compute_s3_byte(uint8_t data, uint16_t preset);
[[nodiscard]] uint16_t compute_s3_u16(uint16_t data, uint16_t preset);

/// 32-bit CRC-32 reflected (poly 0xEDB88320). Used for CPCRC, SCCRC.
[[nodiscard]] uint32_t compute_s4(std::span<const uint8_t> data, uint32_t preset = 0xFFFFFFFFu);

/// 24-bit, poly 0x5D6DCB, XorOut 0x00FFFFFF. Final wire value — use for
/// the CRC field on the wire.
[[nodiscard]] uint32_t compute_s5(std::span<const uint8_t> data, uint32_t preset);

/// CRC-S5 WITHOUT XorOut. Used for seeds that feed further CRC steps.
[[nodiscard]] uint32_t compute_s5_raw(std::span<const uint8_t> data, uint32_t preset);

// ---- PID/CID seed computation ----
// CSS layout: vendId(2LE) + devSerNum(4LE) + cnxnSerNum(2LE) = 8 bytes, init=0.

[[nodiscard]] uint8_t  pid_cid_seed_s1(uint16_t vendor_id, uint32_t device_serial, uint16_t connection_serial);
[[nodiscard]] uint16_t pid_cid_seed_s3(uint16_t vendor_id, uint32_t device_serial, uint16_t connection_serial);
[[nodiscard]] uint32_t pid_cid_seed_s5(uint16_t vendor_id, uint32_t device_serial, uint16_t connection_serial);

/// Extended-format CRC seed = pid_seed_s3 chained over the rollover count.
[[nodiscard]] uint16_t pid_rollover_seed_s3(uint16_t rollover_count, uint16_t pid_seed_s3);
/// Extended-format CRC seed = pid_seed_s5 chained over the rollover count. Returns raw seed.
[[nodiscard]] uint32_t pid_rollover_seed_s5(uint16_t rollover_count, uint32_t pid_seed_s5);

} // namespace crc

} // namespace ethernetip::safety
