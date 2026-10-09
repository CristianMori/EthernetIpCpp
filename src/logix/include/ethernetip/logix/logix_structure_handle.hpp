#pragma once

// Helpers for computing a Logix-style structure handle (the 16-bit value
// Template Object attribute 1 returns and the client sends as the
// `tag_type` on struct Read_Tag / Write_Tag).
//
// Status: provisional. Mirrors the C# LogixStructureHandle helper and the
// Rust logix_structure_handle module: build the FormalStrucTypeSpec byte
// stream from a TemplateDefinition per CIP Vol 1 Section C-6.1 /
// C-6.2.1 and hash it with the CIP 16-bit CRC
// (ethernetip::cip::cip_crc16, polynomial 0xA001).
//
// The algorithm has NOT been validated against a captured Studio 5000
// Read_Template reply for a non-trivial UDT, so callers who want this
// value opt in — TagDatabase::add_template still assigns the default
// 0x8000 | instance_id handle. Scope today is UDTs whose members are
// all scalar atomic types: nested structs, arrays, and packed scalar
// BOOLs each return std::nullopt so the server never ships a
// plausible-but-unverified handle on the wire.

#include "ethernetip/logix/tag_database.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace ethernetip::logix {

/// Build the FormalStrucTypeSpec byte stream for a UDT whose members are
/// all scalar atomic types. Returns std::nullopt when the template has
/// any member the simple encoding cannot represent (nested struct, array,
/// packed scalar BOOL, or an unknown data type).
///
/// Encoding format:
///   [0xA2][length][type_code_1][type_code_2]...[type_code_N]
/// where `length` counts the type_code bytes that follow (so the on-wire
/// size is 2 + length). Each atomic type is a single byte.
[[nodiscard]] std::optional<std::vector<uint8_t>>
try_build_formal_struc_spec(const TemplateDefinition& tmpl);

/// Compute the structure handle for an atomic-only UDT by hashing its
/// FormalStrucTypeSpec with the CIP 16-bit CRC. Returns std::nullopt
/// when try_build_formal_struc_spec rejects the template.
[[nodiscard]] std::optional<uint16_t>
try_compute_structure_handle(const TemplateDefinition& tmpl);

} // namespace ethernetip::logix
