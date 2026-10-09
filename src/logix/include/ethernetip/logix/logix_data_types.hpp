#pragma once

#include <cstdint>
#include <string_view>

namespace ethernetip::logix::logix_data_types {

/// Logix CIP tag type constants and helpers. Values match the Tag Type Service
/// Parameter from 1756-PM020.
///
/// Logix STRING is NOT the CIP STRING type (0xD0) — it's a predefined UDT:
///   LEN  (DINT, offset 0)         — current character count
///   DATA (SINT[82], offset 4)     — fixed-size ASCII array
///   total 88 bytes (4 + 82 + 2 padding)
/// When reading/writing a STRING tag, treat it as a structure, not as CIP
/// STRING (0xD0). The structure handle comes from the Template Object.

// --- Atomic tag type values (Read/Write Tag service parameter) ---
// Codes and widths come from CIP Vol 1 §C-6.1. Bit-string types
// (BYTE/WORD/DWORD/LWORD) share the byte width of the matching
// unsigned integer; the distinct type code lets the server-side
// tag_type check in Write_Tag round-trip exactly.
inline constexpr uint16_t Bool  = 0x00C1;  ///< 1 byte. Bit position encoded in upper nibble (0x0nC1).
inline constexpr uint16_t Sint  = 0x00C2;  ///< signed 8-bit, 1 byte
inline constexpr uint16_t Int   = 0x00C3;  ///< signed 16-bit, 2 bytes
inline constexpr uint16_t Dint  = 0x00C4;  ///< signed 32-bit, 4 bytes
inline constexpr uint16_t Lint  = 0x00C5;  ///< signed 64-bit, 8 bytes
inline constexpr uint16_t Usint = 0x00C6;  ///< unsigned 8-bit, 1 byte
inline constexpr uint16_t Uint  = 0x00C7;  ///< unsigned 16-bit, 2 bytes
inline constexpr uint16_t Udint = 0x00C8;  ///< unsigned 32-bit, 4 bytes
inline constexpr uint16_t Ulint = 0x00C9;  ///< unsigned 64-bit, 8 bytes
inline constexpr uint16_t Real  = 0x00CA;  ///< 32-bit IEEE float, 4 bytes
inline constexpr uint16_t Lreal = 0x00CB;  ///< 64-bit IEEE double, 8 bytes
inline constexpr uint16_t Byte  = 0x00D1;  ///< 8-bit bit string, 1 byte
inline constexpr uint16_t Word  = 0x00D2;  ///< 16-bit bit string, 2 bytes
inline constexpr uint16_t Dword = 0x00D3;  ///< 32-bit bit string, 4 bytes
inline constexpr uint16_t Lword = 0x00D4;  ///< 64-bit bit string, 8 bytes

// --- Logix STRING structure layout ---
inline constexpr int StringStructureSize = 88;
inline constexpr int StringLenOffset     = 0;
inline constexpr int StringDataOffset    = 4;
inline constexpr int StringMaxLength     = 82;

/// Size in bytes of an atomic tag type, or -1 for structures / unknown.
///
/// Covers the integer family (signed and unsigned), the IEEE float family,
/// and the bit-string family (BYTE/WORD/DWORD/LWORD). Variable-length
/// character and time/date types from CIP Vol 1 §C-6.1 are intentionally
/// rejected here — they are not elementary Logix tag types.
[[nodiscard]] constexpr int element_size(uint16_t tag_type) noexcept {
    switch (static_cast<uint16_t>(tag_type & 0x00FF)) {
        case 0xC1: return 1;  // BOOL
        case 0xC2: return 1;  // SINT
        case 0xC3: return 2;  // INT
        case 0xC4: return 4;  // DINT
        case 0xC5: return 8;  // LINT
        case 0xC6: return 1;  // USINT
        case 0xC7: return 2;  // UINT
        case 0xC8: return 4;  // UDINT
        case 0xC9: return 8;  // ULINT
        case 0xCA: return 4;  // REAL
        case 0xCB: return 8;  // LREAL
        case 0xD1: return 1;  // BYTE
        case 0xD2: return 2;  // WORD
        case 0xD3: return 4;  // DWORD
        case 0xD4: return 8;  // LWORD
        default:   return -1;
    }
}

/// Symbol type for an atomic tag. Bit 15=0; bits 14-13 encode array dims.
[[nodiscard]] constexpr uint16_t make_atomic_symbol_type(uint16_t tag_type,
                                                          int array_dims = 0) noexcept {
    uint16_t symbol = static_cast<uint16_t>(tag_type & 0x00FF);
    symbol = static_cast<uint16_t>(symbol | ((array_dims & 0x03) << 13));
    return symbol;
}

/// Symbol type for a structured tag. Bit 15=1; bits 0-11 = template instance.
[[nodiscard]] constexpr uint16_t make_struct_symbol_type(uint16_t template_instance_id,
                                                          int array_dims = 0) noexcept {
    uint16_t symbol = static_cast<uint16_t>(0x8000 | (template_instance_id & 0x0FFF));
    symbol = static_cast<uint16_t>(symbol | ((array_dims & 0x03) << 13));
    return symbol;
}

[[nodiscard]] constexpr bool is_struct(uint16_t symbol_type) noexcept {
    return (symbol_type & 0x8000) != 0;
}

[[nodiscard]] constexpr bool is_system(uint16_t symbol_type) noexcept {
    return (symbol_type & 0x1000) != 0;
}

[[nodiscard]] constexpr int array_dims(uint16_t symbol_type) noexcept {
    return (symbol_type >> 13) & 0x03;
}

[[nodiscard]] constexpr uint16_t template_id(uint16_t symbol_type) noexcept {
    return static_cast<uint16_t>(symbol_type & 0x0FFF);
}

/// Template name matches the predefined Logix STRING (may have ";..." suffix).
[[nodiscard]] inline bool is_logix_string(std::string_view template_name) noexcept {
    constexpr std::string_view expected = "STRING";
    if (template_name.size() < expected.size()) return false;
    for (size_t i = 0; i < expected.size(); ++i) {
        char a = static_cast<char>(template_name[i] | 0x20);
        char b = static_cast<char>(expected[i]      | 0x20);
        if (a != b) return false;
    }
    return template_name.size() == expected.size()
           || template_name[expected.size()] == ';';
}

} // namespace ethernetip::logix::logix_data_types
