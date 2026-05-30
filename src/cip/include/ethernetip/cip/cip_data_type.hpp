#pragma once

#include <cstdint>

namespace ethernetip::cip {

/// CIP data type codes used in attribute definitions and tag type parameters.
enum class CipDataType : uint16_t {
    Bool        = 0xC1,   ///< Boolean - 1 byte
    Sint        = 0xC2,   ///< Signed 8-bit
    Int         = 0xC3,   ///< Signed 16-bit
    Dint        = 0xC4,   ///< Signed 32-bit
    Lint        = 0xC5,   ///< Signed 64-bit
    Usint       = 0xC6,   ///< Unsigned 8-bit
    Uint        = 0xC7,   ///< Unsigned 16-bit
    Udint       = 0xC8,   ///< Unsigned 32-bit
    Ulint       = 0xC9,   ///< Unsigned 64-bit
    Real        = 0xCA,   ///< 32-bit IEEE float
    Lreal       = 0xCB,   ///< 64-bit IEEE double
    ShortString = 0xDA,   ///< 1 byte length + ASCII chars
    String      = 0xD0,   ///< 2 byte length (UINT) + ASCII chars
    Byte        = 0xD1,   ///< 8-bit bit string
    Word        = 0xD2,   ///< 16-bit bit string
    Dword       = 0xD3,   ///< 32-bit bit string
    Lword       = 0xD4,   ///< 64-bit bit string
};

} // namespace ethernetip::cip
