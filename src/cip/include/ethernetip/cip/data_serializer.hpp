#pragma once

#include "ethernetip/cip/cip_data_type.hpp"

#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace ethernetip::cip::serializer {

// All multi-byte CIP values are little-endian on the wire. These helpers do
// the byte work explicitly so the layer stays endian-independent.

namespace detail {
template <class T>
[[nodiscard]] inline T read_le(std::span<const uint8_t> src) noexcept {
    T value{};
    std::memcpy(&value, src.data(), sizeof(T));
    if constexpr (std::endian::native == std::endian::big) {
        // byteswap each octet — rarely needed on industrial targets
        auto* p = reinterpret_cast<uint8_t*>(&value);
        std::reverse(p, p + sizeof(T));
    }
    return value;
}

template <class T>
inline void write_le(std::span<uint8_t> dst, T value) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        auto* p = reinterpret_cast<uint8_t*>(&value);
        std::reverse(p, p + sizeof(T));
    }
    std::memcpy(dst.data(), &value, sizeof(T));
}
} // namespace detail

// ---- Readers: atomic ----
[[nodiscard]] inline bool     read_bool (std::span<const uint8_t> src) noexcept { return src[0] != 0; }
[[nodiscard]] inline int8_t   read_sint (std::span<const uint8_t> src) noexcept { return static_cast<int8_t>(src[0]); }
[[nodiscard]] inline int16_t  read_int  (std::span<const uint8_t> src) noexcept { return detail::read_le<int16_t>(src); }
[[nodiscard]] inline int32_t  read_dint (std::span<const uint8_t> src) noexcept { return detail::read_le<int32_t>(src); }
[[nodiscard]] inline int64_t  read_lint (std::span<const uint8_t> src) noexcept { return detail::read_le<int64_t>(src); }
[[nodiscard]] inline uint8_t  read_usint(std::span<const uint8_t> src) noexcept { return src[0]; }
[[nodiscard]] inline uint16_t read_uint (std::span<const uint8_t> src) noexcept { return detail::read_le<uint16_t>(src); }
[[nodiscard]] inline uint32_t read_udint(std::span<const uint8_t> src) noexcept { return detail::read_le<uint32_t>(src); }
[[nodiscard]] inline uint64_t read_ulint(std::span<const uint8_t> src) noexcept { return detail::read_le<uint64_t>(src); }
[[nodiscard]] inline float    read_real (std::span<const uint8_t> src) noexcept { return detail::read_le<float>(src); }
[[nodiscard]] inline double   read_lreal(std::span<const uint8_t> src) noexcept { return detail::read_le<double>(src); }

/// Read CIP SHORT_STRING: 1 byte length + ASCII chars.
[[nodiscard]] std::string read_short_string(std::span<const uint8_t> src);
/// Read CIP STRING: 2 byte length (UINT) + ASCII chars.
[[nodiscard]] std::string read_string(std::span<const uint8_t> src);

// ---- Writers: atomic (return bytes written) ----
inline int write_bool (std::span<uint8_t> dst, bool v)     noexcept { dst[0] = v ? uint8_t{1} : uint8_t{0}; return 1; }
inline int write_sint (std::span<uint8_t> dst, int8_t v)   noexcept { dst[0] = static_cast<uint8_t>(v); return 1; }
inline int write_int  (std::span<uint8_t> dst, int16_t v)  noexcept { detail::write_le(dst, v); return 2; }
inline int write_dint (std::span<uint8_t> dst, int32_t v)  noexcept { detail::write_le(dst, v); return 4; }
inline int write_lint (std::span<uint8_t> dst, int64_t v)  noexcept { detail::write_le(dst, v); return 8; }
inline int write_usint(std::span<uint8_t> dst, uint8_t v)  noexcept { dst[0] = v; return 1; }
inline int write_uint (std::span<uint8_t> dst, uint16_t v) noexcept { detail::write_le(dst, v); return 2; }
inline int write_udint(std::span<uint8_t> dst, uint32_t v) noexcept { detail::write_le(dst, v); return 4; }
inline int write_ulint(std::span<uint8_t> dst, uint64_t v) noexcept { detail::write_le(dst, v); return 8; }
inline int write_real (std::span<uint8_t> dst, float v)    noexcept { detail::write_le(dst, v); return 4; }
inline int write_lreal(std::span<uint8_t> dst, double v)   noexcept { detail::write_le(dst, v); return 8; }

/// Write CIP SHORT_STRING. Returns 1 + min(value.size(), 255).
int write_short_string(std::span<uint8_t> dst, std::string_view value);
/// Write CIP STRING. Returns 2 + min(value.size(), 0xFFFF).
int write_string(std::span<uint8_t> dst, std::string_view value);

/// Fixed size of a CIP data type, or -1 for variable-length types (strings).
[[nodiscard]] int fixed_size(CipDataType type) noexcept;

} // namespace ethernetip::cip::serializer
