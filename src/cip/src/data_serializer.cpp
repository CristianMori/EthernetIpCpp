#include "ethernetip/cip/data_serializer.hpp"

#include <algorithm>
#include <cstring>

namespace ethernetip::cip::serializer {

std::string read_short_string(std::span<const uint8_t> src) {
    uint8_t len = src[0];
    return std::string(reinterpret_cast<const char*>(src.data() + 1), len);
}

std::string read_string(std::span<const uint8_t> src) {
    uint16_t len = read_uint(src);
    return std::string(reinterpret_cast<const char*>(src.data() + 2), len);
}

int write_short_string(std::span<uint8_t> dst, std::string_view value) {
    uint8_t len = static_cast<uint8_t>(std::min<size_t>(value.size(), 255));
    dst[0] = len;
    if (len > 0) {
        std::memcpy(dst.data() + 1, value.data(), len);
    }
    return 1 + len;
}

int write_string(std::span<uint8_t> dst, std::string_view value) {
    uint16_t len = static_cast<uint16_t>(std::min<size_t>(value.size(), 0xFFFF));
    write_uint(dst, len);
    if (len > 0) {
        std::memcpy(dst.data() + 2, value.data(), len);
    }
    return 2 + len;
}

int fixed_size(CipDataType type) noexcept {
    switch (type) {
        case CipDataType::Bool:  return 1;
        case CipDataType::Sint:  return 1;
        case CipDataType::Int:   return 2;
        case CipDataType::Dint:  return 4;
        case CipDataType::Lint:  return 8;
        case CipDataType::Usint: return 1;
        case CipDataType::Uint:  return 2;
        case CipDataType::Udint: return 4;
        case CipDataType::Ulint: return 8;
        case CipDataType::Real:  return 4;
        case CipDataType::Lreal: return 8;
        case CipDataType::Byte:  return 1;
        case CipDataType::Word:  return 2;
        case CipDataType::Dword: return 4;
        case CipDataType::Lword: return 8;
        default:                 return -1;
    }
}

} // namespace ethernetip::cip::serializer
