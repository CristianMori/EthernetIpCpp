#include "ethernetip/cip/cip_crc.hpp"

namespace ethernetip::cip {

uint16_t cip_crc16(std::span<const uint8_t> data) noexcept {
    uint16_t crc = 0;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            bool carry = (crc & 1) != 0;
            crc = static_cast<uint16_t>(crc >> 1);
            if (carry) crc ^= 0xA001;
        }
    }
    return crc;
}

} // namespace ethernetip::cip
