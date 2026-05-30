#include "ethernetip/cip/cip_status.hpp"

#include "ethernetip/cip/data_serializer.hpp"

namespace ethernetip::cip {

int CipStatus::encode(std::span<uint8_t> dst) const {
    int offset = 0;
    dst[offset++] = general_status;
    dst[offset++] = static_cast<uint8_t>(additional_status.size());
    for (uint16_t s : additional_status) {
        serializer::write_uint(dst.subspan(offset), s);
        offset += 2;
    }
    return offset;
}

} // namespace ethernetip::cip
