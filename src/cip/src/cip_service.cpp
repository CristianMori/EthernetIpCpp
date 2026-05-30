#include "ethernetip/cip/cip_service.hpp"

#include <cstring>

namespace ethernetip::cip {

int CipServiceResponse::encode(std::span<uint8_t> dst) const {
    int offset = 0;
    dst[offset++] = service_code;
    dst[offset++] = 0;  // reserved
    offset += status.encode(dst.subspan(offset));
    if (!data.empty()) {
        std::memcpy(dst.data() + offset, data.data(), data.size());
        offset += static_cast<int>(data.size());
    }
    return offset;
}

} // namespace ethernetip::cip
