#include "ethernetip/cip/cip_service.hpp"

#include <cstring>

namespace ethernetip::cip {

int CipServiceResponse::encode(std::span<uint8_t> dst) const {
    // Full response size: reply_service(1) + reserved(1)
    //                   + general_status(1) + add_status_size(1)
    //                   + add_status(N*2) + data.
    const size_t needed =
        2u + 2u + 2u * status.additional_status.size() + data.size();
    if (needed > dst.size()) return -1;  // caller must handle overflow

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
