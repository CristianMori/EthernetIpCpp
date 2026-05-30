#include "ethernetip/cip/encapsulation.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <stdexcept>

namespace ethernetip::cip {

EncapsulationHeader EncapsulationHeader::parse(std::span<const uint8_t> data) {
    if (data.size() < static_cast<size_t>(Size)) {
        throw std::invalid_argument("Encapsulation header requires 24 bytes");
    }
    EncapsulationHeader h;
    h.command        = static_cast<EncapsulationCommand>(serializer::read_uint(data));
    h.length         = serializer::read_uint(data.subspan(2));
    h.session_handle = serializer::read_udint(data.subspan(4));
    h.status         = static_cast<EncapsulationStatus>(serializer::read_udint(data.subspan(8)));
    h.sender_context = serializer::read_ulint(data.subspan(12));
    h.options        = serializer::read_udint(data.subspan(20));
    return h;
}

int EncapsulationHeader::write_to(std::span<uint8_t> dst) const {
    serializer::write_uint (dst,             static_cast<uint16_t>(command));
    serializer::write_uint (dst.subspan(2),  length);
    serializer::write_udint(dst.subspan(4),  session_handle);
    serializer::write_udint(dst.subspan(8),  static_cast<uint32_t>(status));
    serializer::write_ulint(dst.subspan(12), sender_context);
    serializer::write_udint(dst.subspan(20), options);
    return Size;
}

} // namespace ethernetip::cip
