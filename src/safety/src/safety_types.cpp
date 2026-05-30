#include "ethernetip/safety/safety_types.hpp"

#include "ethernetip/cip/data_serializer.hpp"

namespace ethernetip::safety {

namespace ser = ethernetip::cip::serializer;

void SafetyConfigurationId::copy_to(std::span<uint8_t> dst) const noexcept {
    ser::write_udint(dst, sccrc);
    scts.copy_to(dst.subspan(4));
}

SafetyConfigurationId SafetyConfigurationId::parse(std::span<const uint8_t> data) {
    SafetyConfigurationId out;
    out.sccrc = ser::read_udint(data);
    out.scts  = SafetyNetworkNumber(data.subspan(4, 6));
    return out;
}

void UniqueNetworkId::copy_to(std::span<uint8_t> dst) const noexcept {
    snn.copy_to(dst);
    ser::write_udint(dst.subspan(6), node_address);
}

UniqueNetworkId UniqueNetworkId::parse(std::span<const uint8_t> data) {
    UniqueNetworkId out;
    out.snn = SafetyNetworkNumber(data.subspan(0, 6));
    out.node_address = ser::read_udint(data.subspan(6));
    return out;
}

} // namespace ethernetip::safety
