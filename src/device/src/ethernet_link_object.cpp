#include "ethernetip/device/ethernet_link_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"

namespace ethernetip::device::ethernet_link_object {

using namespace ethernetip::cip;

// Placeholder values — a future revision can query the host NIC matching
// bind_address (Win: GetAdaptersAddresses; POSIX: getifaddrs + AF_PACKET).
static const std::vector<uint8_t> kFallbackMac =
    {0x00, 0x1C, 0x2E, 0x00, 0x00, 0x01};
constexpr uint32_t kFallbackSpeedMbps = 1000;

// Bit flags: bit 0 = link up, bit 1 = full duplex, bits 2-4 = auto-neg ok = 4.
// 0x0F = link active + full duplex + auto-negotiation success.
constexpr uint32_t kDefaultFlags = 0x0F;

std::unique_ptr<CipClass> create(const std::string& /*bind_address*/) {
    auto cls = std::make_unique<CipClass>(0xF6u, "Ethernet Link", uint16_t{4});
    cls->add_standard_instance_services();
    CipInstance& inst = cls->create_instance(1);

    // Attribute 1: Interface Speed (UDINT) in Mbps.
    inst.add_attribute(CipAttribute::create_udint(
        1, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, kFallbackSpeedMbps));

    // Attribute 2: Interface Flags (UDINT).
    inst.add_attribute(CipAttribute::create_udint(
        2, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, kDefaultFlags));

    // Attribute 3: Physical Address (6-byte MAC, USINT array).
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{3}, CipDataType::Usint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, kFallbackMac));

    return cls;
}

} // namespace ethernetip::device::ethernet_link_object
