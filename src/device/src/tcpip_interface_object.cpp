#include "ethernetip/device/tcpip_interface_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <array>
#include <cstring>

namespace ethernetip::device::tcpip_interface_object {

using namespace ethernetip::cip;

namespace {
// Parse "192.168.1.84" into 4 big-endian network bytes. Returns all zeros for
// "0.0.0.0" / empty.
std::array<uint8_t, 4> parse_ipv4(const std::string& dotted) {
    std::array<uint8_t, 4> out{};
    if (dotted.empty() || dotted == "0.0.0.0") return out;
    in_addr addr{};
    if (inet_pton(AF_INET, dotted.c_str(), &addr) == 1) {
        std::memcpy(out.data(), &addr, 4);
    }
    return out;
}
} // namespace

std::unique_ptr<CipClass> create(const std::string& bind_address) {
    auto cls = std::make_unique<CipClass>(0xF5u, "TCP/IP Interface", uint16_t{4});
    cls->add_standard_instance_services();
    CipInstance& inst = cls->create_instance(1);

    // Attribute 1: Status (UDINT) — 1 = interface configured.
    inst.add_attribute(CipAttribute::create_udint(
        1, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, 1u));
    // Attribute 2: Configuration Capability (UDINT) — 0x04 = DHCP capable.
    inst.add_attribute(CipAttribute::create_udint(
        2, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, 0x04u));
    // Attribute 3: Configuration Control (UDINT) — 0x02 = DHCP enabled.
    inst.add_attribute(CipAttribute::create_udint(
        3, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, 0x02u));

    // Attribute 5: Interface Configuration (IP + subnet + gateway + DNS + domain).
    std::vector<uint8_t> if_config(22);
    auto ip = parse_ipv4(bind_address);
    std::memcpy(if_config.data(), ip.data(), 4);
    if_config[4] = 255; if_config[5] = 255; if_config[6] = 255; if_config[7] = 0;
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{5}, CipDataType::Byte,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, std::move(if_config)));

    return cls;
}

} // namespace ethernetip::device::tcpip_interface_object
