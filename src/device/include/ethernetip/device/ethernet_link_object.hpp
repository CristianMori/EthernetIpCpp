#pragma once

#include "ethernetip/cip/cip_class.hpp"

#include <memory>
#include <string>

namespace ethernetip::device::ethernet_link_object {

/// Create the CIP Ethernet Link Object (Class 0xF6). Reports a placeholder
/// MAC + 1 Gbps speed — adequate for PLC discovery. Future improvement: query
/// the real host NIC by `bind_address`. `bind_address` is dotted-decimal IPv4
/// or empty for "any interface".
[[nodiscard]] std::unique_ptr<cip::CipClass> create(const std::string& bind_address = {});

} // namespace ethernetip::device::ethernet_link_object
