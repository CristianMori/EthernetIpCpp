#pragma once

#include "ethernetip/cip/cip_class.hpp"

#include <memory>
#include <string>

namespace ethernetip::device::tcpip_interface_object {

/// Create the CIP TCP/IP Interface Object (Class 0xF5) for the given bind
/// address. Minimal implementation — populates the attributes a PLC needs
/// during discovery + Forward Open. `bind_address` is dotted-decimal IPv4.
[[nodiscard]] std::unique_ptr<cip::CipClass> create(const std::string& bind_address);

} // namespace ethernetip::device::tcpip_interface_object
