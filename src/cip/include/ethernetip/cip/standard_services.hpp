#pragma once

#include "ethernetip/cip/cip_service.hpp"

#include <cstdint>

namespace ethernetip::cip::standard_services {

constexpr uint8_t GetAttributeAll    = 0x01;
constexpr uint8_t SetAttributeAll    = 0x02;
constexpr uint8_t GetAttributeList   = 0x03;
constexpr uint8_t SetAttributeList   = 0x04;
constexpr uint8_t Reset              = 0x05;
constexpr uint8_t GetAttributeSingle = 0x0E;
constexpr uint8_t SetAttributeSingle = 0x10;

/// Handle GetAttributeSingle (0x0E) — read one attribute by ID from the path.
CipServiceResponse handle_get_attribute_single(CipInstance& instance,
                                                const CipServiceRequest& request);

/// Handle SetAttributeSingle (0x10) — write one attribute by ID from the path.
CipServiceResponse handle_set_attribute_single(CipInstance& instance,
                                                const CipServiceRequest& request);

/// Handle GetAttributeAll (0x01) — return all gettable attributes in ID order.
CipServiceResponse handle_get_attribute_all(CipInstance& instance,
                                             const CipServiceRequest& request);

} // namespace ethernetip::cip::standard_services
