#pragma once

#include <cstdint>
#include <string>

namespace ethernetip::cip {

/// Device identity information used in ListIdentity responses and the Identity
/// CIP object (class 0x01). All fields map to Identity Object instance 1
/// attributes.
struct IdentityInfo {
    static constexpr uint32_t ClassCode = 0x01;

    uint16_t vendor_id     = 0;       ///< attribute 1
    uint16_t device_type   = 0;       ///< attribute 2
    uint16_t product_code  = 0;       ///< attribute 3
    uint8_t  major_revision = 1;      ///< attribute 4 byte 0
    uint8_t  minor_revision = 0;      ///< attribute 4 byte 1
    uint16_t status         = 0;      ///< attribute 5
    uint32_t serial_number  = 0;      ///< attribute 6
    std::string product_name = "EthernetIPCpp Virtual Device";  ///< attribute 7 (SHORT_STRING)
};

} // namespace ethernetip::cip
