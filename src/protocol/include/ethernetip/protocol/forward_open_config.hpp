#pragma once

#include <cstdint>

namespace ethernetip::protocol {

/// Plain config record for ScannerConnection / EipScanner::forward_open.
/// All sizes are application data bytes (no headers).
struct ForwardOpenConfig {
    uint32_t consumed_assembly = 0;        ///< O->T target instance
    uint32_t produced_assembly = 0;        ///< T->O target instance
    uint32_t config_assembly   = 0;
    uint16_t consumed_size     = 0;        ///< O->T app data bytes
    uint16_t produced_size     = 0;        ///< T->O app data bytes
    uint32_t rpi               = 10000;    ///< RPI in microseconds (default 10 ms)
    uint8_t  transport_class   = 1;        ///< 0 or 1
    uint8_t  timeout_multiplier = 2;       ///< 0=x4, 1=x8, 2=x16, ...

    [[nodiscard]] bool is_class1() const noexcept { return transport_class == 1; }
};

} // namespace ethernetip::protocol
