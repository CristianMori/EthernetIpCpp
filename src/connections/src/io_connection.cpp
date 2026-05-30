#include "ethernetip/connections/io_connection.hpp"

namespace ethernetip::connections {

int IoConnection::multiplier_value(uint8_t code) noexcept {
    switch (code) {
        case 0: return 4;
        case 1: return 8;
        case 2: return 16;
        case 3: return 32;
        case 4: return 64;
        case 5: return 128;
        case 6: return 256;
        case 7: return 512;
        default: return 4;
    }
}

int64_t IoConnection::connection_timeout_us() const noexcept {
    return static_cast<int64_t>(oto_t_rpi) * multiplier_value(timeout_multiplier);
}

} // namespace ethernetip::connections
