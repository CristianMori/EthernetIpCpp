#include "ethernetip/safety/safety_cpcrc.hpp"

#include "ethernetip/safety/safety_crc.hpp"

#include <cstring>
#include <stdexcept>
#include <vector>

namespace ethernetip::safety::cpcrc {

uint16_t encode_network_params(const connections::NetworkConnectionParams& p) {
    uint16_t raw = 0;
    if (p.redundant_owner) raw |= 0x8000;
    raw |= static_cast<uint16_t>((p.connection_type & 0x03) << 13);
    raw |= static_cast<uint16_t>((p.priority & 0x03) << 10);
    if (p.is_variable) raw |= 0x0200;
    raw |= static_cast<uint16_t>(p.connection_size & 0x01FFu);
    return raw;
}

uint32_t compute_from_raw(std::span<const uint8_t> sd,
                            std::span<const uint8_t> app_path,
                            std::span<const uint8_t> nsd,
                            uint8_t effective_path_size_words) {
    if (sd.size() < 36) {
        throw std::invalid_argument("CPCRC: raw service data needs at least 36 bytes");
    }
    if (nsd.size() != 48 && nsd.size() != 50) {
        throw std::invalid_argument("CPCRC: NSD must be 48 (Target) or 50 (Extended) bytes");
    }

    std::vector<uint8_t> buf(4 + 18 + app_path.size() + nsd.size());
    size_t off = 0;

    // conn_serial(2) + orig_vendor(2) from raw service data offset 10.
    std::memcpy(buf.data() + off, sd.data() + 10, 4); off += 4;
    // timeout/RPI/params/transport/path_size from raw service data offset 18.
    std::memcpy(buf.data() + off, sd.data() + 18, 18); off += 18;
    // Patch path_size (last byte of the 18-byte block) to the path the
    // target sees — without any route prefix.
    buf[off - 1] = effective_path_size_words;

    if (!app_path.empty()) {
        std::memcpy(buf.data() + off, app_path.data(), app_path.size());
        off += app_path.size();
    }
    std::memcpy(buf.data() + off, nsd.data(), nsd.size());
    off += nsd.size();

    return crc::compute_s4(std::span<const uint8_t>(buf.data(), off));
}

} // namespace ethernetip::safety::cpcrc
