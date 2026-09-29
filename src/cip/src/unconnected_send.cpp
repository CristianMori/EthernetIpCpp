#include "ethernetip/cip/unconnected_send.hpp"

#include <stdexcept>

namespace ethernetip::cip::unconnected_send {

namespace {
constexpr uint8_t kServiceCode = 0x52;
constexpr uint8_t kDefaultPriorityTick = 0x07;
constexpr uint8_t kDefaultTimeoutTicks = 0xF9;
constexpr uint8_t kConnectionManagerPath[] = {0x20, 0x06, 0x24, 0x01};
} // namespace

std::vector<uint8_t> build_inner_mr(uint8_t service_code,
                                     std::span<const uint8_t> path_bytes,
                                     std::span<const uint8_t> service_data) {
    if (path_bytes.size() % 2 != 0) {
        throw std::invalid_argument("path must be an even number of bytes");
    }
    std::vector<uint8_t> out;
    out.reserve(2 + path_bytes.size() + service_data.size());
    out.push_back(service_code);
    out.push_back(static_cast<uint8_t>(path_bytes.size() / 2));
    out.insert(out.end(), path_bytes.begin(), path_bytes.end());
    out.insert(out.end(), service_data.begin(), service_data.end());
    return out;
}

std::vector<uint8_t> wrap(std::span<const uint8_t> inner_mr,
                            std::span<const uint8_t> route_path) {
    if (route_path.empty()) {
        throw std::invalid_argument(
            "route path must not be empty; caller should send bare MR instead");
    }
    if (route_path.size() % 2 != 0) {
        throw std::invalid_argument("route path must be an even number of bytes");
    }
    size_t route_words = route_path.size() / 2;
    bool pad_embed = inner_mr.size() % 2 != 0;
    size_t us_len = 2 + 2 + inner_mr.size() + (pad_embed ? 1 : 0) + 2 + route_path.size();
    std::vector<uint8_t> us;
    us.reserve(us_len);
    us.push_back(kDefaultPriorityTick);
    us.push_back(kDefaultTimeoutTicks);
    us.push_back(static_cast<uint8_t>(inner_mr.size() & 0xFF));
    us.push_back(static_cast<uint8_t>((inner_mr.size() >> 8) & 0xFF));
    us.insert(us.end(), inner_mr.begin(), inner_mr.end());
    if (pad_embed) us.push_back(0);
    us.push_back(static_cast<uint8_t>(route_words));
    us.push_back(0);  // reserved
    us.insert(us.end(), route_path.begin(), route_path.end());

    std::vector<uint8_t> outer;
    outer.reserve(2 + sizeof(kConnectionManagerPath) + us.size());
    outer.push_back(kServiceCode);
    outer.push_back(static_cast<uint8_t>(sizeof(kConnectionManagerPath) / 2));
    outer.insert(outer.end(), std::begin(kConnectionManagerPath), std::end(kConnectionManagerPath));
    outer.insert(outer.end(), us.begin(), us.end());
    return outer;
}

} // namespace ethernetip::cip::unconnected_send
