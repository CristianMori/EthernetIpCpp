#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ethernetip::cip::unconnected_send {

/// Build an inner MR = service + path_size_words + path + service_data.
/// path_bytes.size() must be even.
[[nodiscard]] std::vector<uint8_t> build_inner_mr(
    uint8_t service_code,
    std::span<const uint8_t> path_bytes,
    std::span<const uint8_t> service_data);

/// Wrap an inner MR into an Unconnected_Send (service 0x52) MR routed
/// through the Connection Manager (class 0x06, instance 1).  route_path
/// must be non-empty and an even number of bytes.  Byte-for-byte
/// compatible with the C#/Rust/Python UnconnectedSendBuilder helpers.
[[nodiscard]] std::vector<uint8_t> wrap(
    std::span<const uint8_t> inner_mr,
    std::span<const uint8_t> route_path);

} // namespace ethernetip::cip::unconnected_send
