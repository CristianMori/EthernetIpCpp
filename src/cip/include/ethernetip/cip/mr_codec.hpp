#pragma once

#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/cip_status.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace ethernetip::cip {

/// Decoded MR request: service code, parsed EPATH, and the request payload.
struct MrRequest {
    uint8_t service_code = 0;
    CipPath path;
    std::vector<uint8_t> data;
};

/// Decoded MR response: reply service, status, and the response payload.
struct MrResponse {
    uint8_t reply_service = 0;
    CipStatus status;
    std::vector<uint8_t> data;
};

/// Pure codec for the CIP Message Router wire format.
///
/// Request:  service_code(1) + path_size_words(1) + path(N) + data
/// Response: reply_service(1) + reserved(1) + general_status(1) + add_status_size(1)
///           + add_status(N*2) + data
namespace mr_codec {

/// Parse an MR request. Returns std::nullopt if the buffer is too short.
[[nodiscard]] std::optional<MrRequest> try_parse_request(std::span<const uint8_t> mr_data);

/// Parse an MR response. Returns std::nullopt if the buffer is too short.
[[nodiscard]] std::optional<MrResponse> try_parse_response(std::span<const uint8_t> mr_data);

/// Encode an MR request into wire format. Returns bytes written.
/// Throws std::invalid_argument if dst is too small.
int encode_request(std::span<uint8_t> dst, uint8_t service_code,
                   std::span<const uint8_t> path_bytes,
                   std::span<const uint8_t> data);

} // namespace mr_codec

} // namespace ethernetip::cip
