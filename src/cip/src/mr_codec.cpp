#include "ethernetip/cip/mr_codec.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <cstring>
#include <stdexcept>

namespace ethernetip::cip::mr_codec {

std::optional<MrRequest> try_parse_request(std::span<const uint8_t> mr_data) {
    if (mr_data.size() < 2) {
        return std::nullopt;
    }
    MrRequest req;
    req.service_code     = mr_data[0];
    size_t path_size_bytes = static_cast<size_t>(mr_data[1]) * 2;

    if (mr_data.size() < 2 + path_size_bytes) {
        return std::nullopt;
    }
    auto [path, _] = CipPath::parse(mr_data.subspan(2, path_size_bytes));
    req.path = std::move(path);

    if (mr_data.size() > 2 + path_size_bytes) {
        auto payload = mr_data.subspan(2 + path_size_bytes);
        req.data.assign(payload.begin(), payload.end());
    }
    return req;
}

std::optional<MrResponse> try_parse_response(std::span<const uint8_t> mr_data) {
    if (mr_data.size() < 4) {
        return std::nullopt;
    }
    MrResponse resp;
    resp.reply_service             = mr_data[0];
    // mr_data[1] is reserved
    uint8_t general_status         = mr_data[2];
    uint8_t add_status_size_words  = mr_data[3];

    size_t add_status_bytes = static_cast<size_t>(add_status_size_words) * 2;
    if (mr_data.size() < 4 + add_status_bytes) {
        return std::nullopt;
    }

    std::vector<uint16_t> additional(add_status_size_words);
    for (size_t i = 0; i < add_status_size_words; ++i) {
        additional[i] = serializer::read_uint(mr_data.subspan(4 + i * 2));
    }
    resp.status = CipStatus{general_status, std::move(additional)};

    size_t data_offset = 4 + add_status_bytes;
    if (mr_data.size() > data_offset) {
        auto payload = mr_data.subspan(data_offset);
        resp.data.assign(payload.begin(), payload.end());
    }
    return resp;
}

int encode_request(std::span<uint8_t> dst, uint8_t service_code,
                   std::span<const uint8_t> path_bytes,
                   std::span<const uint8_t> data) {
    size_t required = 2 + path_bytes.size() + data.size();
    if (dst.size() < required) {
        throw std::invalid_argument("MR request encode: destination buffer too small");
    }
    size_t off = 0;
    dst[off++] = service_code;
    dst[off++] = static_cast<uint8_t>(path_bytes.size() / 2);  // path size in 16-bit words
    if (!path_bytes.empty()) {
        std::memcpy(dst.data() + off, path_bytes.data(), path_bytes.size());
        off += path_bytes.size();
    }
    if (!data.empty()) {
        std::memcpy(dst.data() + off, data.data(), data.size());
        off += data.size();
    }
    return static_cast<int>(off);
}

} // namespace ethernetip::cip::mr_codec
