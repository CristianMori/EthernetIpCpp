#include "ethernetip/logix/tag_services.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <algorithm>

namespace ethernetip::logix::tag_services {

using cip::CipServiceResponse;
using cip::CipStatus;
namespace ser = cip::serializer;

namespace {

CipServiceResponse build_read_response(const Tag& tag, uint8_t service_code,
                                        int byte_offset, int data_length,
                                        bool is_partial) {
    std::vector<uint8_t> out(2u + static_cast<size_t>(data_length));
    ser::write_uint(out, tag.tag_type());
    auto src = tag.get_data(byte_offset, data_length);
    std::copy(src.begin(), src.end(), out.begin() + 2);
    if (is_partial) {
        return CipServiceResponse{
            static_cast<uint8_t>(service_code | 0x80),
            CipStatus::error(0x06),
            std::move(out),
        };
    }
    return CipServiceResponse::success(service_code, std::move(out));
}

} // namespace

CipServiceResponse handle_read_tag(const Tag& tag, uint8_t service_code,
                                    std::span<const uint8_t> data,
                                    int element_offset) {
    if (data.size() < 2) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t element_count = ser::read_uint(data);
    int byte_offset   = element_offset * tag.element_size();
    int bytes_to_read = element_count * tag.element_size();
    if (byte_offset + bytes_to_read > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int response_len = 2 + bytes_to_read;
    if (response_len > MaxReplyData) {
        int fit_bytes = MaxReplyData - 2;
        return build_read_response(tag, service_code, byte_offset, fit_bytes, /*is_partial=*/true);
    }
    return build_read_response(tag, service_code, byte_offset, bytes_to_read, /*is_partial=*/false);
}

CipServiceResponse handle_write_tag(Tag& tag, uint8_t service_code,
                                     std::span<const uint8_t> data,
                                     int element_offset) {
    if (data.size() < 4) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t tag_type      = ser::read_uint(data);
    uint16_t element_count = ser::read_uint(data.subspan(2));
    if (tag_type != tag.tag_type()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
    }
    int byte_offset    = element_offset * tag.element_size();
    int bytes_to_write = element_count * tag.element_size();
    if (static_cast<int>(data.size()) < 4 + bytes_to_write) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    if (byte_offset + bytes_to_write > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    tag.set_data(data.subspan(4, bytes_to_write), byte_offset);
    return CipServiceResponse::success(service_code);
}

CipServiceResponse handle_read_tag_fragmented(const Tag& tag, uint8_t service_code,
                                                std::span<const uint8_t> data) {
    if (data.size() < 6) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t element_count = ser::read_uint(data);
    uint32_t byte_offset   = ser::read_udint(data.subspan(2));
    int total_bytes = element_count * tag.element_size();
    if (byte_offset >= static_cast<uint32_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int remaining = total_bytes - static_cast<int>(byte_offset);
    int chunk     = std::min(remaining, MaxReplyData - 2);
    bool more     = static_cast<int>(byte_offset) + chunk < total_bytes;
    return build_read_response(tag, service_code, static_cast<int>(byte_offset),
                                chunk, /*is_partial=*/more);
}

CipServiceResponse handle_write_tag_fragmented(Tag& tag, uint8_t service_code,
                                                 std::span<const uint8_t> data) {
    if (data.size() < 8) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t tag_type      = ser::read_uint(data);
    uint16_t element_count = ser::read_uint(data.subspan(2));
    uint32_t byte_offset   = ser::read_udint(data.subspan(4));
    if (tag_type != tag.tag_type()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
    }
    int total_bytes = element_count * tag.element_size();
    int write_len   = static_cast<int>(data.size()) - 8;
    if (byte_offset + static_cast<uint32_t>(write_len) > static_cast<uint32_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2104}));
    }
    tag.set_data(data.subspan(8, write_len), static_cast<int>(byte_offset));
    return CipServiceResponse::success(service_code);
}

CipServiceResponse handle_read_modify_write(Tag& tag, uint8_t service_code,
                                              std::span<const uint8_t> data) {
    if (data.size() < 2) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t mask_size = ser::read_uint(data);
    if (mask_size != 1 && mask_size != 2 && mask_size != 4 && mask_size != 8 && mask_size != 12) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x03));
    }
    if (data.size() < static_cast<size_t>(2 + mask_size * 2)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    auto or_mask  = data.subspan(2, mask_size);
    auto and_mask = data.subspan(2u + mask_size, mask_size);
    int len = std::min<int>(mask_size, tag.data_size());
    std::vector<uint8_t> buf(len);
    auto src = tag.get_data(0, len);
    std::copy(src.begin(), src.end(), buf.begin());
    for (int i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>((buf[i] | or_mask[i]) & and_mask[i]);
    }
    tag.set_data(buf);
    return CipServiceResponse::success(service_code);
}

} // namespace ethernetip::logix::tag_services
