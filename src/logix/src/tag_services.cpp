#include "ethernetip/logix/tag_services.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"

#include <algorithm>

namespace ethernetip::logix::tag_services {

using cip::CipServiceResponse;
using cip::CipStatus;
namespace ser = cip::serializer;

namespace {

// Structure tag marker on the wire. CIP Vol 1 §C-4.4.5: a Read_Tag reply for
// a structured tag leads with [A0 02][structure_handle (UINT)] followed by
// the raw structure bytes; a Write_Tag request uses the same prefix ahead
// of element_count and the data. Atomic tags carry only the 2-byte type code.
constexpr uint16_t kStructTypeIndicator = 0x02A0;

CipServiceResponse build_read_response_atomic(const Tag& tag, uint8_t service_code,
                                               int byte_offset, int data_length,
                                               bool is_partial, uint16_t type_code) {
    std::vector<uint8_t> out(2u + static_cast<size_t>(data_length));
    ser::write_uint(out, type_code);
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

CipServiceResponse build_read_response_struct(const Tag& tag, uint8_t service_code,
                                               int byte_offset, int data_length,
                                               bool is_partial, uint16_t struct_handle) {
    std::vector<uint8_t> out(4u + static_cast<size_t>(data_length));
    ser::write_uint(out, kStructTypeIndicator);
    auto handle_slot = std::span<uint8_t>(out).subspan(2);
    ser::write_uint(handle_slot, struct_handle);
    auto src = tag.get_data(byte_offset, data_length);
    std::copy(src.begin(), src.end(), out.begin() + 4);
    if (is_partial) {
        return CipServiceResponse{
            static_cast<uint8_t>(service_code | 0x80),
            CipStatus::error(0x06),
            std::move(out),
        };
    }
    return CipServiceResponse::success(service_code, std::move(out));
}

CipServiceResponse build_read_response(const Tag& tag, uint8_t service_code,
                                        int byte_offset, int data_length,
                                        bool is_partial) {
    if (logix_data_types::is_struct(tag.symbol_type())) {
        return build_read_response_struct(tag, service_code, byte_offset, data_length,
                                           is_partial, tag.tag_type());
    }
    return build_read_response_atomic(tag, service_code, byte_offset, data_length,
                                       is_partial, tag.tag_type());
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
    int prefix_len   = logix_data_types::is_struct(tag.symbol_type()) ? 4 : 2;
    int response_len = prefix_len + bytes_to_read;
    if (response_len > MaxReplyData) {
        int fit_bytes = MaxReplyData - prefix_len;
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
    uint16_t tag_type = ser::read_uint(data);

    uint16_t element_count = 0;
    int      header_len    = 0;

    if (logix_data_types::is_struct(tag.symbol_type())) {
        if (data.size() < 6) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        uint16_t struct_handle = ser::read_uint(data.subspan(2));
        element_count          = ser::read_uint(data.subspan(4));
        header_len             = 6;
        if (tag_type != kStructTypeIndicator || struct_handle != tag.tag_type()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    } else {
        element_count = ser::read_uint(data.subspan(2));
        header_len    = 4;
        if (tag_type != tag.tag_type()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    }

    int byte_offset    = element_offset * tag.element_size();
    int bytes_to_write = element_count * tag.element_size();
    if (static_cast<int>(data.size()) < header_len + bytes_to_write) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    if (byte_offset + bytes_to_write > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    tag.set_data(data.subspan(header_len, bytes_to_write), byte_offset);
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
    int prefix_len = logix_data_types::is_struct(tag.symbol_type()) ? 4 : 2;
    int remaining  = total_bytes - static_cast<int>(byte_offset);
    int chunk      = std::min(remaining, MaxReplyData - prefix_len);
    bool more      = static_cast<int>(byte_offset) + chunk < total_bytes;
    return build_read_response(tag, service_code, static_cast<int>(byte_offset),
                                chunk, /*is_partial=*/more);
}

CipServiceResponse handle_write_tag_fragmented(Tag& tag, uint8_t service_code,
                                                 std::span<const uint8_t> data) {
    if (data.size() < 8) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t tag_type = ser::read_uint(data);

    uint16_t element_count = 0;
    uint32_t byte_offset   = 0;
    int      header_len    = 0;

    if (logix_data_types::is_struct(tag.symbol_type())) {
        if (data.size() < 10) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        uint16_t struct_handle = ser::read_uint(data.subspan(2));
        element_count          = ser::read_uint(data.subspan(4));
        byte_offset            = ser::read_udint(data.subspan(6));
        header_len             = 10;
        if (tag_type != kStructTypeIndicator || struct_handle != tag.tag_type()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    } else {
        element_count = ser::read_uint(data.subspan(2));
        byte_offset   = ser::read_udint(data.subspan(4));
        header_len    = 8;
        if (tag_type != tag.tag_type()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    }

    int total_bytes = element_count * tag.element_size();
    int write_len   = static_cast<int>(data.size()) - header_len;
    if (byte_offset + static_cast<uint32_t>(write_len) > static_cast<uint32_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2104}));
    }
    tag.set_data(data.subspan(header_len, write_len), static_cast<int>(byte_offset));
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

// --- Walker-aware variants (gaps 2, 5, 6) ---

CipServiceResponse handle_read_tag_at(const Tag& tag, uint8_t service_code,
                                       std::span<const uint8_t> data,
                                       const WalkResult& w) {
    if (data.size() < 2) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t element_count = ser::read_uint(data);

    if (w.bit_pos.has_value()) {
        if (element_count != 1) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
        }
        uint8_t host = tag.get_data(w.offset, 1)[0];
        uint8_t bit = static_cast<uint8_t>((host >> *w.bit_pos) & 0x01);
        std::vector<uint8_t> reply(3);
        ser::write_uint(reply, static_cast<uint16_t>(0x00C1));   // BOOL
        reply[2] = bit;
        return CipServiceResponse::success(service_code, std::move(reply));
    }

    int bytes_to_read = element_count * w.element_size;
    if (w.offset + bytes_to_read > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }

    // Walker that ends on a nested struct member carries a non-null tpl and the
    // structure handle is on the template. Atomic members have a plain CIP
    // type code in w.type_code.
    bool as_struct = w.tpl != nullptr;
    int prefix_len = as_struct ? 4 : 2;
    bool partial = (prefix_len + bytes_to_read) > MaxReplyData;
    int take = partial ? (MaxReplyData - prefix_len) : bytes_to_read;

    if (as_struct) {
        return build_read_response_struct(tag, service_code, w.offset, take,
                                           partial, w.tpl->structure_handle());
    }
    return build_read_response_atomic(tag, service_code, w.offset, take,
                                       partial, w.type_code);
}

CipServiceResponse handle_write_tag_at(Tag& tag, uint8_t service_code,
                                        std::span<const uint8_t> data,
                                        const WalkResult& w) {
    if (data.size() < 4) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t tag_type = ser::read_uint(data);

    bool as_struct = w.tpl != nullptr;
    uint16_t element_count = 0;
    int      header_len    = 0;

    if (as_struct) {
        if (data.size() < 6) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        uint16_t struct_handle = ser::read_uint(data.subspan(2));
        element_count          = ser::read_uint(data.subspan(4));
        header_len             = 6;
        if (tag_type != kStructTypeIndicator || struct_handle != w.tpl->structure_handle()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    } else {
        element_count = ser::read_uint(data.subspan(2));
        header_len    = 4;
        if (tag_type != w.type_code) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    }

    if (w.bit_pos.has_value()) {
        if (element_count != 1 || static_cast<int>(data.size()) < header_len + 1) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        bool new_value = (data[header_len] & 0x01) != 0;
        tag.atomic_set_bit(w.offset, *w.bit_pos, new_value);
        return CipServiceResponse::success(service_code);
    }

    int bytes_to_write = element_count * w.element_size;
    if (static_cast<int>(data.size()) < header_len + bytes_to_write) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    if (w.offset + bytes_to_write > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    tag.set_data(data.subspan(header_len, bytes_to_write), w.offset);
    return CipServiceResponse::success(service_code);
}

} // namespace ethernetip::logix::tag_services
