#include "ethernetip/logix/tag_services.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

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
    // element_offset is bounded by INT32_MAX upstream, but
    // element_offset * element_size() can still overflow a signed int
    // (e.g. 2^30 * 8). Widen to int64_t, verify the result fits in int
    // AND inside the tag buffer, then narrow.
    int64_t byte_offset_wide = static_cast<int64_t>(element_offset) * tag.element_size();
    int64_t bytes_to_read_wide =
        static_cast<int64_t>(element_count) * tag.element_size();
    if (byte_offset_wide < 0 || bytes_to_read_wide < 0 ||
        byte_offset_wide > std::numeric_limits<int>::max() ||
        bytes_to_read_wide > std::numeric_limits<int>::max()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int byte_offset   = static_cast<int>(byte_offset_wide);
    int bytes_to_read = static_cast<int>(bytes_to_read_wide);
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

    // element_offset is bounded by INT32_MAX upstream, but
    // element_offset * element_size() can still overflow a signed int.
    // Compute wide, bounds-check, then narrow.
    int64_t byte_offset_wide = static_cast<int64_t>(element_offset) * tag.element_size();
    int64_t bytes_to_write_wide =
        static_cast<int64_t>(element_count) * tag.element_size();
    if (byte_offset_wide < 0 || bytes_to_write_wide < 0 ||
        byte_offset_wide > std::numeric_limits<int>::max() ||
        bytes_to_write_wide > std::numeric_limits<int>::max()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int byte_offset    = static_cast<int>(byte_offset_wide);
    int bytes_to_write = static_cast<int>(bytes_to_write_wide);

    // pycomm3 writes SHORT_STRING as [length_byte][chars] with no fixed-slot
    // padding, so the payload is 1 + N bytes rather than the full 81-byte
    // element.  Accept the shorter write and pad the remainder of the slot
    // with zeros so Read_Tag returns the same value back.  Studio 5000 does
    // the same on Identity attribute 7, which is the only place real Logix
    // actually exposes SHORT_STRING; application tags of this type are a
    // convenience the server adds on top.
    if (tag_type == 0x00DA && static_cast<int>(data.size()) >= header_len + 1) {
        int provided        = static_cast<int>(data.size()) - header_len;
        uint8_t length_byte = data[static_cast<size_t>(header_len)];
        int expected_short  = 1 + static_cast<int>(length_byte);
        if (provided >= expected_short && provided < bytes_to_write) {
            if (byte_offset + bytes_to_write > tag.data_size()) {
                return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
            }
            std::vector<uint8_t> padded(static_cast<size_t>(bytes_to_write), 0);
            std::memcpy(padded.data(),
                        data.data() + header_len,
                        static_cast<size_t>(provided));
            tag.set_data(std::span<const uint8_t>(padded), byte_offset);
            return CipServiceResponse::success(service_code);
        }
    }

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
                                                std::span<const uint8_t> data,
                                                int element_offset) {
    if (data.size() < 6) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t element_count = ser::read_uint(data);
    uint32_t byte_offset_in_elements = ser::read_udint(data.subspan(2));
    int total_bytes = element_count * tag.element_size();
    if (byte_offset_in_elements >= static_cast<uint32_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    // element_offset is bounded by INT32_MAX upstream, but
    // element_offset * element_size() can still overflow a signed int.
    int64_t base_offset_wide = static_cast<int64_t>(element_offset) * tag.element_size();
    if (base_offset_wide < 0 ||
        base_offset_wide > std::numeric_limits<int>::max()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int base_offset     = static_cast<int>(base_offset_wide);
    int absolute_offset = base_offset + static_cast<int>(byte_offset_in_elements);
    if (absolute_offset >= tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int prefix_len = logix_data_types::is_struct(tag.symbol_type()) ? 4 : 2;
    int remaining  = std::min(total_bytes - static_cast<int>(byte_offset_in_elements),
                              tag.data_size() - absolute_offset);
    int chunk      = std::min(remaining, MaxReplyData - prefix_len);
    bool more      = static_cast<int>(byte_offset_in_elements) + chunk < total_bytes;
    return build_read_response(tag, service_code, absolute_offset,
                                chunk, /*is_partial=*/more);
}

CipServiceResponse handle_write_tag_fragmented(Tag& tag, uint8_t service_code,
                                                 std::span<const uint8_t> data,
                                                 int element_offset) {
    if (data.size() < 8) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t tag_type = ser::read_uint(data);

    uint16_t element_count         = 0;
    uint32_t byte_offset_in_elements = 0;
    int      header_len            = 0;

    if (logix_data_types::is_struct(tag.symbol_type())) {
        if (data.size() < 10) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        uint16_t struct_handle    = ser::read_uint(data.subspan(2));
        element_count             = ser::read_uint(data.subspan(4));
        byte_offset_in_elements   = ser::read_udint(data.subspan(6));
        header_len                = 10;
        if (tag_type != kStructTypeIndicator || struct_handle != tag.tag_type()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    } else {
        element_count             = ser::read_uint(data.subspan(2));
        byte_offset_in_elements   = ser::read_udint(data.subspan(4));
        header_len                = 8;
        if (tag_type != tag.tag_type()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    }

    // element_offset is bounded by INT32_MAX upstream, but
    // element_offset * element_size() can still overflow a signed int.
    int64_t base_offset_wide = static_cast<int64_t>(element_offset) * tag.element_size();
    if (base_offset_wide < 0 ||
        base_offset_wide > std::numeric_limits<int>::max()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int base_offset = static_cast<int>(base_offset_wide);
    int total_bytes = element_count * tag.element_size();
    int write_len   = static_cast<int>(data.size()) - header_len;
    if (write_len < 0 || total_bytes < 0) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    // uint32 sum wraps: byte_offset_in_elements near UINT32_MAX plus a small
    // write_len rolls over to a small value that passes the comparison but
    // then absolute_offset below walks off the end of the tag buffer. Compare
    // in uint64 so no wrap can hide here.
    uint64_t end_in_bytes = static_cast<uint64_t>(byte_offset_in_elements)
                            + static_cast<uint64_t>(static_cast<uint32_t>(write_len));
    if (end_in_bytes > static_cast<uint64_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2104}));
    }
    if (base_offset + static_cast<int>(byte_offset_in_elements) + write_len > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    tag.set_data(data.subspan(header_len, write_len),
                 base_offset + static_cast<int>(byte_offset_in_elements));
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

CipServiceResponse handle_read_tag_fragmented_at(const Tag& tag, uint8_t service_code,
                                                   std::span<const uint8_t> data,
                                                   const WalkResult& w) {
    if (data.size() < 6) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t element_count = ser::read_uint(data);
    uint32_t byte_offset_in_elements = ser::read_udint(data.subspan(2));

    // Fragmented read of a single BOOL bit member. The service is coarse for
    // this (fragmentation is pointless on one bit), but Studio 5000 is known
    // to send 0x52 against any node including bits, so we mirror the atomic
    // sibling handle_read_tag_at and reply with a single 0x00/0x01 byte.
    if (w.bit_pos.has_value()) {
        if (element_count != 1 || byte_offset_in_elements != 0) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
        }
        uint8_t host = tag.get_data(w.offset, 1)[0];
        uint8_t bit = static_cast<uint8_t>((host >> *w.bit_pos) & 0x01);
        std::vector<uint8_t> reply(3);
        ser::write_uint(reply, static_cast<uint16_t>(0x00C1));
        reply[2] = bit;
        return CipServiceResponse::success(service_code, std::move(reply));
    }

    int total_bytes = element_count * w.element_size;
    if (total_bytes < 0 ||
        byte_offset_in_elements >= static_cast<uint32_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }

    // w.offset is already the walker-resolved byte offset into the tag buffer;
    // the fragmented request's own byte_offset adds to it.
    int64_t absolute_wide = static_cast<int64_t>(w.offset)
                            + static_cast<int64_t>(byte_offset_in_elements);
    if (absolute_wide < 0 ||
        absolute_wide > std::numeric_limits<int>::max() ||
        absolute_wide >= tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int absolute_offset = static_cast<int>(absolute_wide);

    // Nested struct: build_read_response_struct prepends [A0 02][handle].
    bool as_struct = w.tpl != nullptr;
    int prefix_len = as_struct ? 4 : 2;
    int remaining  = std::min(total_bytes - static_cast<int>(byte_offset_in_elements),
                              tag.data_size() - absolute_offset);
    int chunk      = std::min(remaining, MaxReplyData - prefix_len);
    bool more      = static_cast<int>(byte_offset_in_elements) + chunk < total_bytes;

    if (as_struct) {
        return build_read_response_struct(tag, service_code, absolute_offset,
                                           chunk, more, w.tpl->structure_handle());
    }
    return build_read_response_atomic(tag, service_code, absolute_offset,
                                       chunk, more, w.type_code);
}

CipServiceResponse handle_write_tag_fragmented_at(Tag& tag, uint8_t service_code,
                                                    std::span<const uint8_t> data,
                                                    const WalkResult& w) {
    if (data.size() < 8) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    uint16_t tag_type = ser::read_uint(data);

    bool as_struct = w.tpl != nullptr;
    uint16_t element_count         = 0;
    uint32_t byte_offset_in_elements = 0;
    int      header_len            = 0;

    if (as_struct) {
        if (data.size() < 10) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        uint16_t struct_handle  = ser::read_uint(data.subspan(2));
        element_count           = ser::read_uint(data.subspan(4));
        byte_offset_in_elements = ser::read_udint(data.subspan(6));
        header_len              = 10;
        if (tag_type != kStructTypeIndicator ||
            struct_handle != w.tpl->structure_handle()) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    } else {
        element_count           = ser::read_uint(data.subspan(2));
        byte_offset_in_elements = ser::read_udint(data.subspan(4));
        header_len              = 8;
        if (tag_type != w.type_code) {
            return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2107}));
        }
    }

    if (w.bit_pos.has_value()) {
        // Degenerate fragmented write to one bit; mirror handle_write_tag_at.
        if (element_count != 1 || byte_offset_in_elements != 0 ||
            static_cast<int>(data.size()) < header_len + 1) {
            return CipServiceResponse::error(service_code, CipStatus::error(0x13));
        }
        bool new_value = (data[header_len] & 0x01) != 0;
        tag.atomic_set_bit(w.offset, *w.bit_pos, new_value);
        return CipServiceResponse::success(service_code);
    }

    int total_bytes = element_count * w.element_size;
    int write_len   = static_cast<int>(data.size()) - header_len;
    if (write_len < 0 || total_bytes < 0) {
        return CipServiceResponse::error(service_code, CipStatus::error(0x13));
    }
    // Guard the uint32 wrap on byte_offset_in_elements + write_len, same as
    // the plain handle_write_tag_fragmented (commit 2377f71).
    uint64_t end_in_bytes = static_cast<uint64_t>(byte_offset_in_elements)
                            + static_cast<uint64_t>(static_cast<uint32_t>(write_len));
    if (end_in_bytes > static_cast<uint64_t>(total_bytes)) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2104}));
    }
    int64_t absolute_wide = static_cast<int64_t>(w.offset)
                            + static_cast<int64_t>(byte_offset_in_elements);
    int64_t end_absolute_wide = absolute_wide + static_cast<int64_t>(write_len);
    if (absolute_wide < 0 ||
        end_absolute_wide > tag.data_size()) {
        return CipServiceResponse::error(service_code, CipStatus::error(0xFF, {0x2105}));
    }
    tag.set_data(data.subspan(header_len, write_len),
                 static_cast<int>(absolute_wide));
    return CipServiceResponse::success(service_code);
}

} // namespace ethernetip::logix::tag_services
