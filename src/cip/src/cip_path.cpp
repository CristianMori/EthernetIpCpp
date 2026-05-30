#include "ethernetip/cip/cip_path.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <sstream>

namespace ethernetip::cip {

std::pair<CipPath, int> CipPath::parse(std::span<const uint8_t> data) {
    CipPath path;
    std::string symbolic;
    bool has_symbolic = false;
    size_t offset = 0;

    while (offset < data.size()) {
        uint8_t seg = data[offset];

        // ANSI Extended Symbolic Segment (0x91)
        if (seg == SymbolicSegmentByte) {
            ++offset;
            if (offset >= data.size()) break;
            uint8_t char_count = data[offset++];
            if (offset + char_count > data.size()) break;

            std::string name(reinterpret_cast<const char*>(data.data() + offset), char_count);
            offset += char_count;
            if (char_count % 2 != 0) ++offset;  // pad to word boundary

            if (!has_symbolic) {
                symbolic = std::move(name);
                has_symbolic = true;
            } else {
                symbolic += '.';
                symbolic += name;
            }
            continue;
        }

        uint8_t seg_type = static_cast<uint8_t>(seg & SegmentTypeMask);
        if (seg_type != LogicalSegment) {
            break;  // unknown / unhandled segment — stop
        }

        uint8_t logical_type = static_cast<uint8_t>(seg & LogicalTypeMask);
        uint8_t format       = static_cast<uint8_t>(seg & LogicalFormatMask);
        ++offset;

        uint32_t value = 0;
        switch (format) {
            case LogicalFormat8Bit:
                if (offset >= data.size()) goto done;
                value = data[offset];
                offset += 1;
                break;
            case LogicalFormat16Bit:
                if (offset % 2 != 0) ++offset;
                if (offset + 2 > data.size()) goto done;
                value = serializer::read_uint(data.subspan(offset));
                offset += 2;
                break;
            case LogicalFormat32Bit:
                if (offset % 2 != 0) ++offset;
                if (offset + 4 > data.size()) goto done;
                value = serializer::read_udint(data.subspan(offset));
                offset += 4;
                break;
            default:
                goto done;
        }

        switch (logical_type) {
            case LogicalTypeClassId:         path.class_id         = value; break;
            case LogicalTypeInstanceId:      path.instance_id      = value; break;
            case LogicalTypeAttributeId:     path.attribute_id     = static_cast<uint16_t>(value); break;
            case LogicalTypeConnectionPoint: path.connection_point = static_cast<uint16_t>(value); break;
            case LogicalTypeElementId:       path.element_id       = value; break;
            default: break;
        }
    }

done:
    if (has_symbolic) path.symbolic_name = std::move(symbolic);
    path.raw_path.assign(data.begin(), data.begin() + offset);
    return {std::move(path), static_cast<int>(offset)};
}

int CipPath::encode_logical_8(std::span<uint8_t> dst, uint8_t logical_type, uint8_t value) {
    dst[0] = static_cast<uint8_t>(LogicalSegment | logical_type | LogicalFormat8Bit);
    dst[1] = value;
    return 2;
}

std::string CipPath::to_string() const {
    std::ostringstream oss;
    bool first = true;
    auto sep = [&]() { if (!first) oss << ", "; first = false; };
    if (symbolic_name) { sep(); oss << "Sym=\"" << *symbolic_name << "\""; }
    if (class_id)     { sep(); oss << "Class=0x" << std::hex << *class_id; }
    if (instance_id)  { sep(); oss << "Instance=" << std::dec << *instance_id; }
    if (attribute_id) { sep(); oss << "Attr="     << std::dec << *attribute_id; }
    if (connection_point) { sep(); oss << "ConnPt=" << std::dec << *connection_point; }
    if (element_id)   { sep(); oss << "Elem=" << std::dec << *element_id; }
    return oss.str();
}

} // namespace ethernetip::cip
