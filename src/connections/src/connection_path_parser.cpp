#include "ethernetip/connections/connection_path_parser.hpp"

#include "ethernetip/cip/data_serializer.hpp"

namespace ethernetip::connections {

ConnectionPathResult parse_connection_path(std::span<const uint8_t> path,
                                            const ForwardOpenRequest& request) {
    namespace ser = ethernetip::cip::serializer;

    // Some originators prepend `21 00 FC 04 2C 01` — strip it so the real
    // assembly shortcut parses cleanly.
    if (path.size() >= 6 &&
        path[0] == 0x21 && path[1] == 0x00 &&
        path[2] == 0xFC && path[3] == 0x04 &&
        path[4] == 0x2C && path[5] == 0x01) {
        path = path.subspan(6);
    }

    ConnectionPathResult result;
    std::optional<uint32_t> current_class;
    std::optional<uint32_t> current_instance;

    constexpr int max_connection_points = 4;
    constexpr int max_instances         = 8;
    uint32_t connection_points[max_connection_points] = {};
    int      conn_point_count = 0;
    uint32_t instance_ids[max_instances] = {};
    int      instance_count = 0;

    size_t offset = 0;
    while (offset < path.size()) {
        uint8_t seg     = path[offset];
        uint8_t seg_type = static_cast<uint8_t>(seg & 0xE0);

        // Electronic key segment (0x34) — must be checked BEFORE the logical
        // branch: 0x34 & 0xE0 == 0x20 so it would otherwise be mistaken for
        // a logical segment with an unrecognized type.
        if (seg == 0x34) {
            result.has_electronic_key = true;
            ++offset;
            if (offset >= path.size()) goto done;
            uint8_t key_format = path[offset++];
            int key_size = (key_format == 4 || key_format == 5) ? 8 : 0;
            offset += key_size;
            continue;
        }

        if (seg_type == 0x20) {  // Logical segment
            uint8_t logical_type = static_cast<uint8_t>(seg & 0x1C);
            uint8_t format       = static_cast<uint8_t>(seg & 0x03);
            ++offset;
            uint32_t value = 0;
            switch (format) {
                case 0x00:   // 8-bit
                    if (offset >= path.size()) goto done;
                    value = path[offset++];
                    break;
                case 0x01:   // 16-bit
                    if (offset % 2 != 0) ++offset;  // pad to word
                    if (offset + 2 > path.size()) goto done;
                    value = ser::read_uint(path.subspan(offset));
                    offset += 2;
                    break;
                default:
                    goto done;
            }
            switch (logical_type) {
                case 0x00:   // Class ID
                    current_class = value;
                    break;
                case 0x04:   // Instance ID
                    current_instance = value;
                    if (instance_count < max_instances) {
                        instance_ids[instance_count++] = value;
                    }
                    break;
                case 0x0C:   // Connection Point
                    if (conn_point_count < max_connection_points) {
                        connection_points[conn_point_count++] = value;
                    }
                    break;
                case 0x10:   // Attribute ID — ignored here
                default:
                    break;
            }
        } else if (seg_type == 0x00) {     // Port segment (routing)
            bool extended = (seg & 0x10) != 0;
            ++offset;
            if (extended) {
                if (offset >= path.size()) goto done;
                uint8_t addr_size = path[offset++];
                offset += addr_size;
                if (offset % 2 != 0) ++offset;
            } else {
                if (offset >= path.size()) goto done;
                ++offset;  // link address byte
            }
        } else if (seg_type == 0x80) {     // Simple Data Segment (config data)
            ++offset;
            if (offset >= path.size()) goto done;
            uint8_t data_words = path[offset++];
            size_t  data_bytes = static_cast<size_t>(data_words) * 2;
            if (offset + data_bytes > path.size()) goto done;
            result.config_data.assign(path.begin() + offset,
                                       path.begin() + offset + data_bytes);
            offset += data_bytes;
        } else if (seg_type == 0x40) {     // Network segment
            if (seg == 0x50) {              // Safety Network Segment
                if (offset + 1 >= path.size()) goto done;
                uint8_t seg_data_words = path[offset + 1];
                size_t  seg_total = 2u + static_cast<size_t>(seg_data_words) * 2;
                if (offset + seg_total > path.size()) goto done;
                result.safety_segment.assign(path.begin() + offset,
                                              path.begin() + offset + seg_total);
                offset += seg_total;
            } else {
                ++offset;
                if (offset >= path.size()) goto done;
                uint8_t net_seg_len = path[offset++];
                offset += static_cast<size_t>(net_seg_len) * 2;
            }
        } else {
            break;
        }
    }

done:
    if (current_class.has_value() && *current_class == 0x04 && conn_point_count >= 2) {
        result.config_assembly_instance   = current_instance;
        result.consumed_assembly_instance = connection_points[0];
        result.produced_assembly_instance = connection_points[1];
    } else if (current_class.has_value() && *current_class == 0x04 && conn_point_count == 1) {
        result.config_assembly_instance = current_instance;
        if (!request.oto_t_params.is_null() && !request.tto_o_params.is_null()) {
            result.consumed_assembly_instance = connection_points[0];
            result.produced_assembly_instance = connection_points[0];
        } else if (!request.oto_t_params.is_null()) {
            result.consumed_assembly_instance = connection_points[0];
        } else {
            result.produced_assembly_instance = connection_points[0];
        }
    } else if (current_class.has_value() && *current_class == 0x04
               && conn_point_count == 0 && instance_count >= 3) {
        // Safety 3-instance path: [config, O->T, T->O]
        result.config_assembly_instance   = instance_ids[0];
        result.consumed_assembly_instance = instance_ids[1];
        result.produced_assembly_instance = instance_ids[2];
    } else if (conn_point_count >= 2) {
        result.consumed_assembly_instance = connection_points[0];
        result.produced_assembly_instance = connection_points[1];
    }

    return result;
}

} // namespace ethernetip::connections
