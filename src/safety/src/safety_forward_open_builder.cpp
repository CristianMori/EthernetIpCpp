#include "ethernetip/safety/safety_forward_open_builder.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/safety/safety_cpcrc.hpp"
#include "ethernetip/safety/safety_crc.hpp"
#include "ethernetip/safety/safety_frame_codec.hpp"
#include "ethernetip/safety/safety_network_segment.hpp"

#include <cstring>

namespace ethernetip::safety {

namespace ser = ethernetip::cip::serializer;

static std::vector<uint8_t> assembly_shortcut_path(const SafetyForwardOpenConfig& cfg) {
    return {
        0x20, 0x04,
        0x24, static_cast<uint8_t>(cfg.config_assembly & 0xFFu),
        0x2C, static_cast<uint8_t>(cfg.consumed_assembly & 0xFFu),
        0x2C, static_cast<uint8_t>(cfg.produced_assembly & 0xFFu),
    };
}

SafetyForwardOpenWire build_safety_forward_open(const SafetyForwardOpenConfig& cfg,
                                                  uint16_t conn_serial,
                                                  uint16_t orig_vendor,
                                                  uint32_t orig_serial,
                                                  uint8_t  transport_class_trigger,
                                                  std::span<const uint8_t> route_prefix,
                                                  std::span<const uint8_t> app_path_in) {
    std::vector<uint8_t> app_path;
    std::span<const uint8_t> app_path_span;
    if (app_path_in.empty()) {
        app_path = assembly_shortcut_path(cfg);
        app_path_span = app_path;
    } else {
        app_path_span = app_path_in;
    }

    // ---- Build safety segment with CPCRC = 0 ----
    bool is_extended = (cfg.format == SafetyFormat::Extended);
    SafetyNetworkSegment seg;
    seg.format = is_extended ? 0x02 : 0x00;
    seg.sccrc  = cfg.scid.sccrc;
    if (cfg.scid.sccrc != 0) seg.scts = cfg.scid.scts.data;
    seg.time_correction_epi = 0;
    seg.time_correction_params = 0;
    seg.tunid = cfg.tunid;
    seg.ounid = cfg.ounid;
    seg.ping_interval_multiplier = cfg.ping_interval_multiplier;
    seg.time_coord_msg_min_multiplier = cfg.time_coord_msg_min_multiplier;
    seg.network_time_expectation_multiplier = cfg.network_time_expectation_multiplier;
    seg.timeout_multiplier = cfg.timeout_multiplier;
    seg.max_consumer_number = 1;
    seg.max_fault_number = cfg.max_fault_number;
    seg.cpcrc = 0;
    seg.time_correction_connection_id = 0xFFFFFFFFu;
    seg.initial_time_stamp = cfg.initial_timestamp;
    seg.initial_rollover_value = cfg.initial_rollover_value;

    std::vector<uint8_t> safety_seg(seg.wire_size());
    seg.encode(safety_seg);

    // ---- Assemble full connection path ----
    std::vector<uint8_t> conn_path;
    conn_path.reserve(route_prefix.size() + app_path_span.size() + safety_seg.size());
    conn_path.insert(conn_path.end(), route_prefix.begin(), route_prefix.end());
    conn_path.insert(conn_path.end(), app_path_span.begin(), app_path_span.end());
    conn_path.insert(conn_path.end(), safety_seg.begin(), safety_seg.end());

    // ---- Compute wire sizes ----
    uint16_t ot_size = cfg.oto_t_connection_size != 0
        ? cfg.oto_t_connection_size
        : static_cast<uint16_t>(frame_codec::wire_size(cfg.consumed_data_size, cfg.format));
    uint16_t to_size = cfg.tto_o_connection_size != 0
        ? cfg.tto_o_connection_size
        : static_cast<uint16_t>(frame_codec::wire_size(cfg.produced_data_size, cfg.format));

    // P2P + High Priority + Fixed (safety requires fixed + high priority).
    uint16_t ot_params = 0x4400 | (ot_size & 0x01FFu);
    uint16_t to_params = 0x4400 | (to_size & 0x01FFu);

    // For P2P: originator chooses the T->O conn ID.
    uint32_t to_conn_id = 0x10000000u | static_cast<uint32_t>(conn_serial);

    uint32_t ot_rpi = cfg.oto_t_rpi != 0 ? cfg.oto_t_rpi : cfg.rpi;
    uint32_t to_rpi = cfg.tto_o_rpi != 0 ? cfg.tto_o_rpi : cfg.rpi;

    // ---- Build Forward Open service data ----
    std::vector<uint8_t> fwd(36 + conn_path.size());
    size_t off = 0;
    fwd[off++] = cfg.priority_time_tick;
    fwd[off++] = cfg.timeout_ticks;
    ser::write_udint(std::span<uint8_t>(fwd).subspan(off), 0u);          off += 4;  // OT ID (target chooses)
    ser::write_udint(std::span<uint8_t>(fwd).subspan(off), to_conn_id);  off += 4;
    ser::write_uint (std::span<uint8_t>(fwd).subspan(off), conn_serial); off += 2;
    ser::write_uint (std::span<uint8_t>(fwd).subspan(off), orig_vendor); off += 2;
    ser::write_udint(std::span<uint8_t>(fwd).subspan(off), orig_serial); off += 4;
    fwd[off++] = cfg.connection_timeout_multiplier;
    off += 3;                                                              // 3 reserved bytes
    ser::write_udint(std::span<uint8_t>(fwd).subspan(off), ot_rpi);      off += 4;
    ser::write_uint (std::span<uint8_t>(fwd).subspan(off), ot_params);   off += 2;
    ser::write_udint(std::span<uint8_t>(fwd).subspan(off), to_rpi);      off += 4;
    ser::write_uint (std::span<uint8_t>(fwd).subspan(off), to_params);   off += 2;
    fwd[off++] = transport_class_trigger;
    fwd[off++] = static_cast<uint8_t>(conn_path.size() / 2);
    std::memcpy(fwd.data() + off, conn_path.data(), conn_path.size());

    // ---- Compute CPCRC and patch into the safety segment ----
    size_t safety_off_in_conn_path = route_prefix.size() + app_path_span.size();
    size_t nsd_size = is_extended ? 50u : 48u;
    std::span<const uint8_t> nsd(conn_path.data() + safety_off_in_conn_path, nsd_size);

    uint8_t effective_path_size = static_cast<uint8_t>(
        (app_path_span.size() + safety_seg.size()) / 2);
    uint32_t cpcrc = cpcrc::compute_from_raw(fwd, app_path_span, nsd, effective_path_size);

    // Patch CPCRC into the wire-encoded segment inside `fwd`. CPCRC offset
    // from the 0x50 byte: 48 (Base) or 50 (Extended).
    size_t cpcrc_abs = 36 + safety_off_in_conn_path + (is_extended ? 50u : 48u);
    ser::write_udint(std::span<uint8_t>(fwd).subspan(cpcrc_abs), cpcrc);

    SafetyForwardOpenWire out;
    out.service_data = std::move(fwd);
    out.cm_path.assign(std::begin(CmPath), std::end(CmPath));
    return out;
}

} // namespace ethernetip::safety
