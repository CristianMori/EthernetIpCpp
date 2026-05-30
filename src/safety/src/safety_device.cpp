#include "ethernetip/safety/safety_device.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/safety/safety_cpcrc.hpp"
#include "ethernetip/safety/safety_crc.hpp"
#include "ethernetip/safety/safety_frame_codec.hpp"
#include "ethernetip/safety/safety_network_segment.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace ethernetip::safety {

using namespace ethernetip::cip;
using namespace ethernetip::connections;
using namespace ethernetip::device;
using namespace ethernetip::protocol;
namespace ser = ethernetip::cip::serializer;

std::atomic<bool> SafetyDevice::enable_trace{false};
std::atomic<int>  SafetyDevice::startup_trace_seconds{0};

namespace {
// Microseconds-since-steady_clock-epoch — matches the C# Stopwatch.GetTimestamp()
// usage where the ticks unit and origin don't matter, only deltas do.
int64_t now_us() noexcept {
    using namespace std::chrono;
    return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

int estimate_data_length(int wire_size) noexcept {
    int short_len = wire_size - 6;
    if (short_len >= 1 && short_len <= 2) return short_len;
    int long_len = (wire_size - 8) / 2;
    if (long_len >= 3 && long_len <= 250 && long_len * 2 + 8 == wire_size) return long_len;
    return -1;
}

void trace(const char* fmt, auto&&... args) {
    if (!SafetyDevice::enable_trace.load(std::memory_order_relaxed)) return;
    std::fprintf(stderr, fmt, std::forward<decltype(args)>(args)...);
    std::fputc('\n', stderr);
}
} // namespace

// ---- Construction ----------------------------------------------------------

SafetyDevice::SafetyDevice(IdentityInfo identity, std::string bind_address,
                              SafetyNetworkNumber snn, uint32_t node_address,
                              std::string name)
    : VirtualDevice(std::move(identity), std::move(bind_address), std::move(name)),
      supervisor_(std::make_unique<SafetySupervisorObject>(snn, node_address)),
      validator_(std::make_unique<SafetyValidatorObject>()) {

    dispatcher().register_class(supervisor_->release_cip_class());
    dispatcher().register_class(validator_->release_cip_class());

    connection_manager().set_safety_handler(this);
    connection_manager().on_connection_removed.push_back(
        [this](IoConnection& conn) { on_connection_removed(conn); });

    supervisor_->start();
}

SafetyDevice::~SafetyDevice() = default;

// ---- ISafetyConnectionHandler ----------------------------------------------

std::optional<uint16_t> SafetyDevice::validate_safety_open(
        std::span<const uint8_t> safety_segment,
        const ForwardOpenRequest& fwd_open) {
    if (safety_segment.size() < 3 || safety_segment[0] != 0x50) return uint16_t{0x080E};

    SafetyNetworkSegment seg;
    try {
        auto [parsed, _] = SafetyNetworkSegment::parse(safety_segment);
        seg = parsed;
    } catch (const std::invalid_argument&) {
        return uint16_t{0x080E};
    }

    // 1. Verify TUNID matches our identity.
    std::vector<uint8_t> our_tunid(UniqueNetworkId::Size);
    supervisor_->tunid().copy_to(our_tunid);
    std::vector<uint8_t> seg_tunid(UniqueNetworkId::Size);
    seg.tunid.copy_to(seg_tunid);
    if (our_tunid != seg_tunid) return uint16_t{0x080E};

    // 2. Validate CPCRC against the raw FwdOpen + path bytes.
    const auto& conn_path = fwd_open.connection_path;
    size_t safety_off = 0;
    for (size_t i = 0; i + 1 < conn_path.size(); ++i) {
        if (conn_path[i] == 0x50) { safety_off = i; break; }
    }
    std::span<const uint8_t> ekey_app_path(conn_path.data(), safety_off);
    size_t nsd_size = (seg.format == 0x02) ? 50u : 48u;
    if (safety_off + nsd_size > conn_path.size()) return uint16_t{0x080E};
    std::span<const uint8_t> nsd_bytes(conn_path.data() + safety_off, nsd_size);

    uint8_t effective_path_size = static_cast<uint8_t>(
        (ekey_app_path.size() + (conn_path.size() - safety_off)) / 2);
    uint32_t computed = cpcrc::compute_from_raw(
        fwd_open.raw_service_data, ekey_app_path, nsd_bytes, effective_path_size);
    if (computed != seg.cpcrc) {
        std::fprintf(stderr, "[SAFETY] CPCRC mismatch: computed=0x%08X received=0x%08X\n",
                     computed, seg.cpcrc);
        return uint16_t{0x080D};
    }

    // 3. SCID type-2a check — non-zero SCID must match our stored one.
    bool has_scid = supervisor_->scid().sccrc != 0;
    if (!has_scid) return std::nullopt;
    if (seg.sccrc != 0 && seg.sccrc != supervisor_->scid().sccrc) {
        return uint16_t{0x0111};
    }
    return std::nullopt;
}

void SafetyDevice::configure_safety_connection(IoConnection& conn,
                                                  const ForwardOpenRequest& fwd_open) {
    bool is_server = (fwd_open.transport_class_trigger & 0x80) != 0;

    if (conn.safety_segment_data.size() >= 3 && conn.safety_segment_data[0] == 0x50) {
        auto [safety_seg, _] = SafetyNetworkSegment::parse(conn.safety_segment_data);
        auto* sv_inst = supervisor_->cip_class().get_instance(1);

        std::vector<uint8_t> cfunid_data(UniqueNetworkId::Size);
        safety_seg.ounid.copy_to(cfunid_data);
        if (sv_inst != nullptr) {
            if (auto* a = sv_inst->get_attribute(25)) a->set_data(cfunid_data);
        }

        std::vector<uint8_t> scid_data(SafetyConfigurationId::Size);
        ser::write_udint(scid_data, safety_seg.sccrc);
        std::memcpy(scid_data.data() + 4, safety_seg.scts.data(), 6);
        if (sv_inst != nullptr) {
            if (auto* a = sv_inst->get_attribute(6)) a->set_data(scid_data);
        }
        supervisor_->set_scid({safety_seg.sccrc, SafetyNetworkNumber(safety_seg.scts)});

        // Initial_TS / Initial_Rollover_Value handling:
        //   TARGET PRODUCER (client direction, we produce): echo originator's values.
        //   TARGET CONSUMER (server direction, we consume): use deterministic 0
        //     so the PLC's per-device cached InitialRolloverValue stays in sync
        //     across reconnects.
        if (is_server) {
            conn.safety_initial_timestamp     = 0;
            conn.safety_initial_rollover_value = 0;
        } else {
            conn.safety_initial_timestamp     = safety_seg.initial_time_stamp;
            conn.safety_initial_rollover_value = safety_seg.initial_rollover_value;
        }

        conn.safety_ping_interval_us =
            static_cast<int64_t>(safety_seg.ping_interval_multiplier) * conn.tto_o_rpi;

        // Connection_Correction_Constant =
        //   Time_Drift_Constant + 1 - Time_Coord_Msg_Min_Multiplier
        // Time_Drift_Constant = Roundup((Timeout_Mult+1) * EPI * PingIntMult / 320000)
        int64_t epi_us = conn.tto_o_rpi;
        int64_t time_drift = ((static_cast<int64_t>(safety_seg.timeout_multiplier) + 1)
                                * epi_us * safety_seg.ping_interval_multiplier + 319999)
                                / 320000;
        if (time_drift < 1) time_drift = 1;
        conn.safety_connection_correction_constant = static_cast<uint16_t>(
            time_drift + 1 - safety_seg.time_coord_msg_min_multiplier);
    }

    int trace_seconds = startup_trace_seconds.load(std::memory_order_relaxed);
    if (trace_seconds > 0) {
        conn.safety_startup_trace_until_ticks = now_us()
            + static_cast<int64_t>(trace_seconds) * 1'000'000;
    }

    auto* vi = validator_->create_instance(conn);
    vi->state = SafetyValidatorState::Executing;
    uint16_t sv_inst_id = static_cast<uint16_t>(vi->instance_id);

    // Target PID — for data WE produce on T->O.
    conn.safety_pid_seed_s1 = crc::pid_cid_seed_s1(identity().vendor_id, identity().serial_number, sv_inst_id);
    conn.safety_pid_seed_s3 = crc::pid_cid_seed_s3(identity().vendor_id, identity().serial_number, sv_inst_id);
    conn.safety_pid_seed_s5 = crc::pid_cid_seed_s5(identity().vendor_id, identity().serial_number, sv_inst_id);

    // Originator PID — for verifying data ORIGINATOR produces on O->T.
    conn.safety_originator_pid_seed_s1 = crc::pid_cid_seed_s1(
        fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
        fwd_open.connection_serial_number);
    conn.safety_originator_pid_seed_s3 = crc::pid_cid_seed_s3(
        fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
        fwd_open.connection_serial_number);
    conn.safety_originator_pid_seed_s5 = crc::pid_cid_seed_s5(
        fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
        fwd_open.connection_serial_number);

    // CID seeds: derived from whichever side is the data consumer.
    if (is_server) {
        conn.safety_cid_seed_s3 = crc::pid_cid_seed_s3(identity().vendor_id,
                                                         identity().serial_number, sv_inst_id);
        conn.safety_cid_seed_s5 = crc::pid_cid_seed_s5(identity().vendor_id,
                                                         identity().serial_number, sv_inst_id);
    } else {
        conn.safety_cid_seed_s3 = crc::pid_cid_seed_s3(
            fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
            fwd_open.connection_serial_number);
        conn.safety_cid_seed_s5 = crc::pid_cid_seed_s5(
            fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
            fwd_open.connection_serial_number);
    }

    conn.safety_validator_instance_id = sv_inst_id;
    conn.safety_last_ping_count = 0xFF;
}

// ---- VirtualDevice overrides -----------------------------------------------

void SafetyDevice::on_connection_ready(IoConnection& conn) {
    // Start producing immediately. Until the first TCOO arrives, we send
    // IDLE frames (run_idle=false, timestamp=0) so the safety connection
    // doesn't time out before PLC starts its consumer task.
    VirtualDevice::on_connection_ready(conn);
}

void SafetyDevice::produce_io_data(IoConnection& conn) {
    if (!conn.is_safety) { VirtualDevice::produce_io_data(conn); return; }
    if (conn.state != ConnectionState::Established) return;

    auto* assembly = assemblies().get_assembly(conn.produced_assembly_instance);
    if (assembly == nullptr) return;

    // TCOO-only direction (T->O is just 6 bytes of TCOO with no data).
    if (conn.tto_o_size == 6 && assembly->data_size() == 0) return;

    int base_size = frame_codec::wire_size(assembly->data_size(), SafetyFormat::Base);
    int ext_size  = frame_codec::wire_size(assembly->data_size(), SafetyFormat::Extended);
    if (conn.tto_o_size != base_size && conn.tto_o_size != ext_size) return;

    SafetyFormat format = (conn.safety_format == 0x02) ? SafetyFormat::Extended : SafetyFormat::Base;
    bool consumer_active = conn.safety_consumer_active;
    bool run_idle = consumer_active;

    uint16_t timestamp = 0;
    if (consumer_active) {
        int64_t now_ticks = now_us();
        conn.safety_last_frame_sent_ticks = now_ticks;
        int64_t elapsed_us = now_ticks - conn.safety_production_start_ticks;
        int64_t raw_ticks  = static_cast<int64_t>(conn.safety_initial_timestamp)
                                + elapsed_us / 128;
        uint16_t raw_timestamp = static_cast<uint16_t>(raw_ticks & 0xFFFF);
        conn.safety_last_produced_timestamp = raw_timestamp;

        // Slew the applied CTCV toward the goal: step = max(1, remaining/8).
        uint16_t goal    = conn.safety_consumer_time_correction_goal;
        uint16_t applied = conn.safety_consumer_time_correction_value;
        if (applied != goal) {
            int16_t slew_delta = static_cast<int16_t>(goal - applied);
            if (slew_delta > 0) {
                int step = std::max(1, slew_delta / 8);
                if (step > slew_delta) step = slew_delta;
                conn.safety_consumer_time_correction_value =
                    static_cast<uint16_t>(applied + step);
            } else {
                // Goal moved backward — the TCOO handler refuses this, but
                // snap defensively if it ever happens.
                conn.safety_consumer_time_correction_value = goal;
            }
        }

        int64_t corrected_ticks =
            raw_ticks + conn.safety_consumer_time_correction_value;
        int64_t prev_sent_ticks = conn.safety_last_sent_ticks;

        // Forward-only guard using full int64 comparison. If CTCV would push
        // corrected ticks backwards from the last sent, force +1 instead so
        // the consumer's monotonicity check passes.
        int64_t delta_ticks = corrected_ticks - prev_sent_ticks;
        if (prev_sent_ticks != 0 && delta_ticks < 0) {
            trace("[GUARD] conn=%04X rawTicks=%lld correctedTicks=%lld prevSent=%lld "
                   "delta=%lld CTCV=%u -> force prev+1",
                   conn.connection_serial_number,
                   (long long)raw_ticks, (long long)corrected_ticks,
                   (long long)prev_sent_ticks, (long long)delta_ticks,
                   conn.safety_consumer_time_correction_value);
            corrected_ticks = prev_sent_ticks + 1;
        }

        timestamp = static_cast<uint16_t>(corrected_ticks & 0xFFFF);
        conn.safety_timestamp = timestamp;
        conn.safety_last_sent_ticks = corrected_ticks;
        conn.safety_rollover_count = static_cast<uint16_t>(
            conn.safety_initial_rollover_value + (corrected_ticks >> 16));
    }

    if (consumer_active) {
        // Bump ping count once per ping interval.
        int64_t now = now_us();
        if (conn.safety_last_ping_change_ticks == 0) {
            conn.safety_last_ping_change_ticks = now;
        }
        int64_t ping_elapsed_us = now - conn.safety_last_ping_change_ticks;
        if (conn.safety_ping_interval_us > 0
            && ping_elapsed_us >= conn.safety_ping_interval_us) {
            conn.safety_last_ping_change_ticks = now;
            conn.safety_ping_count = static_cast<uint8_t>((conn.safety_ping_count + 1) & 0x03);
        }
    }

    ModeByte mode = ModeByte::create(run_idle, conn.safety_ping_count);

    // Small assemblies (1-8 bytes) — stack buffer is fine.
    std::vector<uint8_t> asm_data(assembly->data_size());
    assembly->copy_data_to(asm_data);

    std::vector<uint8_t> safety_buf(assembly->data_size() * 2 + 16);
    int safety_len = frame_codec::encode(
        safety_buf, asm_data, format, mode, timestamp,
        conn.safety_pid_seed_s1, conn.safety_pid_seed_s3, conn.safety_pid_seed_s5,
        conn.safety_rollover_count);
    if (safety_len > 0) {
        send_udp_io_data(conn, std::span<const uint8_t>(safety_buf.data(), safety_len));
    }
}

void SafetyDevice::handle_received_io_data(IoConnection& conn,
                                              std::span<const uint8_t> data) {
    if (!conn.is_safety) { VirtualDevice::handle_received_io_data(conn, data); return; }

    int wire_size = static_cast<int>(data.size());

    // ---- TCOO branch (5 or 6 bytes) ----
    if (wire_size == 5 || wire_size == 6) {
        if (!conn.safety_consumer_active) {
            conn.safety_consumer_active = true;
            conn.safety_timestamp       = conn.safety_initial_timestamp;
            conn.safety_rollover_count  = conn.safety_initial_rollover_value;
            conn.safety_production_start_ticks = now_us();
        }
        if (data.size() < 3) return;

        uint16_t consumer_time_value = ser::read_uint(data.subspan(1));

        // Outlier check: reject TCOOs that arrived > 2 ms after our last send.
        // (PLC's per-frame CTCV is biased by send-to-arrival delay; a delayed
        // TCOO produces a spurious CTCV jump that can FwdClose the connection.)
        if (conn.safety_last_frame_sent_ticks != 0) {
            int64_t send_to_tcoo_us = now_us() - conn.safety_last_frame_sent_ticks;
            constexpr int64_t kLateThresholdUs = 2000;
            if (send_to_tcoo_us > kLateThresholdUs) {
                trace("[TCOO-LATE] conn=%04X ctv=%u sendToTcoo=%lldus (>%lldus) — skipping",
                       conn.connection_serial_number, consumer_time_value,
                       (long long)send_to_tcoo_us, (long long)kLateThresholdUs);
                return;
            }
        }

        // Worst_Case_CTCV = consumer_time_value - last_produced_ts - CCC.
        uint16_t worst_case_ctcv = static_cast<uint16_t>(
            consumer_time_value
            - conn.safety_last_produced_timestamp
            - conn.safety_connection_correction_constant);
        uint16_t old_ctcv = conn.safety_consumer_time_correction_value;
        int16_t  delta_ctcv = static_cast<int16_t>(worst_case_ctcv - old_ctcv);

        if (!conn.safety_time_correction_initialized) {
            conn.safety_time_correction_initialized = true;
            trace("[CTCV-INIT] conn=%04X ctv=%u (SKIPPED first TCOO)",
                   conn.connection_serial_number, consumer_time_value);
            return;
        }

        // Subsequent TCOOs — adaptive correction:
        //   * negative delta: skip (CTCV never goes backward)
        //   * first real CTCV (old=0): apply instantly
        //   * small positive (<= 1 RPI of ticks): apply instantly
        //   * large positive: set goal, slew in produce_io_data
        int instant_apply_threshold = static_cast<int>(conn.tto_o_rpi / 128);
        if (instant_apply_threshold < 1) instant_apply_threshold = 1;
        uint16_t new_applied = old_ctcv;
        uint16_t new_goal    = conn.safety_consumer_time_correction_goal;
        if (delta_ctcv <= 0) {
            // skip
        } else if (old_ctcv == 0) {
            new_applied = worst_case_ctcv;
            new_goal    = worst_case_ctcv;
        } else if (delta_ctcv <= instant_apply_threshold) {
            new_applied = worst_case_ctcv;
            new_goal    = worst_case_ctcv;
        } else {
            if (static_cast<int16_t>(worst_case_ctcv - new_goal) > 0) {
                new_goal = worst_case_ctcv;
            }
        }
        conn.safety_consumer_time_correction_value = new_applied;
        conn.safety_consumer_time_correction_goal  = new_goal;
        return;
    }

    // ---- Safety data frame ----
    SafetyFormat format = (conn.safety_format == 0x02) ? SafetyFormat::Extended : SafetyFormat::Base;
    int data_len = estimate_data_length(wire_size);
    if (data_len <= 0) return;

    // Track the originator's rollover separately from our own producer's:
    // Extended-Format CRC includes rollover in the seed, and the PLC's
    // clock can diverge from ours during startup. Both ends start at
    // safety_initial_rollover_value and increment when the wire ts wraps
    // 0xFFFF -> 0x0000.
    uint16_t incoming_ts = frame_codec::extract_timestamp(data, data_len, format);
    if (!conn.safety_originator_rollover_initialized) {
        conn.safety_originator_rollover_count = conn.safety_initial_rollover_value;
        conn.safety_originator_last_ts        = incoming_ts;
        conn.safety_originator_rollover_initialized = true;
    } else {
        int delta = static_cast<int>(incoming_ts) - static_cast<int>(conn.safety_originator_last_ts);
        if (delta < -0x4000) {
            conn.safety_originator_rollover_count =
                static_cast<uint16_t>(conn.safety_originator_rollover_count + 1);
        }
        conn.safety_originator_last_ts = incoming_ts;
    }

    auto result = frame_codec::decode(data, data_len, format,
                                         conn.safety_originator_pid_seed_s1,
                                         conn.safety_originator_pid_seed_s3,
                                         conn.safety_originator_pid_seed_s5,
                                         conn.safety_originator_rollover_count);

    // IDLE frames before PLC processes our SafetyOpen reply may use
    // rolloverCount=0 (its default) instead of our initial_rollover_value.
    // Retry with 0 if first attempt failed AND the frame is in idle mode.
    if (!result.crc_valid
        && data_len < static_cast<int>(data.size())
        && (data[data_len] & 0x80) == 0
        && conn.safety_originator_rollover_count != 0) {
        result = frame_codec::decode(data, data_len, format,
                                       conn.safety_originator_pid_seed_s1,
                                       conn.safety_originator_pid_seed_s3,
                                       conn.safety_originator_pid_seed_s5,
                                       0);
    }

    if (result.crc_valid) {
        if (auto* asm_inst = assemblies().get_assembly(conn.consumed_assembly_instance)) {
            asm_inst->set_data(result.actual_data);
        }
    }

    uint8_t mode_byte    = (data_len < static_cast<int>(data.size())) ? data[data_len] : uint8_t{0};
    uint8_t current_ping = static_cast<uint8_t>(mode_byte & 0x03);
    bool    plc_running  = (mode_byte & 0x80) != 0;

    // Ping change → reply with TCOO.
    if (current_ping != conn.safety_last_ping_count) {
        conn.safety_last_ping_count = current_ping;
        send_time_coordination(conn);
    }

    // False -> True transition of PLC run state on this connection triggers
    // a cold-start frame on the partner client connection (only fires once).
    if (plc_running && !conn.safety_plc_running) {
        conn.safety_plc_running = true;
        for (auto* other : connection_manager().active_connections()) {
            if (other != &conn
                && other->is_safety
                && other->originator_vendor_id == conn.originator_vendor_id
                && other->originator_serial_number == conn.originator_serial_number
                && !other->safety_consumer_active) {
                produce_io_data(*other);
            }
        }
    }
}

void SafetyDevice::on_remote_endpoint_updated(IoConnection& conn,
                                                const IpEndpoint& sender) {
    if (!conn.is_safety) return;
    // Propagate the endpoint to every safety connection from the same
    // originator (partner connections may not have seen incoming data yet).
    for (auto* other : connection_manager().active_connections()) {
        if (other != &conn
            && other->is_safety
            && other->originator_vendor_id == conn.originator_vendor_id
            && other->originator_serial_number == conn.originator_serial_number) {
            other->remote_host = sender.host;
            other->remote_port = sender.port;
            other->remote_endpoint_set = true;
        }
    }
}

// ---- Private ---------------------------------------------------------------

void SafetyDevice::send_time_coordination(IoConnection& conn) {
    std::array<uint8_t, 6> tcoo_buf{};

    int64_t elapsed_us = now_us() - conn.safety_production_start_ticks;
    uint16_t consumer_time = static_cast<uint16_t>(
        (static_cast<int64_t>(conn.safety_initial_timestamp) + elapsed_us / 128) & 0xFFFF);

    bool is_extended = (conn.safety_format == 0x02);
    int len;
    if (is_extended) {
        len = frame_codec::encode_time_coordination_extended(
            tcoo_buf, conn.safety_last_ping_count, consumer_time, conn.safety_cid_seed_s5);
    } else {
        len = frame_codec::encode_time_coordination(
            tcoo_buf, conn.safety_last_ping_count, consumer_time, conn.safety_cid_seed_s3);
    }
    send_udp_io_data(conn, std::span<const uint8_t>(tcoo_buf.data(), len));
}

void SafetyDevice::on_connection_removed(IoConnection& conn) {
    if (!conn.is_safety) return;
    // If the last safety connection just closed, clear the SCID + CFUNID on
    // the supervisor so the next FwdOpen is treated as fresh.
    bool any_safety_left = false;
    for (auto* other : connection_manager().active_connections()) {
        if (other->is_safety) { any_safety_left = true; break; }
    }
    if (!any_safety_left) {
        supervisor_->set_scid({});
        auto* sv_inst = supervisor_->cip_class().get_instance(1);
        if (sv_inst != nullptr) {
            if (auto* a = sv_inst->get_attribute(6)) {
                a->set_data(std::vector<uint8_t>(SafetyConfigurationId::Size));
            }
            if (auto* a = sv_inst->get_attribute(25)) {
                a->set_data(std::vector<uint8_t>(UniqueNetworkId::Size));
            }
        }
    }
}

} // namespace ethernetip::safety
