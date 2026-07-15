#include "ethernetip/safety/safety_scanner_connection.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/protocol/messages.hpp"
#include "ethernetip/safety/safety_crc.hpp"
#include "ethernetip/safety/safety_frame_codec.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace ethernetip::safety {

namespace ser = cip::serializer;
namespace msg = protocol::messages;

// ---- SafetyAppReply ----

SafetyAppReply SafetyAppReply::parse(std::span<const uint8_t> data) {
    SafetyAppReply r{};
    if (data.size() < 10) return r;
    r.consumer_number          = ser::read_uint (data);
    r.target_vendor_id         = ser::read_uint (data.subspan(2));
    r.target_device_serial     = ser::read_udint(data.subspan(4));
    r.target_connection_serial = ser::read_uint (data.subspan(8));
    if (data.size() >= 14) {
        r.initial_timestamp      = ser::read_uint(data.subspan(10));
        r.initial_rollover_value = ser::read_uint(data.subspan(12));
    }
    return r;
}

// ---- SafetyScannerConnection ----

SafetyScannerConnection::SafetyScannerConnection(protocol::EipScanner& scanner,
                                                    protocol::EipUdpTransport& udp,
                                                    SafetyFormat format)
    : scanner_(scanner), udp_(udp), format_(format) {}

SafetyScannerConnection::~SafetyScannerConnection() {
    close();
}

void SafetyScannerConnection::set_output_data(std::span<const uint8_t> data) {
    std::scoped_lock lock(buf_mu_);
    int n = std::min<int>(static_cast<int>(data.size()),
                            static_cast<int>(output_data_.size()));
    if (n > 0) std::memcpy(output_data_.data(), data.data(), n);
}

std::unique_ptr<SafetyScannerConnection> SafetyScannerConnection::open(
        protocol::EipScanner& scanner,
        protocol::EipUdpTransport& udp,
        const SafetyForwardOpenConfig& server_config,
        const SafetyForwardOpenConfig& client_config,
        uint16_t orig_vendor, uint32_t orig_serial,
        std::span<const uint8_t> route_prefix,
        std::span<const uint8_t> server_app_path,
        std::span<const uint8_t> client_app_path) {

    auto conn = std::unique_ptr<SafetyScannerConnection>(
        new SafetyScannerConnection(scanner, udp, server_config.format));
    conn->orig_vendor_  = orig_vendor;
    conn->orig_serial_  = orig_serial;
    conn->output_data_.assign(server_config.consumed_data_size, 0);
    conn->input_data_size_ = client_config.produced_data_size;
    conn->route_prefix_.assign(route_prefix.begin(), route_prefix.end());
    // Seed producer state from the values we advertise in the safety segment —
    // a spec-compliant consumer reads the same values off the segment and
    // starts its rollover counter there, so both ends must agree from frame 1.
    conn->timestamp_.store(server_config.initial_timestamp);
    conn->producer_rollover_count_.store(server_config.initial_rollover_value);

    uint32_t tick = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    conn->server_conn_serial_ = static_cast<uint16_t>(tick & 0xFFFF);
    conn->client_conn_serial_ = static_cast<uint16_t>((tick + 1) & 0xFFFF);

    // ---- Server Forward Open (we produce O->T) ----
    conn->log("Opening server connection (we produce)...");
    auto server_wire = build_safety_forward_open(
        server_config, conn->server_conn_serial_, orig_vendor, orig_serial,
        /*transport_class_trigger=*/0xA0, route_prefix, server_app_path);
    auto server_raw = scanner.send_explicit_raw(0x54, server_wire.cm_path, server_wire.service_data);
    if (!server_raw.response.status.is_success()) {
        uint16_t ext = server_raw.response.status.additional_status.empty()
            ? 0 : server_raw.response.status.additional_status[0];
        char err[160];
        std::snprintf(err, sizeof(err),
                       "Server Forward Open failed: GS=0x%02X ES=0x%04X",
                       server_raw.response.status.general_status, ext);
        throw std::runtime_error(err);
    }
    const auto& srd = server_raw.response.data;
    if (srd.size() < 26) throw std::runtime_error("Server FO: response too short");
    conn->server_oto_t_id_ = ser::read_udint(srd);
    conn->server_tto_o_id_ = ser::read_udint(std::span<const uint8_t>(srd).subspan(4));
    uint8_t app_reply_size_words = srd[24];
    if (app_reply_size_words > 0
        && srd.size() >= 26u + static_cast<size_t>(app_reply_size_words) * 2u) {
        conn->target_app_reply_ = SafetyAppReply::parse(
            std::span<const uint8_t>(srd).subspan(26));
    }

    // Target UDP endpoint from Sockaddr Info O->T.
    bool got_endpoint = false;
    for (const auto& item : server_raw.cpf_items) {
        if (item.type_id == cip::CpfItemType::SockaddrInfoOtoT && item.data.size() >= 8) {
            uint16_t port = static_cast<uint16_t>((item.data[2] << 8) | item.data[3]);
            char ip[64];
            std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                          item.data[4], item.data[5], item.data[6], item.data[7]);
            std::string ip_str(ip);
            if (ip_str == "0.0.0.0") ip_str = scanner.remote_endpoint().host;
            conn->server_target_endpoint_ = protocol::IpEndpoint{ip_str, port};
            got_endpoint = true;
            break;
        }
    }
    if (!got_endpoint) {
        conn->server_target_endpoint_ = protocol::IpEndpoint{
            scanner.remote_endpoint().host, protocol::EipUdpTransport::IoPort};
    }

    {
        char m[160];
        std::snprintf(m, sizeof(m), "  Server OT=0x%08X TO=0x%08X UDP=%s:%u",
                       conn->server_oto_t_id_, conn->server_tto_o_id_,
                       conn->server_target_endpoint_.host.c_str(),
                       static_cast<unsigned>(conn->server_target_endpoint_.port));
        conn->log(m);
    }

    // ---- Client Forward Open (target produces T->O) ----
    conn->log("Opening client connection (target produces)...");
    auto client_wire = build_safety_forward_open(
        client_config, conn->client_conn_serial_, orig_vendor, orig_serial,
        /*transport_class_trigger=*/0x20, route_prefix, client_app_path);
    auto client_raw = scanner.send_explicit_raw(0x54, client_wire.cm_path, client_wire.service_data);
    if (!client_raw.response.status.is_success()) {
        uint16_t ext = client_raw.response.status.additional_status.empty()
            ? 0 : client_raw.response.status.additional_status[0];
        char err[160];
        std::snprintf(err, sizeof(err),
                       "Client Forward Open failed: GS=0x%02X ES=0x%04X",
                       client_raw.response.status.general_status, ext);
        // Close the server connection we just opened to avoid leaking it.
        conn->send_forward_close(conn->server_conn_serial_);
        throw std::runtime_error(err);
    }
    const auto& crd = client_raw.response.data;
    if (crd.size() < 26) throw std::runtime_error("Client FO: response too short");
    conn->client_oto_t_id_ = ser::read_udint(crd);
    conn->client_tto_o_id_ = ser::read_udint(std::span<const uint8_t>(crd).subspan(4));
    SafetyAppReply client_app_reply{};
    uint8_t client_app_reply_size = crd[24];
    if (client_app_reply_size > 0
        && crd.size() >= 26u + static_cast<size_t>(client_app_reply_size) * 2u) {
        client_app_reply = SafetyAppReply::parse(
            std::span<const uint8_t>(crd).subspan(26));
    }
    {
        char m[160];
        std::snprintf(m, sizeof(m),
                       "  Client OT=0x%08X TO=0x%08X SVInst=%u",
                       conn->client_oto_t_id_, conn->client_tto_o_id_,
                       static_cast<unsigned>(client_app_reply.target_connection_serial));
        conn->log(m);
    }

    // ---- Seeds ----
    uint16_t server_sv_inst = conn->target_app_reply_.target_connection_serial;
    (void)server_sv_inst;  // recorded for context; PID uses our connSerial
    uint16_t client_sv_inst = client_app_reply.target_connection_serial;
    uint16_t tgt_vendor     = conn->target_app_reply_.target_vendor_id;
    uint32_t tgt_serial     = conn->target_app_reply_.target_device_serial;

    conn->pid_seed_s1_     = crc::pid_cid_seed_s1(orig_vendor, orig_serial, conn->server_conn_serial_);
    conn->pid_seed_s3_     = crc::pid_cid_seed_s3(orig_vendor, orig_serial, conn->server_conn_serial_);
    conn->pid_seed_s5_     = crc::pid_cid_seed_s5(orig_vendor, orig_serial, conn->server_conn_serial_);
    conn->tgt_pid_seed_s1_ = crc::pid_cid_seed_s1(tgt_vendor,  tgt_serial,  client_sv_inst);
    conn->tgt_pid_seed_s3_ = crc::pid_cid_seed_s3(tgt_vendor,  tgt_serial,  client_sv_inst);
    conn->tgt_pid_seed_s5_ = crc::pid_cid_seed_s5(tgt_vendor,  tgt_serial,  client_sv_inst);
    conn->cid_seed_s5_     = crc::pid_cid_seed_s5(orig_vendor, orig_serial, conn->client_conn_serial_);

    // ---- Wire up UDP receive — install our handler on the passed transport. ----
    // The transport's existing on_message handler (if any) is replaced; this
    // assumes a single SafetyScannerConnection per UDP transport, which mirrors
    // the C# / Python samples.
    auto* raw_self = conn.get();
    udp.set_on_message([raw_self](std::unique_ptr<msg::Message> m) {
        if (m) raw_self->on_udp_message(*m);
    });

    // ---- Start production thread ----
    conn->open_.store(true);
    uint32_t rpi = server_config.oto_t_rpi != 0 ? server_config.oto_t_rpi : server_config.rpi;
    conn->production_thread_ = std::thread([raw_self, rpi] { raw_self->production_loop(rpi); });

    conn->log("Safety connection open. Producing cold start (run=0, ts=0).");
    return conn;
}

void SafetyScannerConnection::production_loop(uint32_t rpi_us) {
    using clock = std::chrono::steady_clock;
    auto interval = std::chrono::microseconds(std::max<uint32_t>(rpi_us, 1000));
    auto next = clock::now() + interval;
    while (!stop_thread_.load()) {
        produce_server_data();
        std::this_thread::sleep_until(next);
        next += interval;
    }
}

void SafetyScannerConnection::produce_server_data() {
    if (!open_.load()) return;
    try {
        bool active     = consumer_active_.load();
        bool run_idle   = active && run_idle_.load();
        uint16_t ts     = active ? timestamp_.load() : uint16_t{0};
        uint8_t  ping   = ping_count_.load();

        if (active) {
            // RPI/128 µs ticks per send while active. We use a fixed 50 ms RPI
            // → 50000/128 ≈ 390 ticks per send (matches the C# implementation).
            uint16_t prev_ts = timestamp_.fetch_add(static_cast<uint16_t>(50000 / 128));
            uint16_t new_ts  = static_cast<uint16_t>(prev_ts + (50000 / 128));
            if (new_ts < prev_ts) {
                producer_rollover_count_.fetch_add(1);
            }
        }
        auto mode = ModeByte::create(run_idle, ping);

        std::vector<uint8_t> buf(output_data_.size() * 2 + 16);
        int wire_len;
        {
            std::scoped_lock lock(buf_mu_);
            wire_len = frame_codec::encode(
                buf, output_data_, format_, mode, ts,
                pid_seed_s1_, pid_seed_s3_, pid_seed_s5_,
                producer_rollover_count_.load());
        }
        uint32_t seq = server_encap_seq_.fetch_add(1) + 1;
        udp_.send_io_data(server_target_endpoint_, server_oto_t_id_, seq,
                            std::span<const uint8_t>(buf.data(), wire_len));
        tx_count_.fetch_add(1);
    } catch (...) {
        // swallow — production thread must keep running
    }
}

void SafetyScannerConnection::on_udp_message(msg::Message& m) {
    if (!open_.load()) return;
    if (m.kind != msg::MessageKind::CpfConnectedData) return;
    auto& cpf = static_cast<msg::CpfConnectedDataMessage&>(m);

    if (cpf.connection_id == server_tto_o_id_) {
        on_server_tcoo(cpf.payload);
    } else if (cpf.connection_id == client_tto_o_id_) {
        on_client_data(cpf.payload);
    }
}

void SafetyScannerConnection::on_server_tcoo(std::span<const uint8_t> /*payload*/) {
    if (!consumer_active_.exchange(true)) {
        run_idle_.store(true);
        log("Consumer active: transitioning to run=1.");
    }
}

void SafetyScannerConnection::on_client_data(std::span<const uint8_t> payload) {
    int wire_size = static_cast<int>(payload.size());
    if (wire_size == 5 || wire_size == 6) return;  // target TCOO — not expected here

    // Reverse-derive data length from wire size.
    int data_len = -1;
    int short_len = wire_size - 6;
    if (short_len >= 1 && short_len <= 2) {
        data_len = short_len;
    } else {
        int long_len = (wire_size - 8) / 2;
        if (long_len >= 3 && long_len <= 250 && long_len * 2 + 8 == wire_size) {
            data_len = long_len;
        }
    }
    if (data_len <= 0) return;

    // Track the target's 16-bit timestamp and bump tgt_rollover_count on wrap.
    // CRC-S5 mixes in the full 32-bit timestamp (rollover<<16 | ts), so a
    // missed wrap turns into "CRC fail" for the rest of the connection. Must
    // be tracked separately from our own producer's rollover — they wrap on
    // independent schedules.
    uint16_t this_ts  = frame_codec::extract_timestamp(payload, data_len, format_);
    bool initialized  = tgt_rollover_initialized_.exchange(true);
    uint16_t prev_ts  = tgt_last_ts_.exchange(this_ts);
    if (initialized) {
        // Raw int subtraction — a wrap shows as a large-magnitude negative.
        int delta = static_cast<int>(this_ts) - static_cast<int>(prev_ts);
        if (delta < -0x4000) {
            tgt_rollover_count_.fetch_add(1);
        }
    }

    auto result = frame_codec::decode(
        payload, data_len, format_,
        tgt_pid_seed_s1_, tgt_pid_seed_s3_, tgt_pid_seed_s5_,
        tgt_rollover_count_.load());

    // Mode byte is the byte right after data in the wire frame.
    uint8_t mode_byte = (data_len < wire_size) ? payload[data_len] : 0;
    uint8_t target_ping = mode_byte & 0x03;

    uint8_t last = last_target_ping_.load();
    if (last == 0xFF || target_ping != last) {
        last_target_ping_.store(target_ping);
        send_client_tcoo(target_ping);
    }

    if (result.crc_valid) {
        rx_count_.fetch_add(1);
        if (data_received_) data_received_(result.actual_data);
    } else {
        log(std::string("RX CRC FAIL: ") + result.error_message.value_or(""));
    }
}

void SafetyScannerConnection::send_client_tcoo(uint8_t ping_count_reply) {
    std::array<uint8_t, 8> buf{};
    using clk = std::chrono::steady_clock;
    uint64_t tick_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        clk::now().time_since_epoch()).count();
    uint16_t consumer_time = static_cast<uint16_t>((tick_ms * 1000 / 128) & 0xFFFF);

    int len;
    if (format_ == SafetyFormat::Extended) {
        len = frame_codec::encode_time_coordination_extended(
            buf, ping_count_reply, consumer_time, cid_seed_s5_);
    } else {
        len = frame_codec::encode_time_coordination(
            buf, ping_count_reply, consumer_time,
            crc::pid_cid_seed_s3(orig_vendor_, orig_serial_,
                                          target_app_reply_.target_connection_serial));
    }
    uint32_t seq = client_encap_seq_.fetch_add(1) + 1;
    udp_.send_io_data(server_target_endpoint_, client_oto_t_id_, seq,
                        std::span<const uint8_t>(buf.data(), len));
}

void SafetyScannerConnection::close() {
    if (!open_.exchange(false)) return;
    stop_thread_.store(true);

    udp_.set_on_message(nullptr);

    if (production_thread_.joinable()) production_thread_.join();

    try { send_forward_close(server_conn_serial_); } catch (...) {}
    try { send_forward_close(client_conn_serial_); } catch (...) {}
}

void SafetyScannerConnection::send_forward_close(uint16_t conn_serial) {
    // Safety Forward Close timing = 0x05 0x9C. Path includes the route
    // prefix (path size = route_prefix words).
    std::vector<uint8_t> close_data(12 + route_prefix_.size());
    int off = 0;
    close_data[off++] = 0x05; close_data[off++] = 0x9C;
    ser::write_uint (std::span<uint8_t>(close_data).subspan(off), conn_serial); off += 2;
    ser::write_uint (std::span<uint8_t>(close_data).subspan(off), orig_vendor_); off += 2;
    ser::write_udint(std::span<uint8_t>(close_data).subspan(off), orig_serial_); off += 4;
    close_data[off++] = static_cast<uint8_t>(route_prefix_.size() / 2);
    close_data[off++] = 0;
    if (!route_prefix_.empty()) {
        std::memcpy(close_data.data() + off, route_prefix_.data(), route_prefix_.size());
    }
    std::array<uint8_t, 4> cm_path{0x20, 0x06, 0x24, 0x01};
    scanner_.send_explicit_raw(0x4E, cm_path, close_data);
}

} // namespace ethernetip::safety
