#pragma once

#include "ethernetip/protocol/eip_scanner.hpp"
#include "ethernetip/protocol/eip_udp_transport.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/safety/safety_forward_open_builder.hpp"
#include "ethernetip/safety/safety_types.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace ethernetip::safety {

/// Parsed safety application reply from a Forward Open response — covers
/// both the Base (10-byte) and Extended (14-byte) forms.
struct SafetyAppReply {
    uint16_t consumer_number          = 0;
    uint16_t target_vendor_id         = 0;
    uint32_t target_device_serial     = 0;
    uint16_t target_connection_serial = 0;   ///< Safety Validator instance ID
    uint16_t initial_timestamp        = 0;
    uint16_t initial_rollover_value   = 0;

    [[nodiscard]] static SafetyAppReply parse(std::span<const uint8_t> data);
};

/// CIP Safety scanner (originator) connection. Owns two Forward Opens —
/// a "server" connection (we produce O->T frames, target sends TCOO back)
/// and a "client" connection (target produces T->O frames, we send TCOO).
/// One UDP transport (typically `EipScanner::udp_transport()`) shared with
/// other connections via the scanner's UDP route registry.
class SafetyScannerConnection {
public:
    using DataReceivedHandler = std::function<void(std::span<const uint8_t>)>;
    using LogHandler          = std::function<void(const std::string&)>;

    ~SafetyScannerConnection();
    SafetyScannerConnection(const SafetyScannerConnection&)            = delete;
    SafetyScannerConnection& operator=(const SafetyScannerConnection&) = delete;

    /// Open a safety connection pair to a target device.
    ///   server_config  — config for our O->T (we produce safety data)
    ///   client_config  — config for our T<-O (target produces, we consume)
    ///   route_prefix   — port-segment bytes for backplane routing (e.g. {0x01, slot})
    ///   server_app_path / client_app_path — electronic key + assembly path
    ///                                          (if empty, uses standard shortcut)
    [[nodiscard]] static std::unique_ptr<SafetyScannerConnection> open(
        protocol::EipScanner&             scanner,
        protocol::EipUdpTransport&        udp,
        const SafetyForwardOpenConfig&    server_config,
        const SafetyForwardOpenConfig&    client_config,
        uint16_t                          originator_vendor,
        uint32_t                          originator_serial,
        std::span<const uint8_t>          route_prefix      = {},
        std::span<const uint8_t>          server_app_path   = {},
        std::span<const uint8_t>          client_app_path   = {});

    /// Replace the safety output data sent on the next O->T cycle. Caller
    /// owns the bytes; the connection takes a snapshot.
    void set_output_data(std::span<const uint8_t> data);

    /// Fires (on the UDP dispatch thread) for each valid T<-O safety frame.
    void set_data_received_handler(DataReceivedHandler h) { data_received_ = std::move(h); }

    /// Fires for log messages (incl. transition notifications, CRC errors).
    void set_log_handler(LogHandler h) { log_ = std::move(h); }

    [[nodiscard]] bool   is_open()     const noexcept { return open_.load(); }
    [[nodiscard]] uint64_t tx_count()  const noexcept { return tx_count_.load(); }
    [[nodiscard]] uint64_t rx_count()  const noexcept { return rx_count_.load(); }

    /// Send Forward Closes and stop production. Idempotent.
    void close();

private:
    SafetyScannerConnection(protocol::EipScanner&        scanner,
                              protocol::EipUdpTransport& udp,
                              SafetyFormat               format);

    void on_udp_message(protocol::messages::Message& msg);
    void on_server_tcoo(std::span<const uint8_t> payload);
    void on_client_data(std::span<const uint8_t> payload);
    void send_client_tcoo(uint8_t ping_count_reply);
    void produce_server_data();
    void production_loop(uint32_t rpi_us);
    void send_forward_close(uint16_t conn_serial);
    void log(const std::string& msg) const { if (log_) log_(msg); }

    // ---- Refs / config ----
    protocol::EipScanner&      scanner_;
    protocol::EipUdpTransport& udp_;
    SafetyFormat               format_;

    // ---- Connection IDs ----
    uint32_t server_oto_t_id_ = 0;   // target chose
    uint32_t server_tto_o_id_ = 0;   // we chose
    uint32_t client_oto_t_id_ = 0;   // target chose
    uint32_t client_tto_o_id_ = 0;   // we chose
    uint16_t server_conn_serial_ = 0;
    uint16_t client_conn_serial_ = 0;
    protocol::IpEndpoint server_target_endpoint_;

    // ---- Identity ----
    uint16_t orig_vendor_ = 0;
    uint32_t orig_serial_ = 0;
    SafetyAppReply target_app_reply_{};

    // ---- PID / CID seeds ----
    uint8_t  pid_seed_s1_     = 0;
    uint16_t pid_seed_s3_     = 0;
    uint32_t pid_seed_s5_     = 0;
    uint8_t  tgt_pid_seed_s1_ = 0;
    uint16_t tgt_pid_seed_s3_ = 0;
    uint32_t tgt_pid_seed_s5_ = 0;
    uint32_t cid_seed_s5_     = 0;

    // ---- Mode-byte state ----
    std::atomic<bool>     run_idle_{false};
    std::atomic<uint8_t>  ping_count_{0};
    std::atomic<bool>     consumer_active_{false};
    std::atomic<uint16_t> timestamp_{0};
    /// Our producer's rollover (used by encode on server O->T). Seeded from
    /// server_config.initial_rollover_value at open, incremented in
    /// produce_server_data every time timestamp_ wraps 0xFFFF -> 0x0000.
    /// Extended-format CRC-S5 folds this into the seed, so any spec-compliant
    /// consumer would drift out of sync after the first ~8.4 s if this
    /// counter stayed at 0.
    std::atomic<uint16_t> producer_rollover_count_{0};
    /// Target's producer rollover (used by decode on client T<-O). Advanced
    /// here on every observed wire-timestamp wrap. Must be kept distinct
    /// from the producer rollover above — they wrap on independent schedules.
    std::atomic<uint16_t> tgt_rollover_count_{0};
    std::atomic<uint16_t> tgt_last_ts_{0};
    std::atomic<bool>     tgt_rollover_initialized_{false};
    std::atomic<uint8_t>  last_target_ping_{0xFF};

    // ---- Production ----
    std::thread        production_thread_;
    std::atomic<bool>  stop_thread_{false};
    std::atomic<uint32_t> server_encap_seq_{0};
    std::atomic<uint32_t> client_encap_seq_{0};

    mutable std::mutex   buf_mu_;
    std::vector<uint8_t> output_data_;
    int                  input_data_size_ = 0;

    // ---- Misc ----
    std::vector<uint8_t> route_prefix_;
    std::atomic<bool>    open_{false};
    std::atomic<uint64_t> tx_count_{0};
    std::atomic<uint64_t> rx_count_{0};

    DataReceivedHandler data_received_;
    LogHandler          log_;
};

} // namespace ethernetip::safety
