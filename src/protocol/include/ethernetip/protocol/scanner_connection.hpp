#pragma once

#include "ethernetip/protocol/eip_udp_transport.hpp"
#include "ethernetip/protocol/forward_open_config.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/messages.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace ethernetip::protocol {

class EipScanner;  // forward

/// One active I/O connection on the scanner (originator) side.
/// Produces O->T data at the configured RPI; consumes T->O frames from the
/// target. Owns a background production thread; `data_received_handler`
/// fires (on the UDP dispatch thread) whenever a target frame arrives.
class ScannerConnection {
public:
    using DataReceivedHandler = std::function<void(std::span<const uint8_t>)>;

    ~ScannerConnection();
    ScannerConnection(const ScannerConnection&)            = delete;
    ScannerConnection& operator=(const ScannerConnection&) = delete;

    [[nodiscard]] const ForwardOpenConfig& config()           const noexcept { return config_; }
    [[nodiscard]] const IpEndpoint&        target_endpoint()  const noexcept { return target_endpoint_; }
    [[nodiscard]] bool                     is_open()          const noexcept { return open_.load(); }

    [[nodiscard]] uint64_t send_count()    const noexcept { return send_count_.load(); }
    [[nodiscard]] uint64_t receive_count() const noexcept { return receive_count_.load(); }

    void set_data_received_handler(DataReceivedHandler h) { data_received_ = std::move(h); }

    /// Snapshot of the latest T->O frame received from the target.
    [[nodiscard]] std::vector<uint8_t> get_produced_data() const;

    /// Replace the O->T data sent on the next production cycle. Truncates if
    /// `data` is larger than the configured consumed_size.
    void set_consumed_data(std::span<const uint8_t> data);

    template <class T>
    void write(int byte_offset, T value) {
        static_assert(std::is_trivially_copyable_v<T>);
        std::scoped_lock lock(buf_mu_);
        std::memcpy(consumed_data_.data() + byte_offset, &value, sizeof(T));
    }

    template <class T>
    [[nodiscard]] T read(int byte_offset = 0) const {
        static_assert(std::is_trivially_copyable_v<T>);
        T out{};
        std::scoped_lock lock(buf_mu_);
        std::memcpy(&out, produced_data_.data() + byte_offset, sizeof(T));
        return out;
    }

    /// Send Forward Close and stop the production thread. Idempotent.
    void close();

    // ---- Internal API for EipScanner ----
    ScannerConnection(EipScanner& scanner,
                       EipUdpTransport& udp,
                       ForwardOpenConfig config,
                       IpEndpoint target_endpoint,
                       uint32_t oto_t_connection_id,
                       uint32_t tto_o_connection_id,
                       uint16_t connection_serial,
                       uint16_t originator_vendor,
                       uint32_t originator_serial);

    void start();
    void on_udp_message(messages::Message& msg);

private:
    void production_loop();

    EipScanner&       scanner_;
    EipUdpTransport&  udp_;
    ForwardOpenConfig config_;
    IpEndpoint        target_endpoint_;
    uint32_t          oto_t_connection_id_;
    uint32_t          tto_o_connection_id_;
    uint16_t          connection_serial_;
    uint16_t          originator_vendor_;
    uint32_t          originator_serial_;

    mutable std::mutex buf_mu_;
    std::vector<uint8_t> consumed_data_;   ///< O->T payload
    std::vector<uint8_t> produced_data_;   ///< T->O payload (latest)

    std::atomic<uint32_t> encap_seq_num_{0};
    std::atomic<uint16_t> cip_seq_count_{0};
    std::atomic<bool>     open_{true};

    std::atomic<uint64_t> send_count_{0};
    std::atomic<uint64_t> receive_count_{0};

    DataReceivedHandler data_received_;

    std::thread       production_thread_;
    std::atomic<bool> stop_thread_{false};
};

} // namespace ethernetip::protocol
