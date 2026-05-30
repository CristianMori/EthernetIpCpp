#include "ethernetip/protocol/scanner_connection.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/protocol/eip_scanner.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace ethernetip::protocol {

namespace ser = cip::serializer;
using namespace std::chrono_literals;

ScannerConnection::ScannerConnection(EipScanner& scanner,
                                       EipUdpTransport& udp,
                                       ForwardOpenConfig config,
                                       IpEndpoint target_endpoint,
                                       uint32_t oto_t_connection_id,
                                       uint32_t tto_o_connection_id,
                                       uint16_t connection_serial,
                                       uint16_t originator_vendor,
                                       uint32_t originator_serial)
    : scanner_(scanner),
      udp_(udp),
      config_(config),
      target_endpoint_(std::move(target_endpoint)),
      oto_t_connection_id_(oto_t_connection_id),
      tto_o_connection_id_(tto_o_connection_id),
      connection_serial_(connection_serial),
      originator_vendor_(originator_vendor),
      originator_serial_(originator_serial),
      consumed_data_(config.consumed_size),
      produced_data_(config.produced_size) {}

ScannerConnection::~ScannerConnection() {
    close();
}

std::vector<uint8_t> ScannerConnection::get_produced_data() const {
    std::scoped_lock lock(buf_mu_);
    return produced_data_;
}

void ScannerConnection::set_consumed_data(std::span<const uint8_t> data) {
    std::scoped_lock lock(buf_mu_);
    int n = std::min<int>(static_cast<int>(data.size()), static_cast<int>(consumed_data_.size()));
    if (n > 0) std::memcpy(consumed_data_.data(), data.data(), n);
}

void ScannerConnection::start() {
    scanner_.register_udp_route(tto_o_connection_id_,
        [this](messages::Message& m) { on_udp_message(m); });
    production_thread_ = std::thread([this] { production_loop(); });
}

void ScannerConnection::close() {
    if (!open_.exchange(false)) return;   // already closing/closed
    stop_thread_.store(true);
    scanner_.unregister_udp_route(tto_o_connection_id_);
    if (production_thread_.joinable()) production_thread_.join();

    try {
        scanner_.forward_close(connection_serial_, originator_vendor_, originator_serial_);
    } catch (...) {}
}

void ScannerConnection::production_loop() {
    using clock = std::chrono::steady_clock;
    auto interval = std::chrono::microseconds(std::max<uint32_t>(config_.rpi, 1000));
    auto next = clock::now() + interval;

    while (!stop_thread_.load()) {
        try {
            uint32_t seq = encap_seq_num_.fetch_add(1) + 1;

            std::vector<uint8_t> frame;
            std::scoped_lock lock(buf_mu_);
            if (config_.is_class1()) {
                uint16_t cip_seq = cip_seq_count_.fetch_add(1) + 1;
                frame.resize(2u + 4u + consumed_data_.size());
                ser::write_uint (frame, cip_seq);
                ser::write_udint(std::span<uint8_t>(frame).subspan(2), 0x00000001u);  // RUN
                if (!consumed_data_.empty()) {
                    std::memcpy(frame.data() + 6, consumed_data_.data(), consumed_data_.size());
                }
            } else {
                frame = consumed_data_;
            }
            udp_.send_io_data(target_endpoint_, oto_t_connection_id_, seq, frame);
            send_count_.fetch_add(1);
        } catch (...) {
            // swallow send errors; production thread must keep running
        }

        std::this_thread::sleep_until(next);
        next += interval;
    }
}

void ScannerConnection::on_udp_message(messages::Message& msg) {
    if (msg.kind != messages::MessageKind::CpfConnectedData) return;
    auto& cpf = static_cast<messages::CpfConnectedDataMessage&>(msg);
    if (cpf.connection_id != tto_o_connection_id_) return;
    if (!open_.load()) return;

    std::span<const uint8_t> payload = cpf.payload;
    if (config_.is_class1() && payload.size() >= 2) {
        payload = payload.subspan(2);  // strip CIP sequence count
    }
    {
        std::scoped_lock lock(buf_mu_);
        int n = std::min<int>(static_cast<int>(payload.size()),
                                static_cast<int>(produced_data_.size()));
        if (n > 0) std::memcpy(produced_data_.data(), payload.data(), n);
    }
    receive_count_.fetch_add(1);
    if (data_received_) data_received_(payload);
}

} // namespace ethernetip::protocol
