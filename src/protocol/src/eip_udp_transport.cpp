#include "ethernetip/protocol/eip_udp_transport.hpp"

#include <vector>

namespace ethernetip::protocol {

EipUdpTransport::EipUdpTransport() {
    socket_.set_on_packet(
        [this](std::span<const uint8_t> data, const IpEndpoint& remote) {
            auto msg = messages::CpfConnectedDataMessage::try_parse(data, remote);
            if (!msg) return;
            if (on_message_) on_message_(std::move(msg));
        });
}

EipUdpTransport::~EipUdpTransport() { stop(); }

void EipUdpTransport::start(const IpEndpoint& bind) {
    socket_.start(bind);
}

void EipUdpTransport::stop() {
    socket_.stop();
}

void EipUdpTransport::send_io_data(const IpEndpoint& destination, uint32_t connection_id,
                                     uint32_t encap_seq_num,
                                     std::span<const uint8_t> data) {
    const size_t total = messages::CpfConnectedDataMessage::CpfOverhead + data.size();
    std::vector<uint8_t> buf(total);
    messages::CpfConnectedDataMessage::write_wire(buf, connection_id, encap_seq_num, data);
    socket_.send(destination, buf);
}

} // namespace ethernetip::protocol
