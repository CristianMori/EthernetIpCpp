#pragma once

#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/messages.hpp"
#include "ethernetip/protocol/udp_socket.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <span>

namespace ethernetip::protocol {

/// EtherNet/IP UDP I/O transport (port 2222 / 0x08AE). Owns a UdpSocket and
/// parses incoming datagrams into typed CpfConnectedDataMessage objects.
class EipUdpTransport {
public:
    static constexpr uint16_t IoPort = 0x08AE;

    using MessageHandler = std::function<void(std::unique_ptr<messages::Message>)>;

    EipUdpTransport();
    ~EipUdpTransport();

    EipUdpTransport(const EipUdpTransport&) = delete;
    EipUdpTransport& operator=(const EipUdpTransport&) = delete;

    /// Handler invoked on the UDP dispatch thread for each parsed message.
    void set_on_message(MessageHandler h) { on_message_ = std::move(h); }

    /// Bind + start.
    void start(const IpEndpoint& bind);

    /// Stop and release the socket.
    void stop();

    /// Send a CPF SequencedAddress + ConnectedData frame. Hot-path —
    /// writes directly into a stack buffer when small enough.
    void send_io_data(const IpEndpoint& destination, uint32_t connection_id,
                       uint32_t encap_seq_num, std::span<const uint8_t> data);

    [[nodiscard]] uint16_t actual_port() const noexcept { return socket_.actual_port(); }

private:
    UdpSocket socket_;
    MessageHandler on_message_;
};

} // namespace ethernetip::protocol
