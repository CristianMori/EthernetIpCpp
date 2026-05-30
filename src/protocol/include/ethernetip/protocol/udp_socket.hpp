#pragma once

#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace ethernetip::protocol {

/// Pure UDP socket abstraction. Owns the OS socket and two threads:
///   rx_thread:       recvfrom into a freshly-allocated buffer, enqueue.
///   dispatch_thread: dequeue, invoke on_packet, free buffer.
/// Decoupling receive from dispatch keeps a slow handler from causing
/// socket-buffer overflows.
class UdpSocket {
public:
    using PacketHandler = std::function<void(std::span<const uint8_t>, const IpEndpoint&)>;

    UdpSocket();
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    /// Set the packet handler. Called on the dispatch thread for each packet.
    /// Must be set before start().
    void set_on_packet(PacketHandler h) { on_packet_ = std::move(h); }

    /// Bind + start rx + dispatch threads. host may be "" or "0.0.0.0".
    void start(const IpEndpoint& bind);

    /// Send a UDP packet. Thread-safe.
    void send(const IpEndpoint& destination, std::span<const uint8_t> data);

    /// Stop threads and close socket. Idempotent.
    void stop();

    [[nodiscard]] uint16_t actual_port() const noexcept { return actual_port_; }

private:
    struct RxPacket {
        std::vector<uint8_t> data;
        IpEndpoint remote;
    };

    void rx_loop();
    void dispatch_loop();

    sock::socket_t socket_ = sock::invalid;
    uint16_t       actual_port_ = 0;
    std::atomic<bool> running_{false};

    std::thread rx_thread_;
    std::thread dispatch_thread_;

    std::mutex              queue_mu_;
    std::condition_variable queue_cv_;
    std::deque<RxPacket>    queue_;

    PacketHandler on_packet_;
};

} // namespace ethernetip::protocol
