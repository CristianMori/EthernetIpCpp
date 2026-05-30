#include "ethernetip/protocol/udp_socket.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace ethernetip::protocol {

UdpSocket::UdpSocket() {
    sock::ensure_initialized();
}

UdpSocket::~UdpSocket() {
    stop();
}

void UdpSocket::start(const IpEndpoint& bind) {
    if (running_.exchange(true)) return;

    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == sock::invalid) {
        running_ = false;
        throw std::runtime_error("UdpSocket: socket() failed");
    }

    // Generous OS buffers so brief processing stalls can't cause kernel drops.
    int rxbuf = 4 * 1024 * 1024;
    int txbuf = 1 * 1024 * 1024;
    ::setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
                  reinterpret_cast<const char*>(&rxbuf), sizeof(rxbuf));
    ::setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
                  reinterpret_cast<const char*>(&txbuf), sizeof(txbuf));

    // Windows: disable ICMP-driven WSAECONNRESET on subsequent recv after an
    // unreachable destination — otherwise a transient PLC stall silently
    // kills the receive loop.
#ifdef _WIN32
    constexpr DWORD SIO_UDP_CONNRESET_LOCAL = 0x9800000C;  // _WSAIOW(IOC_VENDOR, 12)
    BOOL behavior = FALSE;
    DWORD returned = 0;
    ::WSAIoctl(socket_, SIO_UDP_CONNRESET_LOCAL,
                &behavior, sizeof(behavior),
                nullptr, 0, &returned, nullptr, nullptr);
#endif

    sockaddr_in addr{};
    sock::to_sockaddr(bind, addr);
    if (::bind(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == sock::sockerr) {
        sock::close(socket_);
        socket_ = sock::invalid;
        running_ = false;
        throw std::runtime_error("UdpSocket: bind() failed");
    }

    sockaddr_in actual{};
    socklen_t actual_len = sizeof(actual);
    if (::getsockname(socket_, reinterpret_cast<sockaddr*>(&actual), &actual_len) == 0) {
        actual_port_ = ntohs(actual.sin_port);
    } else {
        actual_port_ = bind.port;
    }

    rx_thread_ = std::thread([this] {
        try { rx_loop(); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "ethernetip UdpSocket rx_loop: %s\n", e.what());
        }
    });
    dispatch_thread_ = std::thread([this] {
        try { dispatch_loop(); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "ethernetip UdpSocket dispatch_loop: %s\n", e.what());
        }
    });
}

void UdpSocket::send(const IpEndpoint& destination, std::span<const uint8_t> data) {
    if (socket_ == sock::invalid) return;
    sockaddr_in addr{};
    sock::to_sockaddr(destination, addr);
    ::sendto(socket_, reinterpret_cast<const char*>(data.data()),
             static_cast<int>(data.size()), 0,
             reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

void UdpSocket::stop() {
    if (!running_.exchange(false)) return;

    if (socket_ != sock::invalid) {
        sock::close(socket_);
        socket_ = sock::invalid;
    }

    {
        std::scoped_lock lock(queue_mu_);
        queue_.emplace_back();   // sentinel to wake dispatch
    }
    queue_cv_.notify_all();

    if (rx_thread_.joinable())       rx_thread_.join();
    if (dispatch_thread_.joinable()) dispatch_thread_.join();
}

void UdpSocket::rx_loop() {
    constexpr int kBufSize = 2048;
    std::vector<uint8_t> buf(kBufSize);
    sockaddr_in remote{};
    socklen_t remote_len = sizeof(remote);

    while (running_.load()) {
        int n = ::recvfrom(socket_, reinterpret_cast<char*>(buf.data()),
                            kBufSize, 0,
                            reinterpret_cast<sockaddr*>(&remote), &remote_len);
        if (n <= 0) {
            // Socket closed via stop() — exit loop.
            if (!running_.load()) break;
            // Transient error; keep going.
            continue;
        }
        RxPacket pkt;
        pkt.data.assign(buf.begin(), buf.begin() + n);
        pkt.remote = sock::from_sockaddr(remote);
        {
            std::scoped_lock lock(queue_mu_);
            queue_.push_back(std::move(pkt));
        }
        queue_cv_.notify_one();
        remote_len = sizeof(remote);  // recvfrom mutates the in/out length param
    }
}

void UdpSocket::dispatch_loop() {
    while (running_.load()) {
        RxPacket pkt;
        {
            std::unique_lock lock(queue_mu_);
            queue_cv_.wait(lock, [this] {
                return !queue_.empty() || !running_.load();
            });
            if (queue_.empty()) continue;
            pkt = std::move(queue_.front());
            queue_.pop_front();
        }
        // Sentinel sent by stop()
        if (!running_.load() && pkt.data.empty()) break;
        if (on_packet_ && !pkt.data.empty()) {
            try { on_packet_(pkt.data, pkt.remote); }
            catch (const std::exception& e) {
                std::fprintf(stderr, "ethernetip UdpSocket on_packet: %s\n", e.what());
            }
        }
    }
}

} // namespace ethernetip::protocol
