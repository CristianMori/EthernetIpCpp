#pragma once

#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace ethernetip::protocol {

/// One accepted TCP client connection. Owns a per-client read thread that
/// invokes on_bytes for each chunk received. Synchronous send() is safe
/// to call from any thread.
class TcpSocketConnection : public std::enable_shared_from_this<TcpSocketConnection> {
public:
    using BytesHandler  = std::function<void(TcpSocketConnection&, std::span<const uint8_t>)>;
    using ClosedHandler = std::function<void(TcpSocketConnection&)>;

    TcpSocketConnection(sock::socket_t socket,
                          IpEndpoint local_endpoint,
                          IpEndpoint remote_endpoint);
    ~TcpSocketConnection();

    TcpSocketConnection(const TcpSocketConnection&) = delete;
    TcpSocketConnection& operator=(const TcpSocketConnection&) = delete;

    [[nodiscard]] const IpEndpoint& local_endpoint()  const noexcept { return local_endpoint_; }
    [[nodiscard]] const IpEndpoint& remote_endpoint() const noexcept { return remote_endpoint_; }

    void set_on_bytes (BytesHandler  h) { on_bytes_  = std::move(h); }
    void set_on_closed(ClosedHandler h) { on_closed_ = std::move(h); }

    /// Start the per-client read thread. Must be called after callbacks are set.
    void start();

    /// Synchronous write. Closes the connection on I/O failure.
    void send(std::span<const uint8_t> data);

    /// Close the socket and join the read thread. Idempotent.
    void close();

private:
    void read_loop();

    sock::socket_t socket_ = sock::invalid;
    IpEndpoint local_endpoint_;
    IpEndpoint remote_endpoint_;
    std::atomic<bool> closed_{false};
    std::thread read_thread_;
    std::mutex send_mu_;

    BytesHandler  on_bytes_;
    ClosedHandler on_closed_;
};

/// Pure TCP listening socket. Accepts client connections on a dedicated
/// accept thread; each accepted client runs on its own thread.
class TcpSocket {
public:
    using AcceptHandler = std::function<void(std::shared_ptr<TcpSocketConnection>)>;

    TcpSocket();
    ~TcpSocket();

    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    /// Set the accept handler. Must be set before start().
    void set_on_accept(AcceptHandler h) { on_accept_ = std::move(h); }

    /// Bind, listen, start the accept thread.
    void start(const IpEndpoint& bind);

    /// Stop accepting and close existing connections. Idempotent.
    void stop();

    [[nodiscard]] uint16_t actual_port() const noexcept { return actual_port_; }

private:
    void accept_loop();

    sock::socket_t listener_ = sock::invalid;
    uint16_t       actual_port_ = 0;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;

    std::mutex connections_mu_;
    std::vector<std::weak_ptr<TcpSocketConnection>> connections_;

    AcceptHandler on_accept_;
};

} // namespace ethernetip::protocol
