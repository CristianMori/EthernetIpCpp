#include "ethernetip/protocol/tcp_socket.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace ethernetip::protocol {

// ---- TcpSocketConnection --------------------------------------------------

TcpSocketConnection::TcpSocketConnection(sock::socket_t socket,
                                            IpEndpoint local_endpoint,
                                            IpEndpoint remote_endpoint)
    : socket_(socket),
      local_endpoint_(std::move(local_endpoint)),
      remote_endpoint_(std::move(remote_endpoint)) {}

TcpSocketConnection::~TcpSocketConnection() {
    close();
}

void TcpSocketConnection::start() {
    read_thread_ = std::thread([self = shared_from_this()] {
        try { self->read_loop(); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "ethernetip TcpSocketConnection read_loop: %s\n", e.what());
        }
    });
}

void TcpSocketConnection::send(std::span<const uint8_t> data) {
    if (closed_.load()) return;
    std::scoped_lock lock(send_mu_);
    size_t total = 0;
    while (total < data.size()) {
        int n = ::send(socket_,
                        reinterpret_cast<const char*>(data.data() + total),
                        static_cast<int>(data.size() - total), 0);
        if (n <= 0) {
            close();
            return;
        }
        total += static_cast<size_t>(n);
    }
}

void TcpSocketConnection::close() {
    if (closed_.exchange(true)) return;
    if (socket_ != sock::invalid) {
        sock::close(socket_);
        socket_ = sock::invalid;
    }
    if (read_thread_.joinable()
        && std::this_thread::get_id() != read_thread_.get_id()) {
        read_thread_.join();
    } else if (read_thread_.joinable()) {
        read_thread_.detach();
    }
}

void TcpSocketConnection::read_loop() {
    constexpr int kBufSize = 4096;
    std::vector<uint8_t> buf(kBufSize);
    while (!closed_.load()) {
        int n = ::recv(socket_, reinterpret_cast<char*>(buf.data()), kBufSize, 0);
        if (n <= 0) break;  // peer closed or error
        if (on_bytes_) {
            try { on_bytes_(*this, std::span<const uint8_t>(buf.data(), n)); }
            catch (const std::exception& e) {
                std::fprintf(stderr, "ethernetip TcpSocketConnection on_bytes: %s\n", e.what());
            }
        }
    }
    if (on_closed_) {
        try { on_closed_(*this); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "ethernetip TcpSocketConnection on_closed: %s\n", e.what());
        }
    }
    close();
}

// ---- TcpSocket ------------------------------------------------------------

TcpSocket::TcpSocket() {
    sock::ensure_initialized();
}

TcpSocket::~TcpSocket() {
    stop();
}

void TcpSocket::start(const IpEndpoint& bind) {
    if (running_.exchange(true)) return;

    listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener_ == sock::invalid) {
        running_ = false;
        throw std::runtime_error("TcpSocket: socket() failed");
    }
    int reuse = 1;
    ::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR,
                  reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    sock::to_sockaddr(bind, addr);
    if (::bind(listener_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == sock::sockerr) {
        sock::close(listener_);
        listener_ = sock::invalid;
        running_  = false;
        throw std::runtime_error("TcpSocket: bind() failed");
    }
    if (::listen(listener_, 16) == sock::sockerr) {
        sock::close(listener_);
        listener_ = sock::invalid;
        running_  = false;
        throw std::runtime_error("TcpSocket: listen() failed");
    }

    sockaddr_in actual{};
    socklen_t actual_len = sizeof(actual);
    if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&actual), &actual_len) == 0) {
        actual_port_ = ntohs(actual.sin_port);
    } else {
        actual_port_ = bind.port;
    }

    accept_thread_ = std::thread([this] {
        try { accept_loop(); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "ethernetip TcpSocket accept_loop: %s\n", e.what());
        }
    });
}

void TcpSocket::stop() {
    if (!running_.exchange(false)) return;

    if (listener_ != sock::invalid) {
        sock::close(listener_);
        listener_ = sock::invalid;
    }
    if (accept_thread_.joinable()) accept_thread_.join();

    std::vector<std::shared_ptr<TcpSocketConnection>> live;
    {
        std::scoped_lock lock(connections_mu_);
        for (auto& wp : connections_) {
            if (auto sp = wp.lock()) live.push_back(std::move(sp));
        }
        connections_.clear();
    }
    for (auto& conn : live) conn->close();
}

void TcpSocket::accept_loop() {
    while (running_.load()) {
        sockaddr_in remote{};
        socklen_t   remote_len = sizeof(remote);
        sock::socket_t client = ::accept(listener_,
                                           reinterpret_cast<sockaddr*>(&remote),
                                           &remote_len);
        if (client == sock::invalid) break;  // listener was closed

        sockaddr_in local{};
        socklen_t   local_len = sizeof(local);
        IpEndpoint local_ep, remote_ep = sock::from_sockaddr(remote);
        if (::getsockname(client, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
            local_ep = sock::from_sockaddr(local);
        }

        auto conn = std::make_shared<TcpSocketConnection>(client, local_ep, remote_ep);
        {
            std::scoped_lock lock(connections_mu_);
            connections_.push_back(conn);
        }
        if (on_accept_) {
            try { on_accept_(conn); }
            catch (const std::exception& e) {
                std::fprintf(stderr, "ethernetip TcpSocket on_accept: %s\n", e.what());
            }
        }
        conn->start();
    }
}

} // namespace ethernetip::protocol
