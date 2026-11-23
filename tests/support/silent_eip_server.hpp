#pragma once

// Test double: a minimal EtherNet/IP target that accepts one TCP client,
// answers RegisterSession (unless told to stay silent from the start) and
// optionally the first SendRRData as a successful Forward_Open, and then
// never replies to anything. Used to exercise client request timeouts.

#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

namespace ethernetip::test {

class SilentEipServer {
public:
    struct Options {
        bool answer_register_session = true;   ///< false: silent from the start
        bool answer_first_forward_open = false; ///< reply once to the first SendRRData
    };

    SilentEipServer() : SilentEipServer(Options{}) {}
    explicit SilentEipServer(Options opts) : opts_(opts) {
        using namespace ethernetip::protocol;
        sock::ensure_initialized();
        listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        sock::to_sockaddr(IpEndpoint{"127.0.0.1", 0}, a);
        ::bind(listener_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(listener_, 4);
        socklen_t len = sizeof(a);
        ::getsockname(listener_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        thread_ = std::thread([this] { run(); });
    }

    ~SilentEipServer() {
        using namespace ethernetip::protocol;
        stop_ = true;
        // Unblock accept() by connecting to ourselves, then drop the client.
        {
            auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in a{};
            sock::to_sockaddr(IpEndpoint{"127.0.0.1", port_}, a);
            ::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
            sock::close(s);
        }
        auto c = client_.load();
        if (c != sock::invalid) ::shutdown(c, 2);
        if (thread_.joinable()) thread_.join();
        sock::close(listener_);
    }

    SilentEipServer(const SilentEipServer&) = delete;
    SilentEipServer& operator=(const SilentEipServer&) = delete;

    [[nodiscard]] uint16_t port() const noexcept { return port_; }

private:
    static constexpr uint32_t kSession = 0x1234ABCD;

    static uint16_t u16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
    static void put16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(x & 0xFF); v.push_back(x >> 8); }
    static void put32(std::vector<uint8_t>& v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xFF); }

    bool recv_all(ethernetip::protocol::sock::socket_t s, uint8_t* dst, size_t n) {
        size_t got = 0;
        while (got < n) {
            int r = ::recv(s, reinterpret_cast<char*>(dst + got), static_cast<int>(n - got), 0);
            if (r <= 0) return false;
            got += static_cast<size_t>(r);
        }
        return true;
    }

    void reply(ethernetip::protocol::sock::socket_t s, const uint8_t* req_hdr,
               uint16_t command, const std::vector<uint8_t>& body) {
        std::vector<uint8_t> out;
        put16(out, command);
        put16(out, static_cast<uint16_t>(body.size()));
        put32(out, kSession);
        put32(out, 0);                                   // status
        out.insert(out.end(), req_hdr + 12, req_hdr + 20); // sender context
        put32(out, 0);                                   // options
        out.insert(out.end(), body.begin(), body.end());
        ::send(s, reinterpret_cast<const char*>(out.data()), static_cast<int>(out.size()), 0);
    }

    void run() {
        using namespace ethernetip::protocol;
        sockaddr_in ra{};
        socklen_t rl = sizeof(ra);
        sock::socket_t c = ::accept(listener_, reinterpret_cast<sockaddr*>(&ra), &rl);
        if (c == sock::invalid || stop_) { if (c != sock::invalid) sock::close(c); return; }
        client_ = c;
        bool fo_pending = opts_.answer_first_forward_open;
        for (;;) {
            uint8_t hdr[24];
            if (!recv_all(c, hdr, sizeof(hdr))) break;
            uint16_t cmd = u16(hdr), len = u16(hdr + 2);
            std::vector<uint8_t> payload(len);
            if (len && !recv_all(c, payload.data(), len)) break;
            if (cmd == 0x0065 && opts_.answer_register_session) {
                reply(c, hdr, cmd, {1, 0, 0, 0});
            } else if (cmd == 0x006F && fo_pending) {
                fo_pending = false;
                // MR reply: service 0xD4, reserved, status 0, ext 0, then
                // O->T id, T->O id, serial, vendor, orig serial, ...
                std::vector<uint8_t> mr{0xD4, 0, 0, 0};
                put32(mr, 0x11110001); put32(mr, 0x22220002);
                put16(mr, 1); put16(mr, 1); put32(mr, 1);
                put32(mr, 1000000); put32(mr, 1000000);
                mr.push_back(0); mr.push_back(0);
                std::vector<uint8_t> body;
                put32(body, 0); put16(body, 0);          // interface + timeout
                put16(body, 2);                          // item count
                put16(body, 0x0000); put16(body, 0);     // NullAddress
                put16(body, 0x00B2); put16(body, static_cast<uint16_t>(mr.size()));
                body.insert(body.end(), mr.begin(), mr.end());
                reply(c, hdr, cmd, body);
            }
            // Everything else: stay silent.
        }
        client_ = sock::invalid;
        sock::close(c);
    }

    Options opts_;
    ethernetip::protocol::sock::socket_t listener_ = ethernetip::protocol::sock::invalid;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::atomic<ethernetip::protocol::sock::socket_t> client_{ethernetip::protocol::sock::invalid};
    std::thread thread_;
};

/// Seconds-resolution helper for "returned within N ms" assertions.
template <class F>
std::chrono::milliseconds elapsed_ms(F&& f) {
    auto t0 = std::chrono::steady_clock::now();
    f();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
}

} // namespace ethernetip::test
