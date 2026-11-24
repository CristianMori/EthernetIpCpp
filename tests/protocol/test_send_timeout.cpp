// Client send timeout: a peer that accepts the connection but stops reading
// must not hang a client in send() once the TCP buffers are full. A send is
// bounded by the request timeout and treated like a missed reply: the
// connection is closed, the session dropped and RequestTimeoutError thrown.
//
// Forcing a hang deterministically: the peer sets a tiny SO_RCVBUF, answers
// RegisterSession, pre-queues many canned replies (so the client's reply
// waits never block) and then never calls recv() again. The client keeps
// sending ~60 KB requests until the kernel buffers are full; the request
// that no longer fits can only fail in send().

#include "ethernetip/logix/tag_client.hpp"
#include "ethernetip/protocol/eip_scanner.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <thread>
#include <vector>

using namespace ethernetip::protocol;
using namespace std::chrono_literals;

namespace {

constexpr auto kShort = 300ms;
constexpr auto kBound = kShort + 1500ms;
constexpr int  kMaxRequests = 600;

void put16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(x & 0xFF); v.push_back(x >> 8); }
void put32(std::vector<uint8_t>& v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xFF); }

bool recv_all(sock::socket_t s, uint8_t* dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = ::recv(s, reinterpret_cast<char*>(dst + got), static_cast<int>(n - got), 0);
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

// Accepts one client, answers RegisterSession, queues canned SendRRData
// success replies, then never reads again.
class StalledReaderServer {
public:
    StalledReaderServer() {
        sock::ensure_initialized();
        listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int small = 4096;   // inherited by the accepted socket
        ::setsockopt(listener_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&small), sizeof(small));
        sockaddr_in a{};
        sock::to_sockaddr(IpEndpoint{"127.0.0.1", 0}, a);
        ::bind(listener_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(listener_, 4);
        socklen_t len = sizeof(a);
        ::getsockname(listener_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        thread_ = std::thread([this] { run(); });
    }
    ~StalledReaderServer() {
        stop_ = true;
        {   // unblock accept() if no client ever came
            auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in a{};
            sock::to_sockaddr(IpEndpoint{"127.0.0.1", port_}, a);
            ::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
            sock::close(s);
        }
        if (thread_.joinable()) thread_.join();   // run() closes the client
        sock::close(listener_);
    }
    StalledReaderServer(const StalledReaderServer&) = delete;
    StalledReaderServer& operator=(const StalledReaderServer&) = delete;

    [[nodiscard]] uint16_t port() const noexcept { return port_; }

private:
    static constexpr uint32_t kSession = 0x1234ABCD;

    static std::vector<uint8_t> frame(uint16_t command, const std::vector<uint8_t>& body) {
        std::vector<uint8_t> out;
        put16(out, command);
        put16(out, static_cast<uint16_t>(body.size()));
        put32(out, kSession);
        put32(out, 0);                       // status
        for (int i = 0; i < 8; ++i) out.push_back(0);   // sender context
        put32(out, 0);                       // options
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

    void run() {
        sockaddr_in ra{};
        socklen_t rl = sizeof(ra);
        sock::socket_t c = ::accept(listener_, reinterpret_cast<sockaddr*>(&ra), &rl);
        if (c == sock::invalid || stop_) { if (c != sock::invalid) sock::close(c); return; }
        uint8_t hdr[24];
        uint8_t body[4];
        if (recv_all(c, hdr, sizeof(hdr)) && recv_all(c, body, sizeof(body))) {
            auto reg = frame(0x0065, {1, 0, 0, 0});
            ::send(c, reinterpret_cast<const char*>(reg.data()), static_cast<int>(reg.size()), 0);
            // Canned SendRRData reply: interface(4) timeout(2) items(2)
            // NullAddress + UnconnectedData{reply svc, rsv, status 0, ext 0}.
            std::vector<uint8_t> mr{0xCD, 0, 0, 0};
            std::vector<uint8_t> b;
            put32(b, 0); put16(b, 0); put16(b, 2);
            put16(b, 0x0000); put16(b, 0);
            put16(b, 0x00B2); put16(b, static_cast<uint16_t>(mr.size()));
            b.insert(b.end(), mr.begin(), mr.end());
            auto reply = frame(0x006F, b);
            for (int i = 0; i < kMaxRequests + 10; ++i)
                ::send(c, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0);
            while (!stop_) std::this_thread::sleep_for(20ms);   // never read again
        }
        sock::close(c);
    }

    sock::socket_t listener_ = sock::invalid;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

// connected loopback pair; `peer` never reads.
struct SocketPair {
    sock::socket_t client = sock::invalid, peer = sock::invalid;
    SocketPair() {
        sock::ensure_initialized();
        auto l = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        sock::to_sockaddr(IpEndpoint{"127.0.0.1", 0}, a);
        ::bind(l, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(l, 1);
        socklen_t len = sizeof(a);
        ::getsockname(l, reinterpret_cast<sockaddr*>(&a), &len);
        client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int small = 4096;
        ::setsockopt(client, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&small), sizeof(small));
        ::connect(client, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        peer = ::accept(l, nullptr, nullptr);
        ::setsockopt(peer, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&small), sizeof(small));
        sock::close(l);
    }
    ~SocketPair() {
        if (client != sock::invalid) sock::close(client);
        if (peer != sock::invalid) sock::close(peer);
    }
};

} // namespace

TEST(SendAllTest, TimesOutAgainstPeerThatNeverReads) {
    SocketPair p;
    // Winsock accepts one oversized send whole into an empty buffer, so keep
    // sending until the buffers are really full.
    std::vector<uint8_t> chunk(256u << 10, 0xAB);
    int err = 0;
    sock::SendResult r = sock::SendResult::Ok;
    std::chrono::steady_clock::time_point t0;
    for (int i = 0; i < 2000 && r == sock::SendResult::Ok; ++i) {
        t0 = std::chrono::steady_clock::now();
        r = sock::send_all(p.client, chunk.data(), chunk.size(), t0 + kShort, err);
    }
    auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    EXPECT_EQ(r, sock::SendResult::TimedOut);
    EXPECT_GE(t, kShort - 50ms);
    EXPECT_LE(t, kBound);
}

TEST(SendAllTest, DeliversEverythingToAReadingPeerAcrossPartialSends) {
    SocketPair p;
    constexpr size_t N = 4u << 20;
    std::vector<uint8_t> data(N);
    for (size_t i = 0; i < N; ++i) data[i] = static_cast<uint8_t>(i * 31u);
    std::vector<uint8_t> got(N);
    auto reader = std::async(std::launch::async, [&] { return recv_all(p.peer, got.data(), N); });
    int err = 0;
    auto r = sock::send_all(p.client, data.data(), N,
                            std::chrono::steady_clock::now() + 30s, err);
    EXPECT_EQ(r, sock::SendResult::Ok);
    EXPECT_TRUE(reader.get());
    EXPECT_EQ(got, data);
}

TEST(SendAllTest, NoDeadlineIsAPlainBlockingSend) {
    SocketPair p;
    std::vector<uint8_t> data(2u << 20, 0x5A);
    std::vector<uint8_t> got(data.size());
    auto reader = std::async(std::launch::async, [&] { return recv_all(p.peer, got.data(), got.size()); });
    int err = 0;
    auto r = sock::send_all(p.client, data.data(), data.size(),
                            std::chrono::steady_clock::time_point::max(), err);
    EXPECT_EQ(r, sock::SendResult::Ok);
    EXPECT_TRUE(reader.get());
    EXPECT_EQ(got, data);
}

TEST(SendAllTest, SocketIsBlockingAgainAfterwards) {
    SocketPair p;
    int err = 0;
    const uint8_t one = 1;
    ASSERT_EQ(sock::send_all(p.client, &one, 1, std::chrono::steady_clock::now() + 1s, err),
              sock::SendResult::Ok);
    // A recv on the (now idle) client must block, not fail with EWOULDBLOCK:
    // let a late byte arrive and expect it to be returned.
    std::thread late([&] {
        std::this_thread::sleep_for(150ms);
        (void)::send(p.peer, reinterpret_cast<const char*>(&one), 1, 0);
    });
    uint8_t b = 0;
    int n = ::recv(p.client, reinterpret_cast<char*>(&b), 1, 0);
    late.join();
    EXPECT_EQ(n, 1);
}

TEST(SendTimeoutTest, ScannerSendTimesOutAndDropsSession) {
    StalledReaderServer server;
    EipScanner s;
    s.set_request_timeout(kShort);
    s.connect("127.0.0.1", server.port());
    ASSERT_TRUE(s.is_connected());

    std::vector<uint8_t> data(60000, 0x11);
    bool timed_out = false;
    std::chrono::milliseconds last{0};
    for (int i = 0; i < kMaxRequests && !timed_out; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        try {
            (void)s.send_generic(0x4D, 0x6B, 1, std::nullopt, data);
        } catch (const RequestTimeoutError&) {
            timed_out = true;
        }
        last = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
    }
    ASSERT_TRUE(timed_out) << "buffers never filled";
    EXPECT_GE(last, kShort - 50ms);
    EXPECT_LE(last, kBound);
    EXPECT_FALSE(s.is_connected());
    EXPECT_EQ(s.session_handle(), 0u);
    // The connection is gone: further requests fail fast.
    EXPECT_THROW(s.send_generic(0x4D, 0x6B, 1, std::nullopt, data), std::runtime_error);
}

TEST(SendTimeoutTest, TagClientSendTimesOutAndDropsSession) {
    StalledReaderServer server;
    ethernetip::logix::TagClient c("127.0.0.1", server.port());
    c.set_request_timeout(kShort);
    c.connect();
    ASSERT_TRUE(c.is_connected());

    std::vector<uint8_t> bytes(60000, 0x22);
    bool timed_out = false;
    std::chrono::milliseconds last{0};
    for (int i = 0; i < kMaxRequests && !timed_out; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        try {
            c.write_raw("Big", 0x00C2, static_cast<uint16_t>(bytes.size()), bytes);
        } catch (const RequestTimeoutError&) {
            timed_out = true;
        }
        last = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
    }
    ASSERT_TRUE(timed_out) << "buffers never filled";
    EXPECT_GE(last, kShort - 50ms);
    EXPECT_LE(last, kBound);
    EXPECT_FALSE(c.is_connected());
}

TEST(SendTimeoutTest, ZeroRequestTimeoutLeavesSendUnbounded) {
    auto server = std::make_unique<StalledReaderServer>();
    EipScanner s;
    s.set_request_timeout(0ms);
    s.connect("127.0.0.1", server->port());
    std::atomic<bool> timeout_error{false};
    auto fut = std::async(std::launch::async, [&] {
        std::vector<uint8_t> data(60000, 0x33);
        try {
            for (int i = 0; i < kMaxRequests; ++i)
                (void)s.send_generic(0x4D, 0x6B, 1, std::nullopt, data);
        } catch (const RequestTimeoutError&) {
            timeout_error = true;
        } catch (const std::exception&) {
        }
    });
    // Far longer than any timeout used above: still blocked in send().
    EXPECT_EQ(fut.wait_for(1500ms), std::future_status::timeout);
    server.reset();   // closes the peer: the blocked send fails (reset)
    EXPECT_EQ(fut.wait_for(30s), std::future_status::ready);
    EXPECT_FALSE(timeout_error);
}
