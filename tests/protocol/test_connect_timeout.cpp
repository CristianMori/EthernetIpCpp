// Client TCP connect timeout: connecting to an address where the handshake
// never completes must not wait for the OS SYN timeout.
//
// Forcing a hang deterministically and locally: a listener with a tiny
// backlog that never accept()s. Once its accept queue is full the stack
// stops completing handshakes for further connects (they hang in SYN-sent),
// with no dependence on the network. If a platform instead refuses or
// completes them, the hang cannot be produced and the test is skipped
// rather than reported as a pass.

#include "ethernetip/logix/tag_client.hpp"
#include "ethernetip/protocol/eip_scanner.hpp"
#include "ethernetip/protocol/socket_compat.hpp"
#include "silent_eip_server.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <thread>
#include <vector>

using namespace ethernetip::protocol;
using ethernetip::test::SilentEipServer;
using ethernetip::test::elapsed_ms;
using namespace std::chrono_literals;

namespace {

constexpr auto kShort = 300ms;
constexpr auto kBound = kShort + 1000ms;   // timeout + 1 s

// A listener whose accept queue is full, so further connects hang.
class BlackholeListener {
public:
    BlackholeListener() {
        sock::ensure_initialized();
        listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        sock::to_sockaddr(IpEndpoint{"127.0.0.1", 0}, a);
        ::bind(listener_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(listener_, 1);
        socklen_t len = sizeof(a);
        ::getsockname(listener_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        // Fill the queue: connect until one stops completing quickly.
        for (int i = 0; i < 16 && !hangs_; ++i) {
            sock::socket_t c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            int err = 0;
            auto r = sock::connect_timed(c, a, 250ms, err);
            if (r == sock::ConnectResult::Ok) {
                fillers_.push_back(c);
            } else {
                sock::close(c);
                hangs_ = r == sock::ConnectResult::TimedOut;
                if (!hangs_) break;   // refused: this stack will not hang
            }
        }
    }
    ~BlackholeListener() { release(); }
    BlackholeListener(const BlackholeListener&) = delete;
    BlackholeListener& operator=(const BlackholeListener&) = delete;

    [[nodiscard]] bool hangs() const noexcept { return hangs_; }
    [[nodiscard]] uint16_t port() const noexcept { return port_; }

    /// Close everything: pending connects are reset and fail.
    void release() {
        for (auto c : fillers_) sock::close(c);
        fillers_.clear();
        if (listener_ != sock::invalid) sock::close(listener_);
        listener_ = sock::invalid;
    }

private:
    sock::socket_t listener_ = sock::invalid;
    uint16_t port_ = 0;
    bool hangs_ = false;
    std::vector<sock::socket_t> fillers_;
};

} // namespace

TEST(ConnectTimeoutTest, DefaultIsFiveSecondsAndConfigurable) {
    EXPECT_EQ(DefaultConnectTimeout, 5000ms);

    EipScanner s;
    EXPECT_EQ(s.connect_timeout(), 5000ms);
    s.set_connect_timeout(0ms);
    EXPECT_EQ(s.connect_timeout(), 0ms);
    s.set_connect_timeout(250ms);
    EXPECT_EQ(s.connect_timeout(), 250ms);

    ethernetip::logix::TagClient c("127.0.0.1");
    EXPECT_EQ(c.connect_timeout(), 5000ms);
    c.set_connect_timeout(0ms);
    EXPECT_EQ(c.connect_timeout(), 0ms);
    c.set_connect_timeout(250ms);
    EXPECT_EQ(c.connect_timeout(), 250ms);
}

TEST(ConnectTimeoutTest, ConnectTimeoutErrorIsARequestTimeoutError) {
    EXPECT_TRUE((std::is_base_of_v<RequestTimeoutError, ConnectTimeoutError>));
    EXPECT_TRUE((std::is_base_of_v<std::runtime_error, ConnectTimeoutError>));
}

TEST(ConnectTimeoutTest, ConnectSucceedsAndSocketIsBlockingAfterwards) {
    // Silent after RegisterSession: the next request must still wait in a
    // blocking recv (request timeout disabled would hang if the socket were
    // left non-blocking; with a timeout it must expire, not fail instantly).
    SilentEipServer server;
    EipScanner s;
    s.set_connect_timeout(2000ms);
    s.set_request_timeout(kShort);
    s.connect("127.0.0.1", server.port());
    ASSERT_TRUE(s.is_connected());
    auto t = elapsed_ms([&] {
        EXPECT_THROW(s.send_generic(0x0E, 0x01, 1, uint16_t{1}), RequestTimeoutError);
    });
    EXPECT_GE(t, kShort - 50ms);   // waited, did not fail on EWOULDBLOCK
}

TEST(ConnectTimeoutTest, RefusedFailsFastNotAsTimeout) {
    // A port with nothing listening.
    uint16_t port;
    {
        SilentEipServer tmp;
        port = tmp.port();
    }
    EipScanner s;
    s.set_connect_timeout(10000ms);
    auto t = elapsed_ms([&] {
        try {
            s.connect("127.0.0.1", port);
            ADD_FAILURE() << "connect should have failed";
        } catch (const ConnectTimeoutError&) {
            ADD_FAILURE() << "refusal must not be reported as a timeout";
        } catch (const std::runtime_error&) {
        }
    });
    // Windows retries a refused loopback SYN for ~2 s; the point is that it
    // ends long before the 10 s timeout.
    EXPECT_LT(t, 5000ms);
    EXPECT_FALSE(s.is_connected());
}

TEST(ConnectTimeoutTest, ScannerConnectTimesOut) {
    BlackholeListener bh;
    if (!bh.hangs()) GTEST_SKIP() << "this stack refuses instead of hanging on a full backlog";
    SilentEipServer server;   // declared before s: s disconnects first
    EipScanner s;
    s.set_connect_timeout(kShort);
    std::string what;
    auto t = elapsed_ms([&] {
        try {
            s.connect("127.0.0.1", bh.port());
            ADD_FAILURE() << "connect should have timed out";
        } catch (const ConnectTimeoutError& e) {
            what = e.what();
        }
    });
    EXPECT_GE(t, kShort - 50ms);
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(s.is_connected());
    EXPECT_NE(what.find("127.0.0.1:" + std::to_string(bh.port())), std::string::npos) << what;
    EXPECT_NE(what.find("300 ms"), std::string::npos) << what;

    // Still usable: a later connect to a live target succeeds.
    s.connect("127.0.0.1", server.port());
    EXPECT_TRUE(s.is_connected());
}

TEST(ConnectTimeoutTest, TagClientConnectTimesOut) {
    BlackholeListener bh;
    if (!bh.hangs()) GTEST_SKIP() << "this stack refuses instead of hanging on a full backlog";
    ethernetip::logix::TagClient c("127.0.0.1", bh.port());
    c.set_connect_timeout(kShort);
    std::string what;
    auto t = elapsed_ms([&] {
        try {
            c.connect();
            ADD_FAILURE() << "connect should have timed out";
        } catch (const ConnectTimeoutError& e) {
            what = e.what();
        }
    });
    EXPECT_GE(t, kShort - 50ms);
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(c.is_connected());
    EXPECT_NE(what.find("127.0.0.1:" + std::to_string(bh.port())), std::string::npos) << what;
    EXPECT_NE(what.find("300 ms"), std::string::npos) << what;
}

TEST(ConnectTimeoutTest, CaughtAsRequestTimeoutError) {
    BlackholeListener bh;
    if (!bh.hangs()) GTEST_SKIP() << "this stack refuses instead of hanging on a full backlog";
    EipScanner s;
    s.set_connect_timeout(kShort);
    EXPECT_THROW(s.connect("127.0.0.1", bh.port()), RequestTimeoutError);
}

TEST(ConnectTimeoutTest, ZeroDisablesTheTimeout) {
    BlackholeListener bh;
    if (!bh.hangs()) GTEST_SKIP() << "this stack refuses instead of hanging on a full backlog";
    EipScanner s;
    s.set_connect_timeout(0ms);
    std::atomic<bool> timed_out{false};
    auto fut = std::async(std::launch::async, [&] {
        try {
            s.connect("127.0.0.1", bh.port());
        } catch (const ConnectTimeoutError&) {
            timed_out = true;
        } catch (const std::exception&) {
        }
    });
    // Well past the 300 ms a timeout would have used: still blocked.
    EXPECT_EQ(fut.wait_for(1500ms), std::future_status::timeout);
    EXPECT_FALSE(timed_out);
    bh.release();   // reset the pending handshake so the connect returns
    EXPECT_EQ(fut.wait_for(30s), std::future_status::ready);
    EXPECT_FALSE(timed_out);
}
