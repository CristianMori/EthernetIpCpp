// Client request timeout: a target that answers RegisterSession and then
// goes silent must not hang the scanner. Exercises every reply-wait site.

#include "ethernetip/protocol/connected_explicit.hpp"
#include "ethernetip/protocol/eip_scanner.hpp"
#include "silent_eip_server.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <stdexcept>

using namespace ethernetip::protocol;
using ethernetip::test::SilentEipServer;
using ethernetip::test::elapsed_ms;
using namespace std::chrono_literals;

namespace {
constexpr auto kShort = 300ms;
constexpr auto kBound = kShort + 1000ms;   // timeout + 1 s
} // namespace

TEST(RequestTimeoutTest, DefaultIsFiveSecondsAndConfigurable) {
    EXPECT_EQ(DefaultRequestTimeout, 5000ms);
    EipScanner s;
    EXPECT_EQ(s.request_timeout(), 5000ms);
    s.set_request_timeout(0ms);
    EXPECT_EQ(s.request_timeout(), 0ms);
}

TEST(RequestTimeoutTest, RegisterSessionTimesOut) {
    SilentEipServer server({.answer_register_session = false});
    EipScanner s;
    s.set_request_timeout(kShort);
    auto t = elapsed_ms([&] {
        EXPECT_THROW(s.connect("127.0.0.1", server.port()), RequestTimeoutError);
    });
    EXPECT_GE(t, kShort - 50ms);
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(s.is_connected());
}

TEST(RequestTimeoutTest, ScannerRequestTimesOutAndDropsSession) {
    SilentEipServer server;
    EipScanner s;
    s.set_request_timeout(kShort);
    s.connect("127.0.0.1", server.port());
    ASSERT_TRUE(s.is_connected());

    auto t = elapsed_ms([&] {
        EXPECT_THROW(s.send_generic(0x0E, 0x01, 1, uint16_t{1}), RequestTimeoutError);
    });
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(s.is_connected());
    EXPECT_EQ(s.session_handle(), 0u);
    // Connection is gone: further requests fail fast rather than waiting.
    auto t2 = elapsed_ms([&] {
        EXPECT_THROW(s.send_generic(0x0E, 0x01, 1, uint16_t{1}), std::runtime_error);
    });
    EXPECT_LT(t2, 200ms);
}

TEST(RequestTimeoutTest, ForwardOpenTimesOut) {
    SilentEipServer server;
    EipScanner s;
    s.set_request_timeout(kShort);
    s.connect("127.0.0.1", server.port());
    ForwardOpenConfig cfg;
    auto t = elapsed_ms([&] {
        EXPECT_THROW((void)s.forward_open(cfg), RequestTimeoutError);
    });
    EXPECT_LE(t, kBound);
}

TEST(RequestTimeoutTest, ClassThreeCloseWithSilentTargetReturnsPromptly) {
    SilentEipServer server({.answer_first_forward_open = true});
    EipScanner s;
    s.set_request_timeout(kShort);
    s.connect("127.0.0.1", server.port());
    auto ce = s.open_explicit();
    ASSERT_NE(ce, nullptr);

    // Pending class-3 connection: Forward_Close gets no reply.
    auto t = elapsed_ms([&] { ce->close(); });
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(s.is_connected());
    auto t2 = elapsed_ms([&] { s.disconnect(); });
    EXPECT_LT(t2, 200ms);
}

TEST(RequestTimeoutTest, SendUnitDataTimesOut) {
    SilentEipServer server({.answer_first_forward_open = true});
    EipScanner s;
    s.set_request_timeout(kShort);
    s.connect("127.0.0.1", server.port());
    auto ce = s.open_explicit();
    auto t = elapsed_ms([&] {
        EXPECT_THROW((void)ce->send(0x0E, 0x01, 1, uint16_t{1}), RequestTimeoutError);
    });
    EXPECT_LE(t, kBound);
    auto t2 = elapsed_ms([&] { ce->close(); });
    EXPECT_LT(t2, 200ms);   // already disconnected: nothing to wait for
}
