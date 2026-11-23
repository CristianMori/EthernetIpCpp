// TagClient request timeout: a target that answers RegisterSession and then
// goes silent must not hang the client, nor disconnect().

#include "ethernetip/logix/tag_client.hpp"
#include "silent_eip_server.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <stdexcept>

using namespace ethernetip::logix;
using ethernetip::protocol::DefaultRequestTimeout;
using ethernetip::protocol::RequestTimeoutError;
using ethernetip::test::SilentEipServer;
using ethernetip::test::elapsed_ms;
using namespace std::chrono_literals;

namespace {
constexpr auto kShort = 300ms;
constexpr auto kBound = kShort + 1000ms;   // timeout + 1 s
} // namespace

TEST(TagClientRequestTimeoutTest, DefaultIsFiveSeconds) {
    TagClient c("127.0.0.1");
    EXPECT_EQ(c.request_timeout(), 5000ms);
    EXPECT_EQ(c.request_timeout(), DefaultRequestTimeout);
    c.set_request_timeout(0ms);
    EXPECT_EQ(c.request_timeout(), 0ms);
}

TEST(TagClientRequestTimeoutTest, RegisterSessionTimesOut) {
    SilentEipServer server({.answer_register_session = false});
    TagClient c("127.0.0.1", server.port());
    c.set_request_timeout(kShort);
    auto t = elapsed_ms([&] { EXPECT_THROW(c.connect(), RequestTimeoutError); });
    EXPECT_GE(t, kShort - 50ms);
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(c.is_connected());
}

TEST(TagClientRequestTimeoutTest, RequestTimesOutAndDropsSession) {
    SilentEipServer server;
    TagClient c("127.0.0.1", server.port());
    c.set_request_timeout(kShort);
    c.connect();
    ASSERT_TRUE(c.is_connected());

    auto t = elapsed_ms([&] {
        EXPECT_THROW((void)c.read<int32_t>("Tag"), RequestTimeoutError);
    });
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(c.is_connected());
    EXPECT_EQ(c.session_handle(), 0u);

    auto t2 = elapsed_ms([&] {
        EXPECT_THROW((void)c.read<int32_t>("Tag"), std::runtime_error);
    });
    EXPECT_LT(t2, 200ms);
}

TEST(TagClientRequestTimeoutTest, ClassThreeForwardOpenTimesOut) {
    SilentEipServer server;   // never answers the Forward_Open
    TagClient c("127.0.0.1", server.port(), {}, /*use_connected=*/true);
    c.set_request_timeout(kShort);
    auto t = elapsed_ms([&] { EXPECT_THROW(c.connect(), RequestTimeoutError); });
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(c.is_connected());
}

TEST(TagClientRequestTimeoutTest, ConnectedRequestTimesOutAndDisconnectReturnsPromptly) {
    SilentEipServer server({.answer_first_forward_open = true});
    TagClient c("127.0.0.1", server.port(), {}, /*use_connected=*/true);
    c.set_request_timeout(kShort);
    c.connect();
    ASSERT_TRUE(c.is_connected());

    auto t = elapsed_ms([&] {
        EXPECT_THROW((void)c.read<int32_t>("Tag"), RequestTimeoutError);   // SendUnitData
    });
    EXPECT_LE(t, kBound);
    auto t2 = elapsed_ms([&] { c.disconnect(); });
    EXPECT_LT(t2, 200ms);
}

TEST(TagClientRequestTimeoutTest, DisconnectWithPendingClassThreeReturnsPromptly) {
    SilentEipServer server({.answer_first_forward_open = true});
    TagClient c("127.0.0.1", server.port(), {}, /*use_connected=*/true);
    c.set_request_timeout(kShort);
    c.connect();
    ASSERT_TRUE(c.is_connected());

    // Forward_Close gets no reply: swallowed after one timeout.
    auto t = elapsed_ms([&] { c.disconnect(); });
    EXPECT_LE(t, kBound);
    EXPECT_FALSE(c.is_connected());
}
