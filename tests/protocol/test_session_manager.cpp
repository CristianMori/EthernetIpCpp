#include "ethernetip/protocol/session_manager.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::protocol;

TEST(SessionManagerTest, RegisterIssuesUniqueHandles) {
    SessionManager m;
    auto a = m.register_session();
    auto b = m.register_session();
    EXPECT_NE(a, b);
    EXPECT_NE(0u, a);
    EXPECT_NE(0u, b);
    EXPECT_EQ(2u, m.active_count());
}

TEST(SessionManagerTest, IsValidReportsActive) {
    SessionManager m;
    auto h = m.register_session();
    EXPECT_TRUE(m.is_valid(h));
    EXPECT_FALSE(m.is_valid(h + 1000));
}

TEST(SessionManagerTest, UnregisterRemovesIt) {
    SessionManager m;
    auto h = m.register_session();
    EXPECT_TRUE(m.unregister_session(h));
    EXPECT_FALSE(m.is_valid(h));
    EXPECT_FALSE(m.unregister_session(h));   // already gone
    EXPECT_EQ(0u, m.active_count());
}
