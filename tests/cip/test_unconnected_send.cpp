#include "ethernetip/cip/unconnected_send.hpp"

#include <gtest/gtest.h>
#include <stdexcept>

using namespace ethernetip::cip::unconnected_send;

TEST(UnconnectedSendTest, BuildInnerEncodesServicePathData) {
    std::vector<uint8_t> path = {0x20, 0x01, 0x24, 0x01, 0x30, 0x07};
    auto inner = build_inner_mr(0x0E, path, {});
    EXPECT_EQ(inner[0], 0x0E);
    EXPECT_EQ(inner[1], 3);
    EXPECT_EQ(std::vector<uint8_t>(inner.begin() + 2, inner.end()), path);
}

TEST(UnconnectedSendTest, EmptyRouteErrors) {
    std::vector<uint8_t> inner = {0x0E, 0x02, 0x20, 0x01, 0x24, 0x01};
    EXPECT_THROW((void)wrap(inner, {}), std::invalid_argument);
}

TEST(UnconnectedSendTest, OddRouteErrors) {
    std::vector<uint8_t> inner = {0x0E, 0x02, 0x20, 0x01, 0x24, 0x01};
    std::vector<uint8_t> route = {0x01};
    EXPECT_THROW((void)wrap(inner, route), std::invalid_argument);
}

TEST(UnconnectedSendTest, MatchesReferenceWireLayout) {
    // CIP Vol 1 §3-5.5.4 reference vector, same as C#/Rust/Python tests.
    std::vector<uint8_t> inner_mr = {0x0E, 0x02, 0x20, 0x01, 0x24, 0x01};
    std::vector<uint8_t> route    = {0x01, 0x00};
    auto outer = wrap(inner_mr, route);
    std::vector<uint8_t> expected = {
        0x52, 0x02, 0x20, 0x06, 0x24, 0x01,
        0x07, 0xF9,
        0x06, 0x00,
        0x0E, 0x02, 0x20, 0x01, 0x24, 0x01,
        0x01, 0x00,
        0x01, 0x00,
    };
    EXPECT_EQ(outer, expected);
}

TEST(UnconnectedSendTest, OddInnerInsertsPad) {
    std::vector<uint8_t> inner_mr = {0x0E, 0x02, 0x20, 0x01, 0x24, 0x01, 0xAA};
    std::vector<uint8_t> route    = {0x01, 0x00};
    auto outer = wrap(inner_mr, route);
    // embedded_size at offset 8 = 7.
    EXPECT_EQ(outer[8], 7);
    // route_size at 8+2+7+1 = 18.
    EXPECT_EQ(outer[18], 1);
    EXPECT_EQ(outer[19], 0);
}
