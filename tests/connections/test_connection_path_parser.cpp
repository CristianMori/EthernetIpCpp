#include "ethernetip/connections/connection_path_parser.hpp"

#include <array>
#include <gtest/gtest.h>

using namespace ethernetip::connections;

namespace {
ForwardOpenRequest with_params(uint16_t ot_size, uint16_t to_size) {
    ForwardOpenRequest req;
    req.oto_t_params = NetworkConnectionParams{.connection_type = 2, .connection_size = ot_size};
    req.tto_o_params = NetworkConnectionParams{.connection_type = 2, .connection_size = to_size};
    return req;
}
} // namespace

TEST(ConnectionPathParserTest, StandardAssemblyShortcut) {
    // class 4, config inst 5, OT cp 100, TO cp 102
    std::array<uint8_t, 8> path{0x20, 0x04, 0x24, 0x05, 0x2C, 0x64, 0x2C, 0x66};
    auto req = with_params(7, 7);
    auto r = parse_connection_path(path, req);
    EXPECT_EQ(5u, r.config_assembly_instance.value_or(0));
    EXPECT_EQ(100u, r.consumed_assembly_instance.value_or(0));
    EXPECT_EQ(102u, r.produced_assembly_instance.value_or(0));
    EXPECT_TRUE(r.safety_segment.empty());
}

TEST(ConnectionPathParserTest, ElectronicKeyDetected) {
    // ekey (10 bytes) + class 4, instance 1, cp 100, cp 102
    std::array<uint8_t, 18> path{
        0x34, 0x04, 0x01, 0x00, 0x23, 0x00, 0x10, 0x00, 0x82, 0x02,
        0x20, 0x04, 0x24, 0x01, 0x2C, 0x64, 0x2C, 0x66};
    auto req = with_params(1, 1);
    auto r = parse_connection_path(path, req);
    EXPECT_TRUE(r.has_electronic_key);
    EXPECT_EQ(1u, r.config_assembly_instance.value_or(0));
    EXPECT_EQ(100u, r.consumed_assembly_instance.value_or(0));
    EXPECT_EQ(102u, r.produced_assembly_instance.value_or(0));
}

TEST(ConnectionPathParserTest, SafetyThreeInstanceForm) {
    // class 4 + 3 instance segments + safety segment header (just type + 0 words)
    std::array<uint8_t, 12> path{
        0x20, 0x04, 0x24, 0x05,            // config inst 5
        0x20, 0x04, 0x24, 0x32,            // OT inst 50
        0x20, 0x04, 0x24, 0x33};           // TO inst 51
    auto req = with_params(0, 0);   // Null params force 3-instance branch
    auto r = parse_connection_path(path, req);
    EXPECT_EQ(5u, r.config_assembly_instance.value_or(0));
    EXPECT_EQ(50u, r.consumed_assembly_instance.value_or(0));
    EXPECT_EQ(51u, r.produced_assembly_instance.value_or(0));
}

TEST(ConnectionPathParserTest, SafetySegmentCaptured) {
    // ... + 0x50 02 02 03 (safety segment, 2 data words)
    std::array<uint8_t, 14> path{
        0x20, 0x04, 0x24, 0x05, 0x2C, 0x64, 0x2C, 0x66,
        0x50, 0x02, 0x02, 0x03, 0x04, 0x05};
    auto req = with_params(7, 7);
    auto r = parse_connection_path(path, req);
    ASSERT_EQ(6u, r.safety_segment.size());
    EXPECT_EQ(0x50, r.safety_segment[0]);
    EXPECT_EQ(0x02, r.safety_segment[1]);
}
