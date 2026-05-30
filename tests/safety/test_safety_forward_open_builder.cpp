#include "ethernetip/safety/safety_cpcrc.hpp"
#include "ethernetip/safety/safety_forward_open_builder.hpp"
#include "ethernetip/safety/safety_network_segment.hpp"

#include <array>
#include <gtest/gtest.h>

using namespace ethernetip::safety;

namespace {
SafetyForwardOpenConfig make_typical_config() {
    SafetyForwardOpenConfig c;
    c.config_assembly = 0x05;
    c.consumed_assembly = 0x64;
    c.produced_assembly = 0x66;
    c.consumed_data_size = 1;
    c.produced_data_size = 1;
    c.rpi = 20000;
    c.format = SafetyFormat::Extended;
    c.tunid = {SafetyNetworkNumber(std::array<uint8_t, 6>{0xC9,0x12,0xB4,0x00,0x8D,0x4D}),
                0xC0A80154u};
    c.ounid = {SafetyNetworkNumber(std::array<uint8_t, 6>{0xC9,0x12,0xB4,0x00,0x8D,0x4D}),
                0xC0A80160u};
    c.ping_interval_multiplier = 19;
    c.time_coord_msg_min_multiplier = 0;
    c.network_time_expectation_multiplier = 625;
    c.timeout_multiplier = 2;
    c.max_fault_number = 2;
    c.initial_timestamp = 0xFFFF;
    c.initial_rollover_value = 0xFFFF;
    return c;
}
} // namespace

TEST(SafetyForwardOpenBuilderTest, BuildsValidExtendedRequest) {
    auto cfg = make_typical_config();
    auto wire = build_safety_forward_open(cfg, /*conn_serial=*/0x1234,
                                            /*orig_vendor=*/0x0001,
                                            /*orig_serial=*/0x012FE10E,
                                            /*transport_class_trigger=*/0xA0);
    // Fixed header + assembly shortcut (8B) + extended safety segment (62B) = 36 + 70 = 106
    EXPECT_EQ(106u, wire.service_data.size());
    EXPECT_EQ(4u, wire.cm_path.size());
    EXPECT_EQ(0x20, wire.cm_path[0]);
    EXPECT_EQ(0x06, wire.cm_path[1]);
}

TEST(SafetyForwardOpenBuilderTest, EmbeddedSegmentParsesBack) {
    auto cfg = make_typical_config();
    auto wire = build_safety_forward_open(cfg, 0x1234, 0x0001, 0x012FE10E, 0xA0);

    // The safety segment starts after the 8-byte assembly shortcut, which itself
    // starts after the 36-byte fixed FwdOpen header. So segment offset = 36 + 8 = 44.
    auto seg_bytes = std::span<const uint8_t>(wire.service_data).subspan(44, 62);
    auto [seg, consumed] = SafetyNetworkSegment::parse(seg_bytes);
    EXPECT_EQ(62, consumed);
    EXPECT_EQ(0x02, seg.format);
    EXPECT_EQ(cfg.tunid, seg.tunid);
    EXPECT_EQ(cfg.ounid, seg.ounid);
    EXPECT_NE(0u, seg.cpcrc);   // CPCRC patched in
}

TEST(SafetyForwardOpenBuilderTest, CustomAppPathHonored) {
    auto cfg = make_typical_config();
    // Custom app path with electronic key (10 bytes) + assembly shortcut (8 bytes) = 18 bytes.
    std::array<uint8_t, 18> custom_path{
        0x34, 0x04, 0x01, 0x00, 0x23, 0x00, 0x10, 0x00, 0x82, 0x02,
        0x20, 0x04, 0x24, 0x05, 0x2C, 0x64, 0x2C, 0x66};
    auto wire = build_safety_forward_open(cfg, 0x1234, 0x0001, 0x012FE10E, 0xA0,
                                            /*route_prefix=*/{}, custom_path);
    // 36 fixed + 18 path + 62 segment = 116
    EXPECT_EQ(116u, wire.service_data.size());
    // App path byte 0 must be 0x34 (electronic key).
    EXPECT_EQ(0x34, wire.service_data[36]);
}
