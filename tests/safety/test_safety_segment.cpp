#include "ethernetip/safety/safety_network_segment.hpp"

#include <array>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::safety;

namespace {
SafetyNetworkSegment make_target_segment() {
    SafetyNetworkSegment seg;
    seg.format = 0x00;
    seg.sccrc = 0x12345678;
    seg.scts  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    seg.time_correction_epi = 10000;
    seg.time_correction_params = 0x4001;
    seg.tunid = {SafetyNetworkNumber(std::array<uint8_t, 6>{0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D}), 0xC0A80154};
    seg.ounid = {SafetyNetworkNumber(std::array<uint8_t, 6>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), 0xC0A80164};
    seg.ping_interval_multiplier = 128;
    seg.time_coord_msg_min_multiplier = 160;
    seg.network_time_expectation_multiplier = 320;
    seg.timeout_multiplier = 2;
    seg.max_consumer_number = 1;
    seg.cpcrc = 0xDEADBEEF;
    seg.time_correction_connection_id = 0xFFFFFFFF;
    return seg;
}
} // namespace

TEST(SafetyNetworkSegmentTest, TargetFormatRoundTrip) {
    auto seg = make_target_segment();
    EXPECT_EQ(56, seg.wire_size());
    std::vector<uint8_t> wire(seg.wire_size());
    int n = seg.encode(wire);
    EXPECT_EQ(56, n);
    EXPECT_EQ(SafetyNetworkSegment::SegmentType, wire[0]);
    EXPECT_EQ(0x1B, wire[1]);  // 27 data-words

    auto [parsed, consumed] = SafetyNetworkSegment::parse(wire);
    EXPECT_EQ(56, consumed);
    EXPECT_EQ(0x00, parsed.format);
    EXPECT_EQ(seg.sccrc, parsed.sccrc);
    EXPECT_EQ(seg.scts, parsed.scts);
    EXPECT_EQ(seg.tunid, parsed.tunid);
    EXPECT_EQ(seg.ounid, parsed.ounid);
    EXPECT_EQ(seg.ping_interval_multiplier, parsed.ping_interval_multiplier);
    EXPECT_EQ(seg.cpcrc, parsed.cpcrc);
}

TEST(SafetyNetworkSegmentTest, ExtendedFormatRoundTrip) {
    auto seg = make_target_segment();
    seg.format = 0x02;
    seg.max_fault_number = 7;
    seg.initial_time_stamp = 0x1234;
    seg.initial_rollover_value = 0x5678;
    EXPECT_EQ(62, seg.wire_size());

    std::vector<uint8_t> wire(seg.wire_size());
    int n = seg.encode(wire);
    EXPECT_EQ(62, n);
    EXPECT_EQ(0x1E, wire[1]);  // 30 data-words

    auto [parsed, consumed] = SafetyNetworkSegment::parse(wire);
    EXPECT_EQ(62, consumed);
    EXPECT_EQ(0x02, parsed.format);
    EXPECT_EQ(7, parsed.max_fault_number);
    EXPECT_EQ(0x1234, parsed.initial_time_stamp);
    EXPECT_EQ(0x5678, parsed.initial_rollover_value);
}

TEST(SafetyNetworkSegmentTest, RejectsWrongSegmentType) {
    std::array<uint8_t, 3> bad{0x60, 0x00, 0x00};
    EXPECT_THROW({ (void)SafetyNetworkSegment::parse(bad); }, std::invalid_argument);
}

TEST(SafetyNetworkSegmentTest, RejectsTruncated) {
    auto seg = make_target_segment();
    std::vector<uint8_t> wire(seg.wire_size());
    seg.encode(wire);
    std::span<const uint8_t> short_buf(wire.data(), 20);
    EXPECT_THROW({ (void)SafetyNetworkSegment::parse(short_buf); }, std::invalid_argument);
}
