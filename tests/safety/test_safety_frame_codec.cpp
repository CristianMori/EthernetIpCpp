#include "ethernetip/safety/safety_crc.hpp"
#include "ethernetip/safety/safety_frame_codec.hpp"

#include <array>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::safety;

namespace {
constexpr uint16_t CONN_SERIAL = 0x0001;
constexpr uint16_t ORIG_VENDOR = 0x0001;
constexpr uint32_t ORIG_SERIAL = 0x12345678;

const uint8_t  SEED_S1 = crc::pid_cid_seed_s1(ORIG_VENDOR, ORIG_SERIAL, CONN_SERIAL);
const uint16_t SEED_S3 = crc::pid_cid_seed_s3(ORIG_VENDOR, ORIG_SERIAL, CONN_SERIAL);
const uint32_t SEED_S5 = crc::pid_cid_seed_s5(ORIG_VENDOR, ORIG_SERIAL, CONN_SERIAL);

SafetyDecodeResult round_trip(std::span<const uint8_t> data, SafetyFormat fmt,
                                ModeByte mode, uint16_t ts, uint16_t rollover = 0) {
    std::vector<uint8_t> wire(frame_codec::wire_size(static_cast<int>(data.size()), fmt));
    int n = frame_codec::encode(wire, data, fmt, mode, ts, SEED_S1, SEED_S3, SEED_S5, rollover);
    EXPECT_EQ(static_cast<int>(wire.size()), n);
    return frame_codec::decode(wire, static_cast<int>(data.size()), fmt,
                                 SEED_S1, SEED_S3, SEED_S5, rollover);
}
} // namespace

TEST(SafetyFrameCodecTest, WireSizes) {
    EXPECT_EQ(7, frame_codec::wire_size(1, SafetyFormat::Base));
    EXPECT_EQ(8, frame_codec::wire_size(2, SafetyFormat::Base));
    EXPECT_EQ(14, frame_codec::wire_size(3, SafetyFormat::Base));
    EXPECT_EQ(28, frame_codec::wire_size(10, SafetyFormat::Base));
    EXPECT_EQ(7, frame_codec::wire_size(1, SafetyFormat::Extended));
    EXPECT_EQ(28, frame_codec::wire_size(10, SafetyFormat::Extended));
}

TEST(SafetyFrameCodecTest, BaseShort1Byte) {
    uint8_t in[] = {0x42};
    auto r = round_trip(in, SafetyFormat::Base, ModeByte::create(true, 0), 1234);
    EXPECT_TRUE(r.crc_valid) << *r.error_message;
    ASSERT_EQ(1u, r.actual_data.size());
    EXPECT_EQ(0x42, r.actual_data[0]);
    EXPECT_EQ(1234, r.timestamp);
    EXPECT_TRUE(r.mode.run_idle());
}

TEST(SafetyFrameCodecTest, BaseShort2Byte) {
    uint8_t in[] = {0xAA, 0x55};
    auto r = round_trip(in, SafetyFormat::Base, ModeByte::create(false, 2), 60000);
    EXPECT_TRUE(r.crc_valid);
    EXPECT_EQ(2u, r.mode.ping_count());
    EXPECT_FALSE(r.mode.run_idle());
}

TEST(SafetyFrameCodecTest, BaseLong4Byte) {
    uint8_t in[] = {0x01, 0x02, 0x03, 0x04};
    auto r = round_trip(in, SafetyFormat::Base, ModeByte::create(true, 1), 5000);
    EXPECT_TRUE(r.crc_valid) << *r.error_message;
    EXPECT_EQ(4u, r.actual_data.size());
    EXPECT_EQ(0x04, r.actual_data[3]);
}

TEST(SafetyFrameCodecTest, BaseLong250Byte) {
    std::vector<uint8_t> data(250);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    auto r = round_trip(data, SafetyFormat::Base, ModeByte::create(true, 3), 0xFFFF);
    EXPECT_TRUE(r.crc_valid) << *r.error_message;
    EXPECT_EQ(data, r.actual_data);
}

TEST(SafetyFrameCodecTest, ExtendedShort1Byte) {
    uint8_t in[] = {0x77};
    auto r = round_trip(in, SafetyFormat::Extended, ModeByte::create(true, 1), 12345);
    EXPECT_TRUE(r.crc_valid) << *r.error_message;
    EXPECT_EQ(1u, r.mode.ping_count());
}

TEST(SafetyFrameCodecTest, ExtendedLongWithRollover) {
    std::vector<uint8_t> data(50);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    auto r = round_trip(data, SafetyFormat::Extended, ModeByte::create(true, 0), 8000, /*rollover=*/5);
    EXPECT_TRUE(r.crc_valid) << *r.error_message;
    EXPECT_EQ(data, r.actual_data);
}

TEST(SafetyFrameCodecTest, BitFlipDetected) {
    uint8_t in[] = {0x42};
    std::vector<uint8_t> wire(frame_codec::wire_size(1, SafetyFormat::Base));
    frame_codec::encode(wire, in, SafetyFormat::Base, ModeByte::create(true, 0), 100,
                         SEED_S1, SEED_S3, SEED_S5);
    wire[0] ^= 0x01;
    auto r = frame_codec::decode(wire, 1, SafetyFormat::Base,
                                   SEED_S1, SEED_S3, SEED_S5);
    EXPECT_FALSE(r.crc_valid);
    EXPECT_TRUE(r.error_message.has_value());
}

TEST(SafetyFrameCodecTest, TcooBase6Bytes) {
    std::array<uint8_t, 6> out{};
    int n = frame_codec::encode_time_coordination(out, /*ping_reply=*/2,
                                                    /*ctv=*/42, SEED_S3);
    EXPECT_EQ(6, n);
    // AckByte: ping_count_reply=2 (bits 1:0 = 10), ping_response=1 (bit 3),
    // even parity over bits 0-6 → already even (count=2), so parity bit = 0.
    EXPECT_EQ(0x0A, out[0]);
    // AckByte2 = ((ack^0xFF)&0x55) | (ack&0xAA) = 0x55 | 0x0A = 0x5F
    EXPECT_EQ(0x5F, out[3]);
}

TEST(SafetyFrameCodecTest, TcooExtended6Bytes) {
    std::array<uint8_t, 6> out{};
    int n = frame_codec::encode_time_coordination_extended(out, 1, 100, SEED_S5);
    EXPECT_EQ(6, n);
}
