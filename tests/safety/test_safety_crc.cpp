#include "ethernetip/safety/safety_crc.hpp"

#include <array>
#include <gtest/gtest.h>
#include <string_view>
#include <vector>

using namespace ethernetip::safety;

namespace {
constexpr std::string_view kCheck = "123456789";
std::span<const uint8_t> check_bytes() {
    return {reinterpret_cast<const uint8_t*>(kCheck.data()), kCheck.size()};
}
} // namespace

// Check values pulled from C# SafetyCrcTests / Python test_crc.py — preset = 0xFF / 0xFFFF.
TEST(SafetyCrcTest, S1CheckValue) {
    EXPECT_EQ(0x4C, crc::compute_s1(check_bytes(), 0xFF));
}
TEST(SafetyCrcTest, S2CheckValue) {
    EXPECT_EQ(0xBF, crc::compute_s2(check_bytes(), 0xFF));
}
TEST(SafetyCrcTest, S3CheckValue) {
    EXPECT_EQ(0x9516, crc::compute_s3(check_bytes(), 0xFFFF));
}
TEST(SafetyCrcTest, S4CheckValueMatchesCrc32) {
    // init 0xFFFFFFFF, no final XOR -> 0x340BC6D9 for "123456789".
    EXPECT_EQ(0x340BC6D9u, crc::compute_s4(check_bytes()));
}

TEST(SafetyCrcTest, S1EmptyAndSingle) {
    EXPECT_EQ(0x00, crc::compute_s1({}, 0));
    uint8_t one[] = {0x01};
    EXPECT_EQ(0x37, crc::compute_s1(one, 0));   // table[1]
}

TEST(SafetyCrcTest, S3OverloadsMatchStream) {
    uint8_t one[] = {0xE0};
    EXPECT_EQ(crc::compute_s3_byte(0xE0, 0xFFFF),
              crc::compute_s3(one, 0xFFFF));

    uint8_t two_le[] = {0x34, 0x12};
    EXPECT_EQ(crc::compute_s3_u16(0x1234, 0xFFFF),
              crc::compute_s3(two_le, 0xFFFF));
}

TEST(SafetyCrcTest, IncrementalEqualsAtOnceS1) {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    auto all_at_once = crc::compute_s1(data, 0xFF);
    auto part1 = crc::compute_s1(std::span<const uint8_t>(data, 2), 0xFF);
    auto part2 = crc::compute_s1(std::span<const uint8_t>(data + 2, 2), part1);
    EXPECT_EQ(all_at_once, part2);
}

TEST(SafetyCrcTest, IncrementalEqualsAtOnceS3) {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    auto all_at_once = crc::compute_s3(data, 0xFFFF);
    auto part1 = crc::compute_s3(std::span<const uint8_t>(data, 2), 0xFFFF);
    auto part2 = crc::compute_s3(std::span<const uint8_t>(data + 2, 2), part1);
    EXPECT_EQ(all_at_once, part2);
}

TEST(SafetyCrcTest, S5XorOutIsRawComplemented) {
    EXPECT_EQ(crc::compute_s5_raw(check_bytes(), 0) ^ 0x00FFFFFFu,
              crc::compute_s5(check_bytes(), 0));
}

TEST(SafetyCrcTest, PidSeedsNonZero) {
    EXPECT_NE(0u, crc::pid_cid_seed_s1(0x0001, 0x12345678, 0x0001));
    EXPECT_NE(0u, crc::pid_cid_seed_s3(0x0001, 0x12345678, 0x0001));
    EXPECT_NE(0u, crc::pid_cid_seed_s5(0x0001, 0x12345678, 0x0001));
}

TEST(SafetyCrcTest, RolloverSeedChangesWithRollover) {
    auto s3 = crc::pid_cid_seed_s3(0x0001, 0x12345678, 0x0001);
    auto s5 = crc::pid_cid_seed_s5(0x0001, 0x12345678, 0x0001);
    EXPECT_NE(crc::pid_rollover_seed_s3(0, s3),
              crc::pid_rollover_seed_s3(1, s3));
    EXPECT_NE(crc::pid_rollover_seed_s5(0, s5),
              crc::pid_rollover_seed_s5(1, s5));
}
