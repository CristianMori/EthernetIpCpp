#include "ethernetip/cip/cip_status.hpp"
#include "ethernetip/cip/data_serializer.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>

using namespace ethernetip::cip;

TEST(CipStatusTest, SuccessIsSuccess) {
    auto s = CipStatus::success();
    EXPECT_TRUE(s.is_success());
    EXPECT_EQ(0, s.general_status);
    EXPECT_TRUE(s.additional_status.empty());
}

TEST(CipStatusTest, ErrorWithoutAdditional) {
    auto s = CipStatus::error(CipStatus::PathSegmentError);
    EXPECT_FALSE(s.is_success());
    EXPECT_EQ(0x04, s.general_status);
    EXPECT_TRUE(s.additional_status.empty());
}

TEST(CipStatusTest, ErrorWithAdditional) {
    auto s = CipStatus::error(0x01, {0x0203, 0xDEAD});
    EXPECT_FALSE(s.is_success());
    EXPECT_EQ(0x01, s.general_status);
    ASSERT_EQ(2u, s.additional_status.size());
    EXPECT_EQ(0x0203, s.additional_status[0]);
    EXPECT_EQ(0xDEAD, s.additional_status[1]);
}

TEST(CipStatusTest, EncodeSuccess) {
    std::array<uint8_t, 16> buf{};
    int n = CipStatus::success().encode(buf);
    EXPECT_EQ(2, n);
    EXPECT_EQ(0u, buf[0]);     // general
    EXPECT_EQ(0u, buf[1]);     // additional count
}

TEST(CipStatusTest, EncodeErrorWithTwoAdditional) {
    std::array<uint8_t, 16> buf{};
    int n = CipStatus::error(0x01, {0x0203, 0xDEAD}).encode(buf);
    EXPECT_EQ(6, n);                       // 1 general + 1 count + 2 * 2 bytes
    EXPECT_EQ(0x01, buf[0]);
    EXPECT_EQ(0x02, buf[1]);               // count = 2
    EXPECT_EQ(0x03, buf[2]); EXPECT_EQ(0x02, buf[3]);   // 0x0203 LE
    EXPECT_EQ(0xAD, buf[4]); EXPECT_EQ(0xDE, buf[5]);   // 0xDEAD LE
}

TEST(CipDataSerializerTest, RoundTripIntegers) {
    std::array<uint8_t, 32> buf{};
    serializer::write_dint(buf, -123456789);
    EXPECT_EQ(-123456789, serializer::read_dint(buf));

    serializer::write_uint(std::span<uint8_t>(buf).subspan(4), 0xBEEF);
    EXPECT_EQ(0xBEEFu, serializer::read_uint(std::span<const uint8_t>(buf).subspan(4)));

    serializer::write_ulint(std::span<uint8_t>(buf).subspan(8), 0x0123456789ABCDEFull);
    EXPECT_EQ(0x0123456789ABCDEFull,
              serializer::read_ulint(std::span<const uint8_t>(buf).subspan(8)));
}

TEST(CipDataSerializerTest, RoundTripStrings) {
    std::array<uint8_t, 64> buf{};
    int n = serializer::write_short_string(buf, "Hello");
    EXPECT_EQ(6, n);     // 1 length + 5 chars
    EXPECT_EQ("Hello", serializer::read_short_string(buf));

    n = serializer::write_string(std::span<uint8_t>(buf).subspan(16), "World!");
    EXPECT_EQ(8, n);     // 2 length + 6 chars
    EXPECT_EQ("World!", serializer::read_string(std::span<const uint8_t>(buf).subspan(16)));
}

TEST(CipDataSerializerTest, FixedSizeLookup) {
    EXPECT_EQ(1, serializer::fixed_size(CipDataType::Bool));
    EXPECT_EQ(4, serializer::fixed_size(CipDataType::Dint));
    EXPECT_EQ(8, serializer::fixed_size(CipDataType::Lreal));
    EXPECT_EQ(-1, serializer::fixed_size(CipDataType::String));
    EXPECT_EQ(-1, serializer::fixed_size(CipDataType::ShortString));
}
