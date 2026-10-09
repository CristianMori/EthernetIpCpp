#include "ethernetip/cip/cip_crc.hpp"

#include <gtest/gtest.h>
#include <vector>

using ethernetip::cip::cip_crc16;

TEST(CipCrc16Test, SpecVector1) {
    std::vector<uint8_t> v = {0xA2, 0x03, 0xC7, 0xC2, 0xC3};
    EXPECT_EQ(cip_crc16(v), 0x5159);
}

TEST(CipCrc16Test, SpecVector2) {
    std::vector<uint8_t> v = {0xA2, 0x07, 0xC7, 0xA2, 0x03, 0xC7, 0xC2, 0xC3, 0xC3};
    EXPECT_EQ(cip_crc16(v), 0x26C7);
}

TEST(CipCrc16Test, EmptyIsZero) {
    EXPECT_EQ(cip_crc16({}), 0);
}

TEST(CipCrc16Test, SingleZeroByteStaysZero) {
    std::vector<uint8_t> v = {0x00};
    EXPECT_EQ(cip_crc16(v), 0);
}
