#include "ethernetip/cip/cpf.hpp"

#include <array>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::cip;

TEST(CpfTest, RoundTripTwoItems) {
    std::vector<CpfItem> items;
    items.emplace_back(CpfItemType::NullAddress, std::vector<uint8_t>{});
    items.emplace_back(CpfItemType::UnconnectedData,
                       std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF});

    auto required = cpf::size_for(items);
    EXPECT_EQ(2u + 4u + 0u + 4u + 4u, required);

    std::vector<uint8_t> buf(required);
    int n = cpf::write(buf, items);
    EXPECT_EQ(static_cast<int>(required), n);

    auto parsed = cpf::parse(buf);
    ASSERT_EQ(2u, parsed.size());
    EXPECT_EQ(CpfItemType::NullAddress, parsed[0].type_id);
    EXPECT_TRUE(parsed[0].data.empty());
    EXPECT_EQ(CpfItemType::UnconnectedData, parsed[1].type_id);
    ASSERT_EQ(4u, parsed[1].data.size());
    EXPECT_EQ(0xDE, parsed[1].data[0]);
    EXPECT_EQ(0xEF, parsed[1].data[3]);
}

TEST(CpfTest, ParseTruncatedReturnsPartial) {
    // Header says 2 items, but the second item header is truncated.
    std::array<uint8_t, 6> buf{
        0x02, 0x00,                 // item count = 2
        0x00, 0x00, 0x00, 0x00,     // item 1: NullAddress, length 0
    };
    auto items = cpf::parse(buf);
    EXPECT_EQ(1u, items.size());
    EXPECT_EQ(CpfItemType::NullAddress, items[0].type_id);
}

TEST(CpfTest, ParseEmptyReturnsEmpty) {
    std::array<uint8_t, 1> buf{0};
    auto items = cpf::parse(buf);
    EXPECT_TRUE(items.empty());
}
