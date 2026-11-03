// Coverage for CIP SHORT_STRING (0xDA) as a Logix atomic tag type:
// metadata, in-memory read/write helpers, and the CIP Read_Tag / Write_Tag
// wire shape. SHORT_STRING is independent of the Logix STRING UDT (which
// stays on the structure path with the 0x02A0 prefix).
//
// Based on the exploration in PR #1 (@SRCthird). Narrowed to just the
// atomic SHORT_STRING feature so it does not collide with the UDT STRING
// handling. Mirrors tests/EthernetIPSharp.Logix.Tests/ShortStringTests.cs.

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

using namespace ethernetip::logix;
namespace ldt = logix_data_types;
namespace ser = ethernetip::cip::serializer;

TEST(ShortStringTest, Metadata_ShortStringElementIs81Bytes) {
    EXPECT_EQ(81, ldt::element_size(ldt::ShortString));
    EXPECT_EQ(81, ldt::ShortStringStorageSize);
    EXPECT_EQ(80, ldt::ShortStringMaxLength);
}

TEST(ShortStringTest, AddTag_ShortStringAtomic_HasExpectedLayout) {
    TagDatabase db;
    auto& tag = db.add_tag("name", ldt::ShortString);
    EXPECT_TRUE(tag.is_sstring());
    EXPECT_EQ(81, tag.element_size());
    EXPECT_EQ(1,  tag.element_count());
    EXPECT_EQ(81, tag.data_size());
}

TEST(ShortStringTest, AddTag_ShortStringArray_SizesInEightyOneByteSlots) {
    TagDatabase db;
    auto& tag = db.add_tag("names", ldt::ShortString, /*element_count=*/4);
    EXPECT_EQ(4,       tag.element_count());
    EXPECT_EQ(81,      tag.element_size());
    EXPECT_EQ(4 * 81,  tag.data_size());
}

TEST(ShortStringTest, WriteSString_ReadBackMatches) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);
    tag.write_sstring("Asset-32");

    EXPECT_EQ("Asset-32", tag.read_sstring());
    EXPECT_EQ(static_cast<uint8_t>(std::string_view("Asset-32").size()),
              tag.get_data(0, 1)[0]);
}

TEST(ShortStringTest, WriteSString_ArrayElement_IsolatesFromNeighbors) {
    TagDatabase db;
    auto& tag = db.add_tag("names", ldt::ShortString, /*element_count=*/3);
    tag.write_sstring(0, "first");
    tag.write_sstring(1, "second-is-longer");
    tag.write_sstring(2, "third");

    EXPECT_EQ("first",            tag.read_sstring(0));
    EXPECT_EQ("second-is-longer", tag.read_sstring(1));
    EXPECT_EQ("third",            tag.read_sstring(2));
}

TEST(ShortStringTest, WriteSString_ShorterOverLonger_ClearsTrailingBytes) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);
    tag.write_sstring(std::string(40, 'x'));
    tag.write_sstring("hi");

    EXPECT_EQ("hi", tag.read_sstring());
    for (int i = 3; i < tag.data_size(); ++i) {
        EXPECT_EQ(0, tag.get_data(i, 1)[0]) << "stale byte at " << i;
    }
}

TEST(ShortStringTest, WriteSString_RejectsOverMaxLength) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);
    std::string big(ldt::ShortStringMaxLength + 1, 'x');
    EXPECT_THROW(tag.write_sstring(big), std::invalid_argument);
}

TEST(ShortStringTest, WriteSString_RejectsNonAscii) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);
    // 0xE9 = Latin small letter e with acute — above 0x7F.
    std::string s;
    s.push_back('c');
    s.push_back('a');
    s.push_back('f');
    s.push_back(static_cast<char>(0xE9));
    EXPECT_THROW(tag.write_sstring(s), std::invalid_argument);
}

TEST(ShortStringTest, ReadSString_OnNonShortStringTag_Throws) {
    TagDatabase db;
    auto& tag = db.add_tag("rate", ldt::Dint);
    EXPECT_THROW((void)tag.read_sstring(), std::logic_error);
}

TEST(ShortStringTest, WriteSString_OutOfRangeElement_Throws) {
    TagDatabase db;
    auto& tag = db.add_tag("names", ldt::ShortString, /*element_count=*/2);
    EXPECT_THROW(tag.write_sstring(5, "nope"), std::out_of_range);
}

TEST(ShortStringTest, HandleReadTag_ShortString_EmitsTwoByteAtomicPrefix) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);
    tag.write_sstring("Asset-32");

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = tag_services::handle_read_tag(tag, tag_services::ReadTag, req);
    ASSERT_TRUE(resp.status.is_success());

    // Atomic prefix is 2 bytes (SHORT_STRING is not a structure, no 0x02A0).
    ASSERT_EQ(static_cast<size_t>(2 + ldt::ShortStringStorageSize), resp.data.size());
    EXPECT_EQ(ldt::ShortString, ser::read_uint(resp.data));
    EXPECT_EQ(static_cast<uint8_t>(std::string_view("Asset-32").size()),
              resp.data[2]);
    std::string chars(reinterpret_cast<const char*>(resp.data.data() + 3),
                      std::string_view("Asset-32").size());
    EXPECT_EQ("Asset-32", chars);
}

TEST(ShortStringTest, HandleWriteTag_ShortString_AcceptsAtomicHeader) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);

    std::vector<uint8_t> payload(ldt::ShortStringStorageSize, 0);
    constexpr std::string_view v = "Asset-32";
    payload[0] = static_cast<uint8_t>(v.size());
    std::memcpy(payload.data() + 1, v.data(), v.size());

    std::vector<uint8_t> req(4 + payload.size());
    ser::write_uint(req, ldt::ShortString);
    ser::write_uint(std::span<uint8_t>(req).subspan(2), 1);
    std::memcpy(req.data() + 4, payload.data(), payload.size());

    auto resp = tag_services::handle_write_tag(tag, tag_services::WriteTag, req);
    ASSERT_TRUE(resp.status.is_success());
    EXPECT_EQ("Asset-32", tag.read_sstring());
}

TEST(ShortStringTest, HandleWriteTag_WrongTypeCode_Rejected) {
    TagDatabase db;
    auto& tag = db.add_tag("asset", ldt::ShortString);

    std::vector<uint8_t> req(4 + ldt::ShortStringStorageSize, 0);
    ser::write_uint(req, ldt::Dint);  // wrong type
    ser::write_uint(std::span<uint8_t>(req).subspan(2), 1);

    auto resp = tag_services::handle_write_tag(tag, tag_services::WriteTag, req);
    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(0xFF, resp.status.general_status);
    ASSERT_FALSE(resp.status.additional_status.empty());
    EXPECT_EQ(static_cast<uint16_t>(0x2107), resp.status.additional_status.front());
}

// A CIP Write_Tag payload can plant any length byte (0..0xFF) at the start
// of a SHORT_STRING slot — handle_write_tag only validates the type code,
// not the string's length prefix. If read_sstring trusted that byte, it
// would read ~0xFF chars past the slot and leak adjacent memory.
TEST(ShortStringTest, ReadSString_ClampsPlantedLengthByteToSlotCapacity) {
    TagDatabase db;
    auto& tag = db.add_tag("names", ldt::ShortString, /*element_count=*/2);

    // Scribble element 1 so the clamp has something distinctive to NOT reveal.
    tag.write_sstring(1, "SECRET");

    // Plant a bogus 0xFF length into element 0 directly, bypassing
    // write_sstring's validator — exactly what a hostile Write_Tag does.
    std::array<uint8_t, 1> poison{0xFF};
    tag.set_data(poison, /*byte_offset=*/0);

    auto s = tag.read_sstring(0);
    EXPECT_LE(s.size(), static_cast<size_t>(tag.element_size() - 1));
    EXPECT_EQ(s.find("SECRET"), std::string::npos);
}
