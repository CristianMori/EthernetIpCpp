// Tests for the CIP Vol 1 §C-6.1 unsigned integer + bit-string atomic
// types. Mirrors the C# UnsignedAndBitStringTypeTests.
#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/persistence.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <sstream>

using namespace ethernetip::logix;
namespace ldt = ethernetip::logix::logix_data_types;
namespace ser = ethernetip::cip::serializer;

TEST(UnsignedAndBitStringTypes, ElementSizeMatchesSpec) {
    EXPECT_EQ(ldt::element_size(ldt::Sint),  1);
    EXPECT_EQ(ldt::element_size(ldt::Usint), 1);
    EXPECT_EQ(ldt::element_size(ldt::Byte),  1);
    EXPECT_EQ(ldt::element_size(ldt::Int),   2);
    EXPECT_EQ(ldt::element_size(ldt::Uint),  2);
    EXPECT_EQ(ldt::element_size(ldt::Word),  2);
    EXPECT_EQ(ldt::element_size(ldt::Dint),  4);
    EXPECT_EQ(ldt::element_size(ldt::Udint), 4);
    EXPECT_EQ(ldt::element_size(ldt::Dword), 4);
    EXPECT_EQ(ldt::element_size(ldt::Real),  4);
    EXPECT_EQ(ldt::element_size(ldt::Lint),  8);
    EXPECT_EQ(ldt::element_size(ldt::Ulint), 8);
    EXPECT_EQ(ldt::element_size(ldt::Lword), 8);
    EXPECT_EQ(ldt::element_size(ldt::Lreal), 8);
}

TEST(UnsignedAndBitStringTypes, AddTagUdintSucceeds) {
    // The specific EscaFlow crash: Unknown tag type 0x00C8.
    TagDatabase db;
    auto& tag = db.add_tag("counter", ldt::Udint);
    EXPECT_EQ(tag.element_size(), 4);
    EXPECT_EQ(tag.data_size(), 4);

    tag.write<uint32_t>(0, 0xFFFF'FFFFu);
    EXPECT_EQ(tag.read<uint32_t>(0), 0xFFFF'FFFFu);
    // Interpreting the same bytes as int32 exposes the two's-complement
    // (the bytes are the bytes — no silent sign-fiddling by the stack).
    EXPECT_EQ(tag.read<int32_t>(0), -1);
}

TEST(UnsignedAndBitStringTypes, BoundaryValuesRoundTrip) {
    TagDatabase db;
    auto& u8  = db.add_tag("u8",  ldt::Usint);
    auto& u16 = db.add_tag("u16", ldt::Uint);
    auto& u32 = db.add_tag("u32", ldt::Udint);
    auto& u64 = db.add_tag("u64", ldt::Ulint);

    u8.write<uint8_t>(0,   0xFFu);
    u16.write<uint16_t>(0, 0xFFFFu);
    u32.write<uint32_t>(0, 0xFFFF'FFFFu);
    u64.write<uint64_t>(0, 0xFFFF'FFFF'FFFF'FFFFull);

    EXPECT_EQ(u8.read<uint8_t>(0),   0xFFu);
    EXPECT_EQ(u16.read<uint16_t>(0), 0xFFFFu);
    EXPECT_EQ(u32.read<uint32_t>(0), 0xFFFF'FFFFu);
    EXPECT_EQ(u64.read<uint64_t>(0), 0xFFFF'FFFF'FFFF'FFFFull);
}

TEST(UnsignedAndBitStringTypes, BitStringTypesAllocateCorrectWidth) {
    TagDatabase db;
    EXPECT_EQ(db.add_tag("b",   ldt::Byte).data_size(),  1);
    EXPECT_EQ(db.add_tag("w",   ldt::Word).data_size(),  2);
    EXPECT_EQ(db.add_tag("dw",  ldt::Dword).data_size(), 4);
    EXPECT_EQ(db.add_tag("lw",  ldt::Lword).data_size(), 8);
}

TEST(UnsignedAndBitStringTypes, AddArrayOfUdint) {
    TagDatabase db;
    auto& tag = db.add_tag("counters", ldt::Udint, /*element_count=*/16);
    EXPECT_EQ(tag.data_size(), 64);
    tag.write<uint32_t>(15 * 4, 0xDEAD'BEEFu);
    EXPECT_EQ(tag.read<uint32_t>(15 * 4), 0xDEAD'BEEFu);
}

TEST(UnsignedAndBitStringTypes, UdtMemberLayout) {
    TagDatabase db;
    auto& tpl = db.add_template("All", {
        {"U8",   ldt::Usint, 0},
        {"U16",  ldt::Uint,  0},
        {"U32",  ldt::Udint, 0},
        {"U64",  ldt::Ulint, 0},
        {"B8",   ldt::Byte,  0},
        {"W16",  ldt::Word,  0},
        {"LW64", ldt::Lword, 0},
    });
    auto find = [&](std::string_view name) -> int {
        for (const auto& m : tpl.members()) if (m.name == name) return m.offset;
        return -1;
    };
    EXPECT_EQ(find("U8"),   0);
    EXPECT_EQ(find("U16"),  2);
    EXPECT_EQ(find("U32"),  4);
    EXPECT_EQ(find("U64"),  8);
    EXPECT_EQ(find("B8"),   16);
    EXPECT_EQ(find("W16"),  18);
    EXPECT_EQ(find("LW64"), 24);
    EXPECT_EQ(tpl.structure_size(), 32u);
}

TEST(UnsignedAndBitStringTypes, PersistenceRoundTrip) {
    TagDatabase db;
    db.add_tag("u8",   ldt::Usint).write<uint8_t>(0,  0xAB);
    db.add_tag("u16",  ldt::Uint).write<uint16_t>(0, 0xBEEF);
    db.add_tag("u32",  ldt::Udint).write<uint32_t>(0, 0xDEAD'BEEFu);
    db.add_tag("u64",  ldt::Ulint).write<uint64_t>(0, 0xFEED'FACE'CAFE'BABEull);
    db.add_tag("b8",   ldt::Byte).write<uint8_t>(0,  0xFF);
    db.add_tag("w16",  ldt::Word).write<uint16_t>(0, 0xFFFE);
    db.add_tag("dw32", ldt::Dword).write<uint32_t>(0, 0x1122'3344u);
    db.add_tag("lw64", ldt::Lword).write<uint64_t>(0, 0x1122'3344'5566'7788ull);

    std::stringstream buf;
    persistence::save(db, buf);

    TagDatabase db2;
    db2.add_tag("u8",   ldt::Usint);
    db2.add_tag("u16",  ldt::Uint);
    db2.add_tag("u32",  ldt::Udint);
    db2.add_tag("u64",  ldt::Ulint);
    db2.add_tag("b8",   ldt::Byte);
    db2.add_tag("w16",  ldt::Word);
    db2.add_tag("dw32", ldt::Dword);
    db2.add_tag("lw64", ldt::Lword);

    buf.seekg(0);
    auto result = persistence::load(db2, buf);
    EXPECT_EQ(result.tags_restored, 8);
    EXPECT_EQ(result.tags_skipped,  0);
    EXPECT_EQ(db2.find_by_name("u32")->read<uint32_t>(0), 0xDEAD'BEEFu);
    EXPECT_EQ(db2.find_by_name("u64")->read<uint64_t>(0), 0xFEED'FACE'CAFE'BABEull);
    EXPECT_EQ(db2.find_by_name("lw64")->read<uint64_t>(0), 0x1122'3344'5566'7788ull);
}

TEST(UnsignedAndBitStringTypes, DispatcherWriteUdintAcceptsUdintCode) {
    auto tags = std::make_shared<TagDatabase>();
    auto& tag = tags->add_tag("counter", ldt::Udint);
    LogixDispatcher logix(tags);

    ethernetip::cip::CipPath path;
    path.symbolic_name = "counter";

    // Encode a Write_Tag body: tag_type(UINT) + element_count(UINT) + value(UDINT).
    std::vector<uint8_t> write(4 + 4);
    ser::write_uint(write, ldt::Udint);
    ser::write_uint(std::span<uint8_t>(write).subspan(2), 1);
    ser::write_udint(std::span<uint8_t>(write).subspan(4), 0xFFFF'FFFFu);

    auto resp = logix.dispatch(tag_services::WriteTag, path, write);
    ASSERT_TRUE(resp.status.is_success()) << std::hex << static_cast<int>(resp.status.general_status);
    EXPECT_EQ(tag.read<uint32_t>(0), 0xFFFF'FFFFu);
}
