#include "ethernetip/cip/cip_path.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>

using namespace ethernetip::cip;

TEST(CipPathTest, ParseClassInstanceShortcut) {
    // 20 04 24 01 — class 0x04, instance 1
    std::array<uint8_t, 4> p{0x20, 0x04, 0x24, 0x01};
    auto [path, n] = CipPath::parse(p);
    EXPECT_EQ(4, n);
    ASSERT_TRUE(path.class_id.has_value());
    ASSERT_TRUE(path.instance_id.has_value());
    EXPECT_EQ(0x04u, *path.class_id);
    EXPECT_EQ(1u, *path.instance_id);
}

TEST(CipPathTest, ParseAssemblyWithTwoConnectionPoints) {
    // 20 04 24 05 2C 64 2C 66 — class 4, inst 5, OT cp 100, TO cp 102
    std::array<uint8_t, 8> p{0x20, 0x04, 0x24, 0x05, 0x2C, 0x64, 0x2C, 0x66};
    auto [path, n] = CipPath::parse(p);
    EXPECT_EQ(8, n);
    EXPECT_EQ(0x04u, path.class_id.value_or(0));
    EXPECT_EQ(5u, path.instance_id.value_or(0));
    // Last connection_point wins in this parser
    EXPECT_EQ(102u, path.connection_point.value_or(0));
}

TEST(CipPathTest, ParseSymbolicTwoLevels) {
    // 91 04 'M' 'y' 'T' 'g'  91 03 'F' 'o' 'o' (pad)
    std::array<uint8_t, 12> p{
        0x91, 0x04, 'M', 'y', 'T', 'g',
        0x91, 0x03, 'F', 'o', 'o', 0x00};
    auto [path, n] = CipPath::parse(p);
    EXPECT_EQ(12, n);
    ASSERT_TRUE(path.symbolic_name.has_value());
    EXPECT_EQ("MyTg.Foo", *path.symbolic_name);
}

TEST(CipPathTest, EncodeLogical8) {
    std::array<uint8_t, 4> buf{};
    int n = CipPath::encode_logical_8(buf, CipPath::LogicalTypeClassId, 0x06);
    EXPECT_EQ(2, n);
    EXPECT_EQ(0x20, buf[0]);
    EXPECT_EQ(0x06, buf[1]);
}

TEST(CipPathTest, ToStringIncludesEachField) {
    CipPath p;
    p.class_id = 0x04;
    p.instance_id = 1;
    p.attribute_id = uint16_t{3};
    auto s = p.to_string();
    EXPECT_NE(s.find("Class"), std::string::npos);
    EXPECT_NE(s.find("Instance=1"), std::string::npos);
    EXPECT_NE(s.find("Attr=3"), std::string::npos);
}

// --- Ordered segments list tests (gap 1/2 foundation) ---

TEST(CipPathSegmentTest, ParsesProgramScopedTag) {
    std::vector<uint8_t> bytes = {
        0x91, 12, 'P','r','o','g','r','a','m',':','M','a','i','n',
        0x91, 5, 'M','y','T','a','g', 0x00,
    };
    auto [path, consumed] = CipPath::parse(bytes);
    EXPECT_EQ(consumed, static_cast<int>(bytes.size()));
    ASSERT_EQ(path.segments.size(), 2u);
    auto* s0 = std::get_if<SymbolicPathSegment>(&path.segments[0]);
    ASSERT_NE(s0, nullptr);
    EXPECT_EQ(s0->name, "Program:Main");
    auto* s1 = std::get_if<SymbolicPathSegment>(&path.segments[1]);
    ASSERT_NE(s1, nullptr);
    EXPECT_EQ(s1->name, "MyTag");
    EXPECT_EQ(*path.symbolic_name, "Program:Main.MyTag");
}

TEST(CipPathSegmentTest, ParsesElementBetweenMembers) {
    std::vector<uint8_t> bytes = {
        0x91, 4, 'L','i','n','e',
        0x28, 0x02,
        0x91, 5, 'M','o','t','o','r', 0x00,
        0x91, 5, 'F','a','u','l','t', 0x00,
    };
    auto [path, _] = CipPath::parse(bytes);
    ASSERT_EQ(path.segments.size(), 4u);
    EXPECT_EQ(std::get<SymbolicPathSegment>(path.segments[0]).name, "Line");
    EXPECT_EQ(std::get<ElementPathSegment>(path.segments[1]).index, 2u);
    EXPECT_EQ(std::get<SymbolicPathSegment>(path.segments[2]).name, "Motor");
    EXPECT_EQ(std::get<SymbolicPathSegment>(path.segments[3]).name, "Fault");
}

TEST(CipPathSegmentTest, ParsesMultiDimIndices) {
    std::vector<uint8_t> bytes = {
        0x91, 6, 'M','a','t','r','i','x',
        0x28, 0x01,
        0x28, 0x02,
    };
    auto [path, _] = CipPath::parse(bytes);
    ASSERT_EQ(path.segments.size(), 3u);
    EXPECT_EQ(std::get<ElementPathSegment>(path.segments[1]).index, 1u);
    EXPECT_EQ(std::get<ElementPathSegment>(path.segments[2]).index, 2u);
    // Back-compat: last element wins in flat element_id.
    EXPECT_EQ(*path.element_id, 2u);
}

TEST(CipPathSegmentTest, LogicalSegmentsAppearInOrder) {
    std::vector<uint8_t> bytes = {0x20, 0x06, 0x24, 0x01};
    auto [path, _] = CipPath::parse(bytes);
    ASSERT_EQ(path.segments.size(), 2u);
    EXPECT_EQ(std::get<LogicalPathSegment>(path.segments[0]).kind, LogicalKind::ClassId);
    EXPECT_EQ(std::get<LogicalPathSegment>(path.segments[0]).value, 6u);
    EXPECT_EQ(std::get<LogicalPathSegment>(path.segments[1]).kind, LogicalKind::InstanceId);
    EXPECT_EQ(std::get<LogicalPathSegment>(path.segments[1]).value, 1u);
}
