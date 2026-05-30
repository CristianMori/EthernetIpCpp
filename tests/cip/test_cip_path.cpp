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
