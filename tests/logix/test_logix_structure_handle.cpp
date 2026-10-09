// Tests for the FormalStrucTypeSpec + CRC-16 structure handle helper.
// Mirrors the C# LogixStructureHandleTests, the Rust
// logix_structure_handle module tests, and the Python
// test_logix_structure_handle test file. Opt-in behavior:
// try_build_formal_struc_spec computes a plausible handle for
// atomic-only UDTs and returns std::nullopt for anything else;
// TagDatabase::add_template is unchanged.

#include "ethernetip/logix/logix_structure_handle.hpp"
#include "ethernetip/logix/tag_database.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace ethernetip::logix;

namespace {

// Build a TemplateDefinition straight from (name, data_type) pairs with
// plausible offsets/sizes. The helper doesn't look at offset / size, so
// the exact numbers don't matter — only the data_type field does.
std::unique_ptr<TemplateDefinition> mk_scalar_tpl(
    const std::string& name,
    const std::vector<std::pair<std::string, uint16_t>>& member_codes) {
    std::vector<TemplateMemberInfo> members;
    members.reserve(member_codes.size());
    for (const auto& [n, code] : member_codes) {
        TemplateMemberInfo mi;
        mi.name         = n;
        mi.data_type    = code;
        mi.offset       = 0;
        mi.array_size   = 0;
        mi.element_size = 1;
        members.push_back(std::move(mi));
    }
    return std::make_unique<TemplateDefinition>(
        /*instance_id*/ 0x100,
        name,
        /*structure_handle*/ 0x8100,
        /*structure_size*/   0,
        std::move(members));
}

} // namespace

TEST(LogixStructureHandle, ThreeAtomicMembers_MatchSpecExampleBytes) {
    // CIP Vol 1 Section C-6.1 Example 3: STRUCT ::= { UINT, SINT, INT }
    // encodes as [A2][03][C7][C2][C3]. Hashing it should give the spec's
    // quoted 0x5159.
    auto tpl = mk_scalar_tpl("Three", {{"A", 0xC7}, {"B", 0xC2}, {"C", 0xC3}});
    auto bytes = try_build_formal_struc_spec(*tpl);
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(*bytes, (std::vector<uint8_t>{0xA2, 0x03, 0xC7, 0xC2, 0xC3}));
}

TEST(LogixStructureHandle, SpecExampleCrc_Is_0x5159) {
    auto tpl = mk_scalar_tpl("Three", {{"A", 0xC7}, {"B", 0xC2}, {"C", 0xC3}});
    auto h = try_compute_structure_handle(*tpl);
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(*h, 0x5159u);
}

TEST(LogixStructureHandle, UnsignedAndBitStringMembers_EncodeAsExpectedBytes) {
    auto tpl = mk_scalar_tpl("Mixed", {{"U32", 0xC8}, {"U8", 0xC6}, {"W", 0xD2}});
    auto bytes = try_build_formal_struc_spec(*tpl);
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(*bytes, (std::vector<uint8_t>{0xA2, 0x03, 0xC8, 0xC6, 0xD2}));
}

TEST(LogixStructureHandle, PackedBoolMemberRefused) {
    // Scalar BOOL packed into a host byte: data_type == 0x00C1,
    // element_size == 0 (array_size then carries the bit position 0..7).
    // The simple formal encoding can't represent that; refuse rather
    // than ship a plausible wrong handle.
    std::vector<TemplateMemberInfo> members;
    {
        TemplateMemberInfo mi;
        mi.name = "A"; mi.data_type = 0x00C4; mi.offset = 0;
        mi.array_size = 0; mi.element_size = 4;
        members.push_back(std::move(mi));
    }
    {
        TemplateMemberInfo mi;
        mi.name = "B"; mi.data_type = 0x00C1; mi.offset = 8;
        mi.array_size = 0; mi.element_size = 0;
        members.push_back(std::move(mi));
    }
    TemplateDefinition tpl(0x200, "WithBool", 0x8200, 12, std::move(members));
    EXPECT_FALSE(try_build_formal_struc_spec(tpl).has_value());
}

TEST(LogixStructureHandle, ArrayMemberRefused) {
    std::vector<TemplateMemberInfo> members;
    TemplateMemberInfo mi;
    mi.name = "Buf"; mi.data_type = 0x00C2; mi.offset = 0;
    mi.array_size = 16; mi.element_size = 1;
    members.push_back(std::move(mi));
    TemplateDefinition tpl(0x300, "WithArray", 0x8300, 16, std::move(members));
    EXPECT_FALSE(try_build_formal_struc_spec(tpl).has_value());
}

TEST(LogixStructureHandle, NestedStructMemberRefused) {
    std::vector<TemplateMemberInfo> members;
    TemplateMemberInfo mi;
    mi.name = "Inner"; mi.data_type = 0x8ABC; mi.offset = 0; // 0x8000 bit → nested
    mi.array_size = 0; mi.element_size = 4;
    members.push_back(std::move(mi));
    TemplateDefinition tpl(0x400, "WithNested", 0x8400, 4, std::move(members));
    EXPECT_FALSE(try_build_formal_struc_spec(tpl).has_value());
}

TEST(LogixStructureHandle, AddTemplateDefault_HandleStillStructureHandleOnly) {
    // Explicit regression guard: TagDatabase::add_template must NOT flip
    // to the computed CRC-16 handle silently. The helper is opt-in only;
    // callers who want it call try_compute_structure_handle themselves.
    TagDatabase db;
    std::vector<TemplateMember> members;
    members.push_back({"A", 0xC7, 0});
    members.push_back({"B", 0xC2, 0});
    members.push_back({"C", 0xC3, 0});
    auto& tpl = db.add_template("Three", std::move(members));
    EXPECT_NE(tpl.structure_handle(), 0x5159u);
}
