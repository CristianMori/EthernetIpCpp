#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::cip;
using namespace ethernetip::logix;
namespace ldt = ethernetip::logix::logix_data_types;
namespace ser = ethernetip::cip::serializer;

static std::vector<uint8_t> encode_u16(uint16_t v) {
    std::vector<uint8_t> b(2);
    b[0] = static_cast<uint8_t>(v & 0xFF);
    b[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    return b;
}

TEST(WalkerDispatchTest, ReadScalarMember) {
    auto tags = std::make_shared<TagDatabase>();
    auto tpl = std::make_unique<TemplateDefinition>(
        0x300, "Timer", 0x8300, 12,
        std::vector<TemplateMemberInfo>{
            {"PRE", ldt::Dint, 0, 0, 4},
            {"ACC", ldt::Dint, 4, 0, 4},
            {"EN",  ldt::Bool, 8, 0, 0},
            {"TT",  ldt::Bool, 8, 1, 0},
            {"DN",  ldt::Bool, 8, 2, 0},
        });
    auto& t = tags->add_template_prebuilt(std::move(tpl));
    auto& tag = tags->add_tag("MyTimer", t);
    tag.write<int32_t>(4, 6789);

    LogixDispatcher logix(tags);
    CipPath path;
    path.segments.push_back(SymbolicPathSegment{"MyTimer"});
    path.segments.push_back(SymbolicPathSegment{"ACC"});

    auto req = encode_u16(1);
    auto resp = logix.dispatch(tag_services::ReadTag, path, req);
    ASSERT_TRUE(resp.status.is_success()) << std::hex << (int)resp.status.general_status;
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    int32_t val;
    std::memcpy(&val, resp.data.data() + 2, 4);
    EXPECT_EQ(val, 6789);
}

TEST(WalkerDispatchTest, WriteBoolMemberBitPreservesNeighbors) {
    auto tags = std::make_shared<TagDatabase>();
    auto tpl = std::make_unique<TemplateDefinition>(
        0x301, "Timer", 0x8301, 12,
        std::vector<TemplateMemberInfo>{
            {"PRE", ldt::Dint, 0, 0, 4},
            {"ACC", ldt::Dint, 4, 0, 4},
            {"EN",  ldt::Bool, 8, 0, 0},
            {"TT",  ldt::Bool, 8, 1, 0},
            {"DN",  ldt::Bool, 8, 2, 0},
        });
    auto& t = tags->add_template_prebuilt(std::move(tpl));
    auto& tag = tags->add_tag("MyTimer", t);
    tag.write<uint8_t>(8, 0b0000'0010);   // preset TT

    LogixDispatcher logix(tags);
    CipPath path;
    path.segments.push_back(SymbolicPathSegment{"MyTimer"});
    path.segments.push_back(SymbolicPathSegment{"DN"});

    std::vector<uint8_t> payload = { 0xC1, 0x00, 0x01, 0x00, 0x01 };
    auto resp = logix.dispatch(tag_services::WriteTag, path, payload);
    ASSERT_TRUE(resp.status.is_success());
    EXPECT_EQ(tag.read<uint8_t>(8), 0b0000'0110);
}

TEST(WalkerDispatchTest, ReadMultiDimElement) {
    auto tags = std::make_shared<TagDatabase>();
    auto& tag = tags->add_tag_dims("Matrix", ldt::Dint, {5, 10, 4});
    tag.write<int32_t>(204, 999);   // ((1*10+2)*4+3)*4 = 204

    LogixDispatcher logix(tags);
    CipPath path;
    path.segments.push_back(SymbolicPathSegment{"Matrix"});
    path.segments.push_back(ElementPathSegment{1});
    path.segments.push_back(ElementPathSegment{2});
    path.segments.push_back(ElementPathSegment{3});

    auto req = encode_u16(1);
    auto resp = logix.dispatch(tag_services::ReadTag, path, req);
    ASSERT_TRUE(resp.status.is_success());
    int32_t val;
    std::memcpy(&val, resp.data.data() + 2, 4);
    EXPECT_EQ(val, 999);
}

TEST(WalkerDispatchTest, WriteBoolArrayBit) {
    auto tags = std::make_shared<TagDatabase>();
    auto& tag = tags->add_tag("Flags", ldt::Bool, 32);
    LogixDispatcher logix(tags);

    CipPath path;
    path.segments.push_back(SymbolicPathSegment{"Flags"});
    path.segments.push_back(ElementPathSegment{5});

    std::vector<uint8_t> payload = { 0xC1, 0x00, 0x01, 0x00, 0x01 };
    auto resp = logix.dispatch(tag_services::WriteTag, path, payload);
    ASSERT_TRUE(resp.status.is_success());
    EXPECT_EQ(tag.read<uint8_t>(0), 0b0010'0000);
    EXPECT_EQ(tag.read<uint8_t>(1), 0);
}

TEST(WalkerDispatchTest, ProgramScopedRead) {
    auto tags = std::make_shared<TagDatabase>();
    tags->register_program("Cell");
    auto& t = tags->add_program_tag("Cell", "Rate", ldt::Dint);
    t.write<int32_t>(0, 4242);

    LogixDispatcher logix(tags);
    CipPath path;
    path.segments.push_back(SymbolicPathSegment{"Program:Cell"});
    path.segments.push_back(SymbolicPathSegment{"Rate"});

    auto req = encode_u16(1);
    auto resp = logix.dispatch(tag_services::ReadTag, path, req);
    ASSERT_TRUE(resp.status.is_success()) << std::hex << (int)resp.status.general_status;
    int32_t val;
    std::memcpy(&val, resp.data.data() + 2, 4);
    EXPECT_EQ(val, 4242);
}

TEST(WalkerDispatchTest, FastPathStillWorks) {
    auto tags = std::make_shared<TagDatabase>();
    auto& tag = tags->add_tag("rate", ldt::Dint);
    tag.write<int32_t>(0, 42);

    LogixDispatcher logix(tags);
    CipPath path;
    path.symbolic_name = "rate";  // no segments — fast path
    auto req = encode_u16(1);
    auto resp = logix.dispatch(tag_services::ReadTag, path, req);
    ASSERT_TRUE(resp.status.is_success());
    int32_t val;
    std::memcpy(&val, resp.data.data() + 2, 4);
    EXPECT_EQ(val, 42);
}
