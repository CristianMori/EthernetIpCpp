// Regression tests for the Logix structured-tag wire contract.
// CIP Vol 1 §C-4.4.5: struct reads/writes carry a 4-byte prefix on the wire
// ([0x02A0][structure_handle]) ahead of the data. libplctag and pycomm3 both
// enforce this. Tests cover whole-tag and walker-aware handlers; atomic
// behavior is pinned by test_tag_services.cpp.

#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/tag_services.hpp"
#include "ethernetip/logix/walker.hpp"

#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::logix;
namespace ldt = logix_data_types;
namespace ser = ethernetip::cip::serializer;

static constexpr uint16_t kStructTypeIndicator = 0x02A0;

// ---- Whole-tag path ----

TEST(StructWirePrefixTest, HandleReadTag_Struct_EmitsFourBytePrefix) {
    TagDatabase db;
    auto& tpl = db.add_template("Timer", {
        {"PRE", ldt::Dint, 0},
        {"ACC", ldt::Dint, 0},
    });
    auto& tag = db.add_tag("t1", tpl);
    tag.write<int32_t>(0, 123);
    tag.write<int32_t>(4, 456);

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = tag_services::handle_read_tag(tag, tag_services::ReadTag, req);

    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(4u + tpl.structure_size(), resp.data.size());
    EXPECT_EQ(kStructTypeIndicator, ser::read_uint(resp.data));
    EXPECT_EQ(tpl.structure_handle(),
              ser::read_uint(std::span<const uint8_t>(resp.data).subspan(2)));
    EXPECT_EQ(123, static_cast<int32_t>(ser::read_udint(
                       std::span<const uint8_t>(resp.data).subspan(4))));
    EXPECT_EQ(456, static_cast<int32_t>(ser::read_udint(
                       std::span<const uint8_t>(resp.data).subspan(8))));
}

TEST(StructWirePrefixTest, HandleReadTag_Atomic_StaysTwoBytePrefix) {
    // Regression guard: atomic reads keep the 2-byte prefix.
    Tag t(1, "rate", ldt::make_atomic_symbol_type(ldt::Dint, 0), ldt::Dint, 4, 1);
    t.write<int32_t>(0, 42);

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = tag_services::handle_read_tag(t, tag_services::ReadTag, req);

    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(6u, resp.data.size());
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(42u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(StructWirePrefixTest, HandleWriteTag_Struct_AcceptsSixByteHeader) {
    TagDatabase db;
    auto& tpl = db.add_template("Timer", {
        {"PRE", ldt::Dint, 0},
        {"ACC", ldt::Dint, 0},
    });
    auto& tag = db.add_tag("t1", tpl);

    std::vector<uint8_t> req(6 + tpl.structure_size());
    ser::write_uint(req, kStructTypeIndicator);
    ser::write_uint(std::span<uint8_t>(req).subspan(2), tpl.structure_handle());
    ser::write_uint(std::span<uint8_t>(req).subspan(4), 1);
    ser::write_udint(std::span<uint8_t>(req).subspan(6), 777);
    ser::write_udint(std::span<uint8_t>(req).subspan(10), 888);

    auto resp = tag_services::handle_write_tag(tag, tag_services::WriteTag, req);

    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(777, tag.read<int32_t>(0));
    EXPECT_EQ(888, tag.read<int32_t>(4));
}

TEST(StructWirePrefixTest, HandleWriteTag_Struct_WrongIndicator_Rejected) {
    TagDatabase db;
    auto& tpl = db.add_template("Timer", {{"PRE", ldt::Dint, 0}});
    auto& tag = db.add_tag("t1", tpl);

    std::vector<uint8_t> req(6 + 4);
    ser::write_uint(req, 0x1234);  // Wrong indicator
    ser::write_uint(std::span<uint8_t>(req).subspan(2), tpl.structure_handle());
    ser::write_uint(std::span<uint8_t>(req).subspan(4), 1);

    auto resp = tag_services::handle_write_tag(tag, tag_services::WriteTag, req);

    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(0xFF, resp.status.general_status);
    ASSERT_EQ(1u, resp.status.additional_status.size());
    EXPECT_EQ(0x2107u, resp.status.additional_status[0]);
}

TEST(StructWirePrefixTest, HandleWriteTag_Struct_WrongHandle_Rejected) {
    TagDatabase db;
    auto& tpl = db.add_template("Timer", {{"PRE", ldt::Dint, 0}});
    auto& tag = db.add_tag("t1", tpl);

    std::vector<uint8_t> req(6 + 4);
    ser::write_uint(req, kStructTypeIndicator);
    ser::write_uint(std::span<uint8_t>(req).subspan(2),
                     static_cast<uint16_t>(tpl.structure_handle() ^ 0xFFFF));
    ser::write_uint(std::span<uint8_t>(req).subspan(4), 1);

    auto resp = tag_services::handle_write_tag(tag, tag_services::WriteTag, req);

    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(0xFF, resp.status.general_status);
    ASSERT_EQ(1u, resp.status.additional_status.size());
    EXPECT_EQ(0x2107u, resp.status.additional_status[0]);
}

TEST(StructWirePrefixTest, HandleWriteTag_Atomic_StillAcceptsFourByteHeader) {
    Tag t(1, "rate", ldt::make_atomic_symbol_type(ldt::Dint, 0), ldt::Dint, 4, 1);

    std::array<uint8_t, 8> req{};
    ser::write_uint(req, ldt::Dint);
    ser::write_uint(std::span<uint8_t>(req).subspan(2), 1);
    ser::write_udint(std::span<uint8_t>(req).subspan(4), 99);

    auto resp = tag_services::handle_write_tag(t, tag_services::WriteTag, req);

    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(99, t.read<int32_t>(0));
}

TEST(StructWirePrefixTest, HandleReadTagFragmented_Struct_EmitsFourBytePrefix) {
    TagDatabase db;
    std::vector<TemplateMember> members;
    for (int i = 0; i < 130; ++i) {
        members.push_back({"m" + std::to_string(i), ldt::Dint, 0});
    }
    auto& tpl = db.add_template("BigUdt", std::move(members));
    auto& tag = db.add_tag("big", tpl);

    std::array<uint8_t, 6> req{};
    ser::write_uint(req, 1);
    ser::write_udint(std::span<uint8_t>(req).subspan(2), 0u);

    auto resp = tag_services::handle_read_tag_fragmented(
        tag, tag_services::ReadTagFragmented, req);

    // Partial-transfer reply.
    EXPECT_EQ(static_cast<uint8_t>(tag_services::ReadTagFragmented | 0x80), resp.service_code);
    EXPECT_EQ(0x06, resp.status.general_status);
    ASSERT_GE(resp.data.size(), 4u);
    EXPECT_EQ(kStructTypeIndicator, ser::read_uint(resp.data));
    EXPECT_EQ(tpl.structure_handle(),
              ser::read_uint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(StructWirePrefixTest, HandleWriteTagFragmented_Struct_AcceptsTenByteHeader) {
    TagDatabase db;
    auto& tpl = db.add_template("Timer", {
        {"PRE", ldt::Dint, 0},
        {"ACC", ldt::Dint, 0},
    });
    auto& tag = db.add_tag("t1", tpl);

    std::array<uint8_t, 14> req{};
    ser::write_uint(req, kStructTypeIndicator);
    ser::write_uint(std::span<uint8_t>(req).subspan(2), tpl.structure_handle());
    ser::write_uint(std::span<uint8_t>(req).subspan(4), 1);
    ser::write_udint(std::span<uint8_t>(req).subspan(6), 4);     // offset
    ser::write_udint(std::span<uint8_t>(req).subspan(10), 321);  // value

    auto resp = tag_services::handle_write_tag_fragmented(
        tag, tag_services::WriteTagFragmented, req);

    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(321, tag.read<int32_t>(4));
}

// ---- Walker-aware path ----

namespace {

struct MotorFixture {
    TagDatabase db;
    const TemplateDefinition* timer_tpl = nullptr;
    const TemplateDefinition* motor_tpl = nullptr;
    std::unique_ptr<Tag> tag;

    MotorFixture() {
        timer_tpl = &db.add_template("Timer", {
            {"PRE", ldt::Dint, 0},
            {"ACC", ldt::Dint, 0},
        });

        std::vector<TemplateMemberInfo> motor_members{
            TemplateMemberInfo{"Speed", ldt::Real, 0, 0, 4},
            TemplateMemberInfo{"Timer",
                               static_cast<uint16_t>(0x8000 | timer_tpl->instance_id()),
                               4, 0, static_cast<int>(timer_tpl->structure_size())},
        };
        auto motor_owning = std::make_unique<TemplateDefinition>(
            0x301, "Motor", 0xBEEF, 4u + timer_tpl->structure_size(),
            std::move(motor_members));
        motor_tpl = &db.add_template_prebuilt(std::move(motor_owning));

        tag = std::make_unique<Tag>(
            100, "m1",
            ldt::make_struct_symbol_type(motor_tpl->instance_id(), 0),
            motor_tpl->structure_handle(),
            static_cast<int>(motor_tpl->structure_size()),
            1);
        tag->set_template(motor_tpl);
    }
};

}  // namespace

TEST(StructWirePrefixTest, HandleReadTagAt_StructMember_EmitsFourBytePrefix) {
    MotorFixture f;
    f.tag->write<int32_t>(4, 11);  // Timer.PRE
    f.tag->write<int32_t>(8, 22);  // Timer.ACC

    std::vector<ethernetip::cip::PathSegment> segs{ethernetip::cip::SymbolicPathSegment{"Timer"}};
    std::string err;
    auto walked = walk(*f.tag, segs, f.db, &err);
    ASSERT_TRUE(walked.has_value()) << err;

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = tag_services::handle_read_tag_at(*f.tag, tag_services::ReadTag, req, *walked);

    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(4u + f.timer_tpl->structure_size(), resp.data.size());
    EXPECT_EQ(kStructTypeIndicator, ser::read_uint(resp.data));
    EXPECT_EQ(f.timer_tpl->structure_handle(),
              ser::read_uint(std::span<const uint8_t>(resp.data).subspan(2)));
    EXPECT_EQ(11, static_cast<int32_t>(
                      ser::read_udint(std::span<const uint8_t>(resp.data).subspan(4))));
    EXPECT_EQ(22, static_cast<int32_t>(
                      ser::read_udint(std::span<const uint8_t>(resp.data).subspan(8))));
}

TEST(StructWirePrefixTest, HandleReadTagAt_AtomicMember_StaysTwoBytePrefix) {
    TagDatabase db;
    auto& tpl = db.add_template("Timer", {
        {"PRE", ldt::Dint, 0},
        {"ACC", ldt::Dint, 0},
    });
    auto& tag = db.add_tag("t1", tpl);
    tag.write<int32_t>(4, 777);  // ACC

    std::vector<ethernetip::cip::PathSegment> segs{ethernetip::cip::SymbolicPathSegment{"ACC"}};
    std::string err;
    auto walked = walk(tag, segs, db, &err);
    ASSERT_TRUE(walked.has_value()) << err;

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = tag_services::handle_read_tag_at(tag, tag_services::ReadTag, req, *walked);

    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(6u, resp.data.size());
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(777u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(StructWirePrefixTest, HandleWriteTagAt_StructMember_AcceptsSixByteHeader) {
    MotorFixture f;

    std::vector<ethernetip::cip::PathSegment> segs{ethernetip::cip::SymbolicPathSegment{"Timer"}};
    std::string err;
    auto walked = walk(*f.tag, segs, f.db, &err);
    ASSERT_TRUE(walked.has_value()) << err;

    std::vector<uint8_t> req(6 + f.timer_tpl->structure_size());
    ser::write_uint(req, kStructTypeIndicator);
    ser::write_uint(std::span<uint8_t>(req).subspan(2), f.timer_tpl->structure_handle());
    ser::write_uint(std::span<uint8_t>(req).subspan(4), 1);
    ser::write_udint(std::span<uint8_t>(req).subspan(6), 555);
    ser::write_udint(std::span<uint8_t>(req).subspan(10), 666);

    auto resp = tag_services::handle_write_tag_at(*f.tag, tag_services::WriteTag, req, *walked);

    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(555, f.tag->read<int32_t>(4));
    EXPECT_EQ(666, f.tag->read<int32_t>(8));
}

TEST(StructWirePrefixTest, HandleWriteTagAt_StructMember_WrongHandle_Rejected) {
    MotorFixture f;

    std::vector<ethernetip::cip::PathSegment> segs{ethernetip::cip::SymbolicPathSegment{"Timer"}};
    std::string err;
    auto walked = walk(*f.tag, segs, f.db, &err);
    ASSERT_TRUE(walked.has_value()) << err;

    std::vector<uint8_t> req(6 + f.timer_tpl->structure_size());
    ser::write_uint(req, kStructTypeIndicator);
    ser::write_uint(std::span<uint8_t>(req).subspan(2),
                     static_cast<uint16_t>(f.timer_tpl->structure_handle() ^ 0xFFFF));
    ser::write_uint(std::span<uint8_t>(req).subspan(4), 1);

    auto resp = tag_services::handle_write_tag_at(*f.tag, tag_services::WriteTag, req, *walked);

    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(0xFF, resp.status.general_status);
    ASSERT_EQ(1u, resp.status.additional_status.size());
    EXPECT_EQ(0x2107u, resp.status.additional_status[0]);
}
