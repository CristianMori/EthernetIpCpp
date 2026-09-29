#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/walker.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::cip;
using namespace ethernetip::logix;
namespace ldt = ethernetip::logix::logix_data_types;

static TemplateDefinition make_timer() {
    return TemplateDefinition{
        0x300, "Timer", 0x8300, 12,
        std::vector<TemplateMemberInfo>{
            {"PRE", ldt::Dint, 0, 0, 4},
            {"ACC", ldt::Dint, 4, 0, 4},
            {"EN",  ldt::Bool, 8, 0, 0},
            {"TT",  ldt::Bool, 8, 1, 0},
            {"DN",  ldt::Bool, 8, 2, 0},
        }
    };
}

TEST(WalkerTest, ResolvesScalarMember) {
    TagDatabase db;
    auto& tpl = db.add_template_prebuilt(std::make_unique<TemplateDefinition>(make_timer()));
    auto& tag = db.add_tag("t1", tpl);
    std::vector<PathSegment> segs = { SymbolicPathSegment{"ACC"} };
    std::string err;
    auto r = walk(tag, segs, db, &err);
    ASSERT_TRUE(r.has_value()) << err;
    EXPECT_EQ(r->offset, 4);
    EXPECT_EQ(r->type_code, ldt::Dint);
    EXPECT_FALSE(r->bit_pos.has_value());
}

TEST(WalkerTest, ResolvesBoolMemberBitPosition) {
    TagDatabase db;
    auto& tpl = db.add_template_prebuilt(std::make_unique<TemplateDefinition>(make_timer()));
    auto& tag = db.add_tag("t1", tpl);
    std::vector<PathSegment> segs = { SymbolicPathSegment{"DN"} };
    std::string err;
    auto r = walk(tag, segs, db, &err);
    ASSERT_TRUE(r.has_value()) << err;
    EXPECT_EQ(r->offset, 8);
    EXPECT_TRUE(r->bit_pos.has_value());
    EXPECT_EQ(*r->bit_pos, 2);
}

TEST(WalkerTest, ThreeDimRowMajorOffset) {
    TagDatabase db;
    auto& tag = db.add_tag_dims("m", ldt::Dint, {5, 10, 4});
    std::vector<PathSegment> segs = {
        ElementPathSegment{1}, ElementPathSegment{2}, ElementPathSegment{3}
    };
    std::string err;
    auto r = walk(tag, segs, db, &err);
    ASSERT_TRUE(r.has_value()) << err;
    EXPECT_EQ(r->offset, 204);   // ((1*10+2)*4+3)*4
}

TEST(WalkerTest, UnderIndexedErrors) {
    TagDatabase db;
    auto& tag = db.add_tag_dims("m", ldt::Dint, {5, 10, 4});
    std::vector<PathSegment> segs = {
        ElementPathSegment{1}, ElementPathSegment{2}
    };
    std::string err;
    auto r = walk(tag, segs, db, &err);
    EXPECT_FALSE(r.has_value());
    EXPECT_NE(err.find("under-indexed"), std::string::npos);
}

TEST(WalkerTest, BoolArrayBitIndex) {
    TagDatabase db;
    auto& tag = db.add_tag("flags", ldt::Bool, 32);
    std::vector<PathSegment> segs = { ElementPathSegment{5} };
    std::string err;
    auto r = walk(tag, segs, db, &err);
    ASSERT_TRUE(r.has_value()) << err;
    EXPECT_EQ(r->offset, 0);
    EXPECT_TRUE(r->bit_pos.has_value());
    EXPECT_EQ(*r->bit_pos, 5);
}

TEST(WalkerTest, BoolArrayCrossesDwordBoundary) {
    TagDatabase db;
    auto& tag = db.add_tag("big", ldt::Bool, 128);
    std::vector<PathSegment> segs = { ElementPathSegment{65} };
    std::string err;
    auto r = walk(tag, segs, db, &err);
    ASSERT_TRUE(r.has_value()) << err;
    EXPECT_EQ(r->offset, 8);
    EXPECT_TRUE(r->bit_pos.has_value());
    EXPECT_EQ(*r->bit_pos, 1);
}

TEST(WalkerTest, BoolArrayNonMultipleOf32Rejected) {
    TagDatabase db;
    EXPECT_THROW(db.add_tag("bad", ldt::Bool, 10), std::invalid_argument);
}
