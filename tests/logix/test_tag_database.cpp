#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag_database.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::logix;
namespace ldt = logix_data_types;

TEST(TagDatabaseTest, AddsAtomicTagsAndAssignsInstanceIds) {
    TagDatabase db;
    auto& a = db.add_tag("rate", ldt::Dint);
    auto& b = db.add_tag("count", ldt::Int);
    EXPECT_EQ(2, db.count());
    EXPECT_NE(a.instance_id(), b.instance_id());
    EXPECT_EQ(4, a.element_size());
    EXPECT_EQ(2, b.element_size());
    EXPECT_EQ(ldt::Dint, a.tag_type());
}

TEST(TagDatabaseTest, FindByNameIsCaseInsensitiveAndDottedPathRootsToTag) {
    TagDatabase db;
    auto& t = db.add_tag("MyTag", ldt::Real);
    EXPECT_EQ(&t, db.find_by_name("mytag"));
    EXPECT_EQ(&t, db.find_by_name("MYTAG"));
    EXPECT_EQ(&t, db.find_by_name("MyTag.member"));
    EXPECT_EQ(nullptr, db.find_by_name("other"));
}

TEST(TagDatabaseTest, FindByInstanceIdReturnsTag) {
    TagDatabase db;
    auto& t = db.add_tag("alpha", ldt::Sint);
    EXPECT_EQ(&t, db.find_by_instance_id(t.instance_id()));
    EXPECT_EQ(nullptr, db.find_by_instance_id(0xDEADu));
}

TEST(TagDatabaseTest, RejectsUnknownTagType) {
    TagDatabase db;
    EXPECT_THROW(db.add_tag("bad", 0x0099u), std::invalid_argument);
}

TEST(TagDatabaseTest, DuplicateNameThrows) {
    TagDatabase db;
    db.add_tag("same", ldt::Dint);
    EXPECT_THROW(db.add_tag("same", ldt::Dint), std::invalid_argument);
}

TEST(TagDatabaseTest, TemplateAlignmentForMixedTypes) {
    TagDatabase db;
    auto& tmpl = db.add_template("Mix", {
        {"a", ldt::Sint, 0},
        {"b", ldt::Dint, 0},
        {"c", ldt::Sint, 0},
        {"d", ldt::Lint, 0},
    });
    // a@0 (size 1), pad to 4, b@4 (size 4), c@8 (size 1), pad to 16, d@16 (size 8) → 24
    ASSERT_EQ(4, tmpl.member_count());
    EXPECT_EQ(0, tmpl.members()[0].offset);
    EXPECT_EQ(4, tmpl.members()[1].offset);
    EXPECT_EQ(8, tmpl.members()[2].offset);
    EXPECT_EQ(16, tmpl.members()[3].offset);
    EXPECT_EQ(24u, tmpl.structure_size());
}

TEST(TagDatabaseTest, BoolPackingInsertsHiddenHostSint) {
    TagDatabase db;
    auto& tmpl = db.add_template("Bits", {
        {"b0", ldt::Bool, 0},
        {"b1", ldt::Bool, 0},
        {"b2", ldt::Bool, 0},
    });
    ASSERT_EQ(4, tmpl.member_count());
    EXPECT_EQ(ldt::Sint, tmpl.members()[0].data_type);
    EXPECT_EQ(0, tmpl.members()[0].offset);
    EXPECT_EQ("ZZZZZZZZZZBits0", tmpl.members()[0].name);
    EXPECT_EQ(ldt::Bool, tmpl.members()[1].data_type);
    EXPECT_EQ(0, tmpl.members()[1].array_size);  // bit position
    EXPECT_EQ(ldt::Bool, tmpl.members()[2].data_type);
    EXPECT_EQ(1, tmpl.members()[2].array_size);
    EXPECT_EQ(ldt::Bool, tmpl.members()[3].data_type);
    EXPECT_EQ(2, tmpl.members()[3].array_size);
    EXPECT_EQ(4u, tmpl.structure_size());  // padded to 32-bit
}

TEST(TagDatabaseTest, AddTagFromTemplateUsesStructureHandle) {
    TagDatabase db;
    auto& tmpl = db.add_template("Box", {
        {"x", ldt::Dint, 0},
        {"y", ldt::Dint, 0},
    });
    auto& t = db.add_tag("boxA", tmpl);
    EXPECT_EQ(tmpl.structure_handle(), t.tag_type());
    EXPECT_EQ(static_cast<int>(tmpl.structure_size()), t.element_size());
    EXPECT_TRUE(ldt::is_struct(t.symbol_type()));
}

TEST(TagDatabaseTest, AnyTagChangedFiresOnWrite) {
    TagDatabase db;
    auto& t = db.add_tag("watch", ldt::Dint);
    int fires = 0;
    db.add_any_tag_changed_handler([&](const Tag&, TagChangeInfo) { ++fires; });
    t.write<int32_t>(0, 42);
    EXPECT_EQ(1, fires);
}
