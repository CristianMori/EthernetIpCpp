#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/persistence.hpp"
#include "ethernetip/logix/tag_database.hpp"

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <sstream>

using namespace ethernetip::logix;
namespace ldt = ethernetip::logix::logix_data_types;

static void make_schema(TagDatabase& db) {
    db.add_tag("rate", ldt::Dint);
    db.add_tag("arr", ldt::Dint, 8);
    db.add_tag("flags", ldt::Bool, 32);
}

TEST(PersistenceTest, RoundTripPreservesValues) {
    TagDatabase db;
    make_schema(db);
    db.find_by_name("rate")->write<int32_t>(0, 12345);
    for (int i = 0; i < 8; ++i) {
        db.find_by_name("arr")->write<int32_t>(i * 4, 100 + i);
    }
    uint8_t flag_bytes[4] = {0xAB, 0xCD, 0xEF, 0x12};
    db.find_by_name("flags")->set_data(flag_bytes);

    std::stringstream buf;
    persistence::save(db, buf);

    TagDatabase db2;
    make_schema(db2);
    buf.seekg(0);
    auto result = persistence::load(db2, buf);
    EXPECT_EQ(result.tags_restored, 3);
    EXPECT_EQ(result.tags_skipped, 0);
    EXPECT_EQ(db2.find_by_name("rate")->read<int32_t>(0), 12345);
    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(db2.find_by_name("arr")->read<int32_t>(i * 4), 100 + i);
    }
    EXPECT_EQ(db2.find_by_name("flags")->get_data()[0], 0xAB);
}

TEST(PersistenceTest, ProgramScopeRoundTrip) {
    TagDatabase db;
    db.add_tag("controller_tag", ldt::Dint);
    db.find_by_name("controller_tag")->write<int32_t>(0, 111);
    db.register_program("Cell");
    auto& t = db.add_program_tag("Cell", "Rate", ldt::Dint);
    t.write<int32_t>(0, 222);

    std::stringstream buf;
    persistence::save(db, buf);

    TagDatabase db2;
    db2.add_tag("controller_tag", ldt::Dint);
    db2.register_program("Cell");
    db2.add_program_tag("Cell", "Rate", ldt::Dint);

    buf.seekg(0);
    auto result = persistence::load(db2, buf);
    EXPECT_EQ(result.tags_restored, 2);
    EXPECT_EQ(db2.find_program_tag("Cell", "Rate")->read<int32_t>(0), 222);
}

TEST(PersistenceTest, MissingTagSkipped) {
    TagDatabase db;
    make_schema(db);
    std::stringstream buf;
    persistence::save(db, buf);

    TagDatabase db2;
    db2.add_tag("rate", ldt::Dint);   // arr and flags missing
    buf.seekg(0);
    auto result = persistence::load(db2, buf);
    EXPECT_EQ(result.tags_restored, 1);
    EXPECT_EQ(result.tags_skipped, 2);
    EXPECT_EQ(2u, std::count_if(result.warnings.begin(), result.warnings.end(),
                                 [](const std::string& s){ return s.find("not registered") != std::string::npos; }));
}

TEST(PersistenceTest, BadMagicRaises) {
    TagDatabase db;
    std::stringstream buf(std::string(8, '\0'));
    EXPECT_THROW((void)persistence::load(db, buf), std::runtime_error);
}

TEST(PersistenceTest, FutureVersionRaises) {
    TagDatabase db;
    std::vector<char> payload = {'E','I','P','S', static_cast<char>(99), 0, 0, 0,
                                  0, 0, 0, 0,   // 0 controller tags
                                  0, 0, 0, 0};  // 0 programs
    std::stringstream buf(std::string(payload.begin(), payload.end()));
    EXPECT_THROW((void)persistence::load(db, buf), std::runtime_error);
}
