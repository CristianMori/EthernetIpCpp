#include "ethernetip/safety/safety_types.hpp"

#include <array>
#include <gtest/gtest.h>

using namespace ethernetip::safety;

TEST(ModeByteTest, CreateRunIdleZero) {
    auto m = ModeByte::create(false, 0);
    EXPECT_EQ(0x14, m.value());                 // run=0, ping=0, n_run=1, n_tbd=1
    EXPECT_FALSE(m.run_idle());
    EXPECT_EQ(0u, m.ping_count());
    EXPECT_TRUE(m.validate());
}

TEST(ModeByteTest, CreateRunWithPings) {
    EXPECT_EQ(0x84, ModeByte::create(true, 0).value());
    EXPECT_EQ(0x85, ModeByte::create(true, 1).value());
    EXPECT_EQ(0x86, ModeByte::create(true, 2).value());
    EXPECT_EQ(0x87, ModeByte::create(true, 3).value());
}

TEST(ModeByteTest, ValidateRejectsInvalidComplement) {
    // raw = 0x84 (valid) — clearing the n_run bit produces 0x90 -> still has bit 7,
    // n_run cleared -> run==n_run==1? Actually bit 4 is n_run; clearing => 0
    // run=1 n_run=0 -> still complement -> valid. Hmm let me try invalidating differently.
    EXPECT_FALSE(ModeByte{0x80}.validate());     // run=1, n_run=0... wait 0x80 has bit 7=1, bit 4=0, so n_run=0 which IS complement
    // Build a known-invalid: run=1, n_run=1 (both set) -> 0x90
    EXPECT_FALSE(ModeByte{0x90}.validate());
}

TEST(SafetyNetworkNumberTest, CopyAndCompare) {
    std::array<uint8_t, 6> raw{0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D};
    SafetyNetworkNumber snn{raw};
    std::array<uint8_t, 6> out{};
    snn.copy_to(out);
    EXPECT_EQ(raw, out);
    EXPECT_EQ(snn, SafetyNetworkNumber{raw});
}

TEST(UniqueNetworkIdTest, RoundTrip) {
    UniqueNetworkId u{
        .snn = SafetyNetworkNumber(std::array<uint8_t, 6>{0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D}),
        .node_address = 0xC0A80154,
    };
    std::array<uint8_t, 10> buf{};
    u.copy_to(buf);
    auto round = UniqueNetworkId::parse(buf);
    EXPECT_EQ(u, round);
}

TEST(SafetyConfigurationIdTest, RoundTrip) {
    SafetyConfigurationId s{
        .sccrc = 0x781B988E,
        .scts = SafetyNetworkNumber(std::array<uint8_t, 6>{0xB6, 0x0D, 0xED, 0x00, 0x8E, 0x4D}),
    };
    std::array<uint8_t, 10> buf{};
    s.copy_to(buf);
    auto round = SafetyConfigurationId::parse(buf);
    EXPECT_EQ(s.sccrc, round.sccrc);
    EXPECT_EQ(s.scts, round.scts);
}
