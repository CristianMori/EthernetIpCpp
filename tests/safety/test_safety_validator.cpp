#include "ethernetip/connections/io_connection.hpp"
#include "ethernetip/safety/safety_validator_object.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::safety;
using namespace ethernetip::connections;

TEST(SafetyValidatorTest, CreateInstanceCopiesSeeds) {
    IoConnection conn;
    conn.safety_pid_seed_s1 = 0x12;
    conn.safety_pid_seed_s3 = 0xABCD;
    conn.safety_pid_seed_s5 = 0x00CAFEBA;

    SafetyValidatorObject v;
    auto* inst = v.create_instance(conn);
    ASSERT_NE(nullptr, inst);
    EXPECT_EQ(1u, inst->instance_id);
    EXPECT_EQ(&conn, inst->connection);
    EXPECT_EQ(SafetyValidatorState::Idle, inst->state);
    EXPECT_EQ(0x12, inst->pid_seed_s1);
    EXPECT_EQ(0xABCD, inst->pid_seed_s3);
    EXPECT_EQ(0x00CAFEBAu, inst->pid_seed_s5);
}

TEST(SafetyValidatorTest, AdvanceTimestampWrapsAndBumpsRollover) {
    SafetyValidatorInstance inst;
    inst.timestamp = 0xFFF0;
    inst.rollover_count = 5;
    inst.advance_timestamp(0x20);                 // 0xFFF0 + 0x20 = 0x10010
    EXPECT_EQ(0x0010, inst.timestamp);
    EXPECT_EQ(6, inst.rollover_count);
}

TEST(SafetyValidatorTest, GetInstanceFindsCreated) {
    IoConnection conn;
    SafetyValidatorObject v;
    auto* a = v.create_instance(conn);
    auto* b = v.get_instance(a->instance_id);
    EXPECT_EQ(a, b);
    EXPECT_EQ(nullptr, v.get_instance(999));
}

// Regression: FwdOpen+FwdClose cycles must not leak validator entries
// (previously instances_ grew unbounded and the raw IoConnection*
// pointers in released entries dangled past their owners).
TEST(SafetyValidatorTest, RemoveInstanceByConnectionDoesNotLeakAcrossReopens) {
    SafetyValidatorObject v;
    EXPECT_EQ(0u, v.instance_count());
    for (int i = 0; i < 10; ++i) {
        IoConnection conn;
        auto* inst = v.create_instance(conn);
        ASSERT_NE(nullptr, inst);
        EXPECT_EQ(1u, v.instance_count());
        EXPECT_TRUE(v.remove_instance_by_connection(&conn));
        EXPECT_EQ(0u, v.instance_count());
        // Removed instance must be gone from the lookup table.
        EXPECT_EQ(nullptr, v.get_instance(inst->instance_id));
    }
    // Second remove is a no-op (reverse map already drained).
    IoConnection sentinel;
    EXPECT_FALSE(v.remove_instance_by_connection(&sentinel));
}
