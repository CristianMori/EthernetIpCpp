#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/safety/safety_supervisor_object.hpp"

#include <array>
#include <gtest/gtest.h>

using namespace ethernetip::safety;
using namespace ethernetip::cip;

namespace {
SafetyNetworkNumber make_snn() {
    return SafetyNetworkNumber(std::array<uint8_t, 6>{0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D});
}
} // namespace

TEST(SafetySupervisorTest, ConstructionRegistersClassAndInstance) {
    SafetySupervisorObject sup(make_snn(), 0xC0A80154u);
    EXPECT_EQ(SafetySupervisorObject::ClassCode, sup.cip_class().class_code());
    EXPECT_NE(nullptr, sup.cip_class().get_instance(1));
    EXPECT_EQ(SafetySupervisorState::Idle, sup.state());
    EXPECT_EQ(SafetySupervisorMode::Idle, sup.mode());
}

TEST(SafetySupervisorTest, StartTransitionsToExecutingRun) {
    SafetySupervisorObject sup(make_snn(), 0xC0A80154u);
    sup.start();
    EXPECT_EQ(SafetySupervisorState::Executing, sup.state());
    EXPECT_EQ(SafetySupervisorMode::Run, sup.mode());

    // Instance 1 attr 1 (state) should reflect Executing.
    auto* a = sup.cip_class().get_instance(1)->get_attribute(1);
    ASSERT_NE(nullptr, a);
    EXPECT_EQ(static_cast<uint8_t>(SafetySupervisorState::Executing), a->data()[0]);
}

TEST(SafetySupervisorTest, ProposeApplyTunidPersists) {
    SafetySupervisorObject sup(make_snn(), 0xC0A80154u);
    UniqueNetworkId new_tunid{
        SafetyNetworkNumber(std::array<uint8_t, 6>{1, 2, 3, 4, 5, 6}), 0x0A00000B};

    std::vector<uint8_t> serial(UniqueNetworkId::Size);
    new_tunid.copy_to(serial);

    auto& inst = *sup.cip_class().get_instance(1);
    const auto* propose = sup.cip_class().get_instance_service(SafetySupervisorObject::ProposeTunidService);
    const auto* apply   = sup.cip_class().get_instance_service(SafetySupervisorObject::ApplyTunidService);

    auto r1 = propose->handler(inst,
        CipServiceRequest{SafetySupervisorObject::ProposeTunidService, CipPath{}, serial});
    EXPECT_TRUE(r1.status.is_success());
    EXPECT_FALSE(sup.tunid_assigned());

    auto r2 = apply->handler(inst,
        CipServiceRequest{SafetySupervisorObject::ApplyTunidService, CipPath{}, serial});
    EXPECT_TRUE(r2.status.is_success());
    EXPECT_TRUE(sup.tunid_assigned());
    EXPECT_EQ(new_tunid, sup.tunid());
}

TEST(SafetySupervisorTest, ApplyWithoutProposeFails) {
    SafetySupervisorObject sup(make_snn(), 0xC0A80154u);
    std::vector<uint8_t> serial(UniqueNetworkId::Size);
    auto& inst = *sup.cip_class().get_instance(1);
    const auto* apply = sup.cip_class().get_instance_service(SafetySupervisorObject::ApplyTunidService);

    auto r = apply->handler(inst,
        CipServiceRequest{SafetySupervisorObject::ApplyTunidService, CipPath{}, serial});
    EXPECT_FALSE(r.status.is_success());
    EXPECT_EQ(0x0C, r.status.general_status);   // Object state conflict
}

TEST(SafetySupervisorTest, ResetType2ClearsOwnership) {
    SafetySupervisorObject sup(make_snn(), 0xC0A80154u);
    sup.set_scid(SafetyConfigurationId{0xDEADBEEFu, SafetyNetworkNumber{}});

    std::vector<uint8_t> req_data{2};
    auto& inst = *sup.cip_class().get_instance(1);
    auto r = sup.cip_class().get_instance_service(SafetySupervisorObject::SafetyResetService)
                  ->handler(inst,
                            CipServiceRequest{SafetySupervisorObject::SafetyResetService,
                                                CipPath{}, req_data});
    EXPECT_TRUE(r.status.is_success());
    EXPECT_EQ(0u, sup.scid().sccrc);
    EXPECT_FALSE(sup.tunid_assigned());
}
