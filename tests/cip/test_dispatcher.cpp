#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/cip_instance.hpp"
#include "ethernetip/cip/standard_services.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::cip;

namespace {

std::unique_ptr<CipClass> make_simple_identity_class() {
    auto cls = std::make_unique<CipClass>(0x01, "Identity", uint16_t{1});
    cls->add_standard_instance_services();
    auto& inst = cls->create_instance(1);
    inst.add_attribute(CipAttribute::create_uint(
        1, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        uint16_t{0x4242}));  // vendor ID
    inst.add_attribute(CipAttribute::create_byte(
        4, CipDataType::Usint,
        AttributeAccess::GetSingle | AttributeAccess::SetSingle,
        uint8_t{7}));        // settable byte
    return cls;
}

CipPath path(uint32_t cls, uint32_t inst, std::optional<uint16_t> attr) {
    CipPath p;
    p.class_id = cls;
    p.instance_id = inst;
    p.attribute_id = attr;
    return p;
}

} // namespace

TEST(DispatcherTest, GetAttributeSingleReturnsAttributeData) {
    CipDispatcher d;
    d.register_class(make_simple_identity_class());

    auto resp = d.dispatch(standard_services::GetAttributeSingle,
                           path(0x01, 1, uint16_t{1}),
                           std::span<const uint8_t>());
    EXPECT_EQ(0x8E, resp.service_code);     // reply bit
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(2u, resp.data.size());
    EXPECT_EQ(0x42, resp.data[0]);          // 0x4242 little-endian
    EXPECT_EQ(0x42, resp.data[1]);
}

TEST(DispatcherTest, UnknownClassReturnsPathDestinationUnknown) {
    CipDispatcher d;
    auto resp = d.dispatch(0x0E, path(0x99, 1, uint16_t{1}), std::span<const uint8_t>());
    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(CipStatus::PathDestinationUnknown, resp.status.general_status);
}

TEST(DispatcherTest, UnknownInstanceReturnsObjectDoesNotExist) {
    CipDispatcher d;
    d.register_class(make_simple_identity_class());
    auto resp = d.dispatch(0x0E, path(0x01, 99, uint16_t{1}), std::span<const uint8_t>());
    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(CipStatus::ObjectDoesNotExist, resp.status.general_status);
}

TEST(DispatcherTest, UnknownServiceReturnsServiceNotSupported) {
    CipDispatcher d;
    d.register_class(make_simple_identity_class());
    auto resp = d.dispatch(0x7F, path(0x01, 1, uint16_t{1}), std::span<const uint8_t>());
    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(CipStatus::ServiceNotSupported, resp.status.general_status);
}

TEST(DispatcherTest, SetAttributeSinglePersists) {
    CipDispatcher d;
    d.register_class(make_simple_identity_class());

    uint8_t new_value[] = {0x55};
    auto resp = d.dispatch(standard_services::SetAttributeSingle,
                           path(0x01, 1, uint16_t{4}),
                           std::span<const uint8_t>(new_value));
    EXPECT_TRUE(resp.status.is_success());

    auto read = d.dispatch(standard_services::GetAttributeSingle,
                           path(0x01, 1, uint16_t{4}),
                           std::span<const uint8_t>());
    ASSERT_EQ(1u, read.data.size());
    EXPECT_EQ(0x55, read.data[0]);
}

TEST(DispatcherTest, GetAttributeAllReturnsSortedByAttributeId) {
    CipDispatcher d;
    d.register_class(make_simple_identity_class());

    // class-level (instance 0)
    auto resp = d.dispatch(standard_services::GetAttributeAll,
                           path(0x01, 0, std::nullopt),
                           std::span<const uint8_t>());
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(4u, resp.data.size());     // attr 1 (revision UINT) + attr 2 (max-inst UINT)
    EXPECT_EQ(0x01, resp.data[0]);       // revision = 1
    EXPECT_EQ(0x00, resp.data[1]);
    EXPECT_EQ(0x01, resp.data[2]);       // max instance ID = 1
    EXPECT_EQ(0x00, resp.data[3]);
}
