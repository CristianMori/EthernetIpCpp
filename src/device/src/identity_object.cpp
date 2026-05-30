#include "ethernetip/device/identity_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/standard_services.hpp"

namespace ethernetip::device::identity_object {

using namespace ethernetip::cip;

std::unique_ptr<CipClass> create(const IdentityInfo& identity) {
    auto cls = std::make_unique<CipClass>(IdentityInfo::ClassCode, "Identity", uint16_t{1});
    cls->add_standard_instance_services();

    // Reset (no-op for a simulator — returns success).
    cls->add_instance_service({
        standard_services::Reset, "Reset",
        [](CipInstance&, const CipServiceRequest& r) {
            return CipServiceResponse::success(r.service_code);
        }});

    CipInstance& inst = cls->create_instance(1);
    inst.add_attribute(CipAttribute::create_uint(
        1, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, identity.vendor_id));
    inst.add_attribute(CipAttribute::create_uint(
        2, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, identity.device_type));
    inst.add_attribute(CipAttribute::create_uint(
        3, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, identity.product_code));
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{4}, CipDataType::Usint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        std::vector<uint8_t>{identity.major_revision, identity.minor_revision}));
    inst.add_attribute(CipAttribute::create_uint(
        5, CipDataType::Word,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, identity.status));
    inst.add_attribute(CipAttribute::create_udint(
        6, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, identity.serial_number));
    inst.add_attribute(CipAttribute::create_short_string(
        7, AttributeAccess::GetSingle | AttributeAccess::GetAll, identity.product_name));
    return cls;
}

} // namespace ethernetip::device::identity_object
