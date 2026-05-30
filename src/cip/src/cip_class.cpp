#include "ethernetip/cip/cip_class.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/cip/standard_services.hpp"

namespace ethernetip::cip {

CipClass::CipClass(uint32_t class_code, std::string name, uint16_t revision)
    : class_code_(class_code), name_(std::move(name)) {
    class_instance_.set_owner_class(this);

    // Standard class-level attributes
    class_instance_.add_attribute(CipAttribute::create_uint(
        1, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, revision));
    class_instance_.add_attribute(CipAttribute::create_uint(
        2, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        uint16_t{0}));  // max instance — updated dynamically

    // Standard class-level services
    add_class_service({standard_services::GetAttributeSingle, "Get_Attribute_Single",
                       standard_services::handle_get_attribute_single});
    add_class_service({standard_services::GetAttributeAll, "Get_Attributes_All",
                       standard_services::handle_get_attribute_all});
}

CipInstance& CipClass::create_instance(uint32_t instance_id) {
    auto inst = std::make_unique<CipInstance>(instance_id);
    inst->set_owner_class(this);
    CipInstance* raw = inst.get();
    instances_[instance_id] = std::move(inst);
    update_max_instance(instance_id);
    return *raw;
}

CipInstance* CipClass::get_instance(uint32_t instance_id) {
    if (instance_id == 0) {
        return &class_instance_;
    }
    auto it = instances_.find(instance_id);
    return it == instances_.end() ? nullptr : it->second.get();
}

void CipClass::update_max_instance(uint32_t instance_id) {
    if (instance_id <= max_instance_id_) return;
    max_instance_id_ = instance_id;
    if (auto* attr = class_instance_.get_attribute(2)) {
        uint8_t buf[2];
        serializer::write_uint(buf, static_cast<uint16_t>(max_instance_id_));
        attr->set_data(buf);
    }
}

void CipClass::add_instance_service(CipServiceDefinition service) {
    instance_services_[service.service_code] = std::move(service);
}

const CipServiceDefinition* CipClass::get_instance_service(uint8_t code) const {
    auto it = instance_services_.find(code);
    return it == instance_services_.end() ? nullptr : &it->second;
}

void CipClass::add_class_service(CipServiceDefinition service) {
    class_services_[service.service_code] = std::move(service);
}

const CipServiceDefinition* CipClass::get_class_service(uint8_t code) const {
    auto it = class_services_.find(code);
    return it == class_services_.end() ? nullptr : &it->second;
}

const CipServiceDefinition* CipClass::get_service(uint8_t code, bool is_class_level) const {
    return is_class_level ? get_class_service(code) : get_instance_service(code);
}

void CipClass::add_standard_instance_services() {
    add_instance_service({standard_services::GetAttributeSingle, "Get_Attribute_Single",
                          standard_services::handle_get_attribute_single});
    add_instance_service({standard_services::SetAttributeSingle, "Set_Attribute_Single",
                          standard_services::handle_set_attribute_single});
    add_instance_service({standard_services::GetAttributeAll, "Get_Attributes_All",
                          standard_services::handle_get_attribute_all});
}

} // namespace ethernetip::cip
