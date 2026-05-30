#include "ethernetip/safety/safety_validator_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"

namespace ethernetip::safety {

void SafetyValidatorInstance::advance_timestamp(uint16_t increment) noexcept {
    uint32_t nxt = static_cast<uint32_t>(timestamp) + increment;
    if (nxt > 0xFFFFu) {
        rollover_count = static_cast<uint16_t>(rollover_count + 1);
        timestamp = static_cast<uint16_t>(nxt & 0xFFFFu);
    } else {
        timestamp = static_cast<uint16_t>(nxt);
    }
}

SafetyValidatorObject::SafetyValidatorObject() {
    cip_class_ = std::make_unique<cip::CipClass>(ClassCode, "Safety Validator", uint16_t{1});
    cip_class_ptr_ = cip_class_.get();  // survives release_cip_class()
    cip_class_->add_standard_instance_services();
}

std::unique_ptr<cip::CipClass> SafetyValidatorObject::release_cip_class() {
    return std::move(cip_class_);
}

SafetyValidatorInstance* SafetyValidatorObject::create_instance(
        connections::IoConnection& connection) {
    ++next_instance_id_;
    cip::CipInstance& cip_inst = cip_class_ptr_->create_instance(next_instance_id_);

    auto validator = std::make_unique<SafetyValidatorInstance>();
    validator->instance_id  = next_instance_id_;
    validator->cip_instance = &cip_inst;
    validator->connection   = &connection;
    validator->state        = SafetyValidatorState::Idle;
    validator->pid_seed_s1  = connection.safety_pid_seed_s1;
    validator->pid_seed_s3  = connection.safety_pid_seed_s3;
    validator->pid_seed_s5  = connection.safety_pid_seed_s5;

    cip_inst.set_user_data(validator.get());

    cip_inst.add_attribute(cip::CipAttribute::create_byte(
        1, cip::CipDataType::Usint,
        cip::AttributeAccess::GetSingle | cip::AttributeAccess::GetAll,
        static_cast<uint8_t>(validator->state)));
    cip_inst.add_attribute(cip::CipAttribute::create_byte(
        2, cip::CipDataType::Usint,
        cip::AttributeAccess::GetSingle | cip::AttributeAccess::GetAll,
        uint8_t{0}));  // Validator type — reserved for now

    SafetyValidatorInstance* raw = validator.get();
    instances_[next_instance_id_] = std::move(validator);
    return raw;
}

SafetyValidatorInstance* SafetyValidatorObject::get_instance(uint32_t instance_id) {
    auto it = instances_.find(instance_id);
    return it == instances_.end() ? nullptr : it->second.get();
}

} // namespace ethernetip::safety
