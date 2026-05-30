#pragma once

#include "ethernetip/cip/cip_instance.hpp"
#include "ethernetip/cip/cip_service.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

namespace ethernetip::cip {

/// A CIP class (object type). Holds a set of instances plus services
/// available at the class level (instance 0) and at the instance level
/// (shared by all instances). Instance 0 (class_instance()) holds class
/// attributes such as revision and max instance ID.
class CipClass {
public:
    /// Construct a class with the given class code, name, and revision.
    /// Auto-creates instance 0 with revision (attr 1) and max instance ID
    /// (attr 2). Also registers GetAttributeSingle / GetAttributeAll as
    /// class-level services on instance 0.
    CipClass(uint32_t class_code, std::string name, uint16_t revision = 1);

    [[nodiscard]] uint32_t          class_code() const noexcept { return class_code_; }
    [[nodiscard]] const std::string& name()      const noexcept { return name_; }

    /// Instance 0 — class-level instance.
    [[nodiscard]] CipInstance& class_instance() noexcept { return class_instance_; }

    /// Create a new instance with the given ID and add it to this class.
    /// Updates the max-instance class attribute.
    CipInstance& create_instance(uint32_t instance_id);

    /// Look up an instance by ID. Instance 0 returns the class instance.
    /// Returns nullptr if the instance does not exist.
    [[nodiscard]] CipInstance* get_instance(uint32_t instance_id);

    [[nodiscard]] const std::unordered_map<uint32_t, std::unique_ptr<CipInstance>>&
        instances() const noexcept { return instances_; }

    /// Register a service available on all instances of this class.
    void add_instance_service(CipServiceDefinition service);
    [[nodiscard]] const CipServiceDefinition* get_instance_service(uint8_t code) const;

    /// Register a service available on the class itself (instance 0).
    void add_class_service(CipServiceDefinition service);
    [[nodiscard]] const CipServiceDefinition* get_class_service(uint8_t code) const;

    /// Look up a service, picking class-level or instance-level based on whether
    /// the request targets instance 0.
    [[nodiscard]] const CipServiceDefinition* get_service(uint8_t code, bool is_class_level) const;

    /// Register the standard CIP instance services (Get/Set Attribute Single,
    /// Get Attributes All) on this class.
    void add_standard_instance_services();

private:
    void update_max_instance(uint32_t instance_id);

    uint32_t class_code_ = 0;
    std::string name_;
    CipInstance class_instance_{0};
    uint32_t max_instance_id_ = 0;
    std::unordered_map<uint32_t, std::unique_ptr<CipInstance>> instances_;
    std::unordered_map<uint8_t, CipServiceDefinition> instance_services_;
    std::unordered_map<uint8_t, CipServiceDefinition> class_services_;
};

} // namespace ethernetip::cip
