#pragma once

#include "ethernetip/cip/cip_attribute.hpp"

#include <any>
#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

namespace ethernetip::cip {

class CipClass;  // forward

/// Represents a single instance of a CIP class. Each instance holds a set of
/// attributes identified by numeric ID. Instance 0 is reserved for
/// class-level attributes (managed by CipClass).
class CipInstance {
public:
    explicit CipInstance(uint32_t instance_id) : instance_id_(instance_id) {}

    [[nodiscard]] uint32_t instance_id() const noexcept { return instance_id_; }
    [[nodiscard]] CipClass* owner_class() const noexcept { return owner_class_; }

    /// Application-specific data attached to this instance — used to wire CIP
    /// objects to domain entities (Assembly, Tag) without coupling the CIP
    /// layer to those types. The CipInstance does not own the pointed-to value.
    [[nodiscard]] void* user_data() const noexcept { return user_data_; }
    void set_user_data(void* p) noexcept { user_data_ = p; }

    /// Add or replace an attribute on this instance. Invalidates GetAll cache.
    void add_attribute(std::unique_ptr<CipAttribute> attr);

    /// Look up an attribute by ID. Returns nullptr if not found.
    [[nodiscard]] CipAttribute* get_attribute(uint16_t id) const;

    [[nodiscard]] size_t attribute_count() const noexcept { return attributes_.size(); }

    /// Encode all attributes with the GetAll access flag, sorted by ID.
    /// Returns the number of bytes written.
    int encode_all_attributes(std::span<uint8_t> dst);

    // Used by CipClass when adding the instance.
    void set_owner_class(CipClass* c) noexcept { owner_class_ = c; }

private:
    uint32_t instance_id_ = 0;
    CipClass* owner_class_ = nullptr;
    void* user_data_ = nullptr;
    std::unordered_map<uint16_t, std::unique_ptr<CipAttribute>> attributes_;
    mutable std::vector<CipAttribute*> get_all_cache_;
    mutable bool get_all_cache_valid_ = false;

    void rebuild_get_all_cache() const;
};

} // namespace ethernetip::cip
