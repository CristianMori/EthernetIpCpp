#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/logix/tag_database.hpp"

#include <cstdint>

namespace ethernetip::logix {

/// CIP Symbol Object (Class 0x6B). Each Tag in the controller is an instance.
/// Supports Read/Write Tag at the instance level and
/// Get_Instance_Attribute_List (0x55) at the class level for tag browsing.
class SymbolObject {
public:
    static constexpr uint32_t ClassCode               = 0x6B;
    static constexpr uint8_t  GetInstanceAttributeList = 0x55;

    explicit SymbolObject(TagDatabase& tags);

    [[nodiscard]] cip::CipClass&                       cip_class() noexcept { return *cip_class_view_; }
    [[nodiscard]] std::unique_ptr<cip::CipClass>       release_cip_class();

    /// Ensure a CIP instance exists for `tag`. Idempotent.
    void ensure_instance(Tag& tag);

private:
    cip::CipServiceResponse handle_instance_read_tag           (cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_instance_write_tag          (cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_instance_read_tag_fragmented(cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_instance_write_tag_fragmented(cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_instance_read_modify_write  (cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_get_instance_attribute_list (cip::CipInstance&, const cip::CipServiceRequest&);

    Tag* tag_from_instance(cip::CipInstance&);

    TagDatabase& tags_;
    std::unique_ptr<cip::CipClass> cip_class_;
    cip::CipClass* cip_class_view_ = nullptr;
};

} // namespace ethernetip::logix
