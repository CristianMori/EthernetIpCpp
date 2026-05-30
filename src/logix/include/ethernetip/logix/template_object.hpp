#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/logix/tag_database.hpp"

#include <cstdint>
#include <memory>

namespace ethernetip::logix {

/// CIP Template Object (Class 0x6C). Each UDT/structure has one instance.
/// Provides Get_Attribute_List (0x03) for handle/size info and
/// Template_Read (0x4C) for member definitions.
class TemplateObject {
public:
    static constexpr uint32_t ClassCode = 0x6C;

    explicit TemplateObject(TagDatabase& tags);

    [[nodiscard]] cip::CipClass&                  cip_class() noexcept { return *cip_class_view_; }
    [[nodiscard]] std::unique_ptr<cip::CipClass>  release_cip_class();

    /// Ensure a CIP instance exists for the template. Idempotent.
    void ensure_instance(const TemplateDefinition& tmpl);

private:
    cip::CipServiceResponse handle_get_attribute_list(cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_template_read    (cip::CipInstance&, const cip::CipServiceRequest&);

    /// Build the wire-format template definition data for Template_Read.
    [[nodiscard]] static std::vector<uint8_t> build_template_definition(const TemplateDefinition& tmpl);

    TagDatabase& tags_;
    std::unique_ptr<cip::CipClass> cip_class_;
    cip::CipClass* cip_class_view_ = nullptr;
};

} // namespace ethernetip::logix
