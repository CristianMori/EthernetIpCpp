#include "ethernetip/logix/template_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/data_serializer.hpp"

#include <algorithm>
#include <cstring>

namespace ethernetip::logix {

using cip::CipAttribute;
using cip::CipDataType;
using cip::CipInstance;
using cip::CipServiceDefinition;
using cip::CipServiceRequest;
using cip::CipServiceResponse;
using cip::CipStatus;
using cip::AttributeAccess;
namespace ser = cip::serializer;

TemplateObject::TemplateObject(TagDatabase& tags) : tags_(tags) {
    cip_class_ = std::make_unique<cip::CipClass>(ClassCode, "Template", uint16_t{1});
    cip_class_view_ = cip_class_.get();

    cip_class_view_->add_instance_service(CipServiceDefinition{
        0x03, "Get_Attribute_List",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_get_attribute_list(i, r); }});
    cip_class_view_->add_instance_service(CipServiceDefinition{
        0x4C, "Template_Read",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_template_read(i, r); }});
    cip_class_view_->add_standard_instance_services();
}

std::unique_ptr<cip::CipClass> TemplateObject::release_cip_class() {
    return std::move(cip_class_);
}

void TemplateObject::ensure_instance(const TemplateDefinition& tmpl) {
    if (cip_class_view_->get_instance(tmpl.instance_id()) != nullptr) return;
    auto& inst = cip_class_view_->create_instance(tmpl.instance_id());
    // Store as void* for fast lookup in handle_template_read. const-cast is
    // safe — the template definition is owned by TagDatabase and is read-only
    // from this side.
    inst.set_user_data(const_cast<TemplateDefinition*>(&tmpl));

    inst.add_attribute(CipAttribute::create_uint(
        1, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, tmpl.structure_handle()));
    inst.add_attribute(CipAttribute::create_uint(
        2, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        static_cast<uint16_t>(tmpl.member_count())));
    inst.add_attribute(CipAttribute::create_udint(
        4, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, tmpl.definition_size()));
    inst.add_attribute(CipAttribute::create_udint(
        5, CipDataType::Udint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, tmpl.structure_size()));
}

CipServiceResponse TemplateObject::handle_get_attribute_list(
        CipInstance& inst, const CipServiceRequest& req) {
    if (req.data.size() < 2) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0x13));
    }
    uint16_t attr_count = ser::read_uint(req.data);
    if (req.data.size() < static_cast<size_t>(2 + attr_count * 2)) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0x1C));
    }

    std::vector<uint8_t> buf(512);
    int offset = 0;
    ser::write_uint(buf, attr_count);
    offset += 2;
    for (uint16_t i = 0; i < attr_count; ++i) {
        uint16_t attr_id = ser::read_uint(req.data.subspan(2u + i * 2u));
        ser::write_uint(std::span<uint8_t>(buf).subspan(offset), attr_id);
        offset += 2;

        auto* attr = inst.get_attribute(attr_id);
        if (attr != nullptr) {
            ser::write_uint(std::span<uint8_t>(buf).subspan(offset), 0u);
            offset += 2;
            offset += attr->encode_to(std::span<uint8_t>(buf).subspan(offset));
        } else {
            ser::write_uint(std::span<uint8_t>(buf).subspan(offset), 0x0014u);
            offset += 2;
        }
    }
    buf.resize(offset);
    return CipServiceResponse::success(req.service_code, std::move(buf));
}

CipServiceResponse TemplateObject::handle_template_read(
        CipInstance& inst, const CipServiceRequest& req) {
    auto* tmpl = static_cast<const TemplateDefinition*>(inst.user_data());
    if (tmpl == nullptr) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0x05));
    }
    if (req.data.size() < 6) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0x13));
    }
    uint32_t byte_offset   = ser::read_udint(req.data);
    uint16_t bytes_to_read = ser::read_uint(req.data.subspan(4));

    auto full = build_template_definition(*tmpl);
    if (byte_offset >= static_cast<uint32_t>(full.size())) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0xFF, {0x2105}));
    }
    int available = static_cast<int>(full.size()) - static_cast<int>(byte_offset);
    int chunk     = std::min<int>(available, bytes_to_read);
    chunk         = std::min(chunk, 480);

    std::vector<uint8_t> resp(full.begin() + byte_offset,
                                full.begin() + byte_offset + chunk);
    bool more = static_cast<int>(byte_offset) + chunk < static_cast<int>(full.size());
    if (more) {
        return CipServiceResponse{
            static_cast<uint8_t>(req.service_code | 0x80),
            CipStatus::error(0x06),
            std::move(resp),
        };
    }
    return CipServiceResponse::success(req.service_code, std::move(resp));
}

std::vector<uint8_t> TemplateObject::build_template_definition(const TemplateDefinition& tmpl) {
    int member_info_bytes = tmpl.member_count() * 8;
    int name_bytes = static_cast<int>(tmpl.name().size()) + 1;
    for (const auto& m : tmpl.members()) name_bytes += static_cast<int>(m.name.size()) + 1;

    int total = member_info_bytes + name_bytes;
    total = (total + 3) / 4 * 4;
    std::vector<uint8_t> data(total);
    int offset = 0;

    for (const auto& m : tmpl.members()) {
        uint16_t info = m.array_size > 0 ? static_cast<uint16_t>(m.array_size) : 0u;
        uint32_t type_and_info = (static_cast<uint32_t>(m.data_type) << 16) | info;
        ser::write_udint(std::span<uint8_t>(data).subspan(offset), type_and_info);
        offset += 4;
        ser::write_udint(std::span<uint8_t>(data).subspan(offset),
                          static_cast<uint32_t>(m.offset));
        offset += 4;
    }

    std::memcpy(data.data() + offset, tmpl.name().data(), tmpl.name().size());
    offset += static_cast<int>(tmpl.name().size());
    data[offset++] = 0;

    for (const auto& m : tmpl.members()) {
        std::memcpy(data.data() + offset, m.name.data(), m.name.size());
        offset += static_cast<int>(m.name.size());
        data[offset++] = 0;
    }
    return data;
}

} // namespace ethernetip::logix
