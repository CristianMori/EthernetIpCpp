#include "ethernetip/logix/symbol_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

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

SymbolObject::SymbolObject(TagDatabase& tags) : tags_(tags) {
    cip_class_ = std::make_unique<cip::CipClass>(ClassCode, "Symbol", uint16_t{1});
    cip_class_view_ = cip_class_.get();

    cip_class_view_->add_instance_service(CipServiceDefinition{
        tag_services::ReadTag, "Read_Tag",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_instance_read_tag(i, r); }});
    cip_class_view_->add_instance_service(CipServiceDefinition{
        tag_services::WriteTag, "Write_Tag",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_instance_write_tag(i, r); }});
    cip_class_view_->add_instance_service(CipServiceDefinition{
        tag_services::ReadTagFragmented, "Read_Tag_Fragmented",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_instance_read_tag_fragmented(i, r); }});
    cip_class_view_->add_instance_service(CipServiceDefinition{
        tag_services::WriteTagFragmented, "Write_Tag_Fragmented",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_instance_write_tag_fragmented(i, r); }});
    cip_class_view_->add_instance_service(CipServiceDefinition{
        tag_services::ReadModifyWrite, "Read_Modify_Write",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_instance_read_modify_write(i, r); }});

    cip_class_view_->add_class_service(CipServiceDefinition{
        GetInstanceAttributeList, "Get_Instance_Attribute_List",
        [this](CipInstance& i, const CipServiceRequest& r) { return handle_get_instance_attribute_list(i, r); }});
}

std::unique_ptr<cip::CipClass> SymbolObject::release_cip_class() {
    return std::move(cip_class_);
}

void SymbolObject::ensure_instance(Tag& tag) {
    if (cip_class_view_->get_instance(tag.instance_id()) != nullptr) return;
    auto& inst = cip_class_view_->create_instance(tag.instance_id());
    inst.set_user_data(&tag);

    // Attribute 1: Symbol Name (STRING — UINT length + ASCII chars)
    std::vector<uint8_t> name_data(2u + tag.name().size());
    ser::write_uint(name_data, static_cast<uint16_t>(tag.name().size()));
    std::memcpy(name_data.data() + 2, tag.name().data(), tag.name().size());
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{1}, CipDataType::String,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        std::move(name_data)));

    // Attribute 2: Symbol Type (WORD)
    inst.add_attribute(CipAttribute::create_uint(
        2, CipDataType::Word,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, tag.symbol_type()));
}

Tag* SymbolObject::tag_from_instance(CipInstance& inst) {
    if (auto* t = static_cast<Tag*>(inst.user_data())) return t;
    return tags_.find_by_instance_id(inst.instance_id());
}

CipServiceResponse SymbolObject::handle_instance_read_tag(CipInstance& inst, const CipServiceRequest& req) {
    auto* tag = tag_from_instance(inst);
    if (tag == nullptr) return CipServiceResponse::error(req.service_code, CipStatus::error(0x05));
    int elem = static_cast<int>(req.path.element_id.value_or(0));
    return tag_services::handle_read_tag(*tag, req.service_code, req.data, elem);
}

CipServiceResponse SymbolObject::handle_instance_write_tag(CipInstance& inst, const CipServiceRequest& req) {
    auto* tag = tag_from_instance(inst);
    if (tag == nullptr) return CipServiceResponse::error(req.service_code, CipStatus::error(0x05));
    int elem = static_cast<int>(req.path.element_id.value_or(0));
    return tag_services::handle_write_tag(*tag, req.service_code, req.data, elem);
}

CipServiceResponse SymbolObject::handle_instance_read_tag_fragmented(CipInstance& inst, const CipServiceRequest& req) {
    auto* tag = tag_from_instance(inst);
    if (tag == nullptr) return CipServiceResponse::error(req.service_code, CipStatus::error(0x05));
    return tag_services::handle_read_tag_fragmented(*tag, req.service_code, req.data);
}

CipServiceResponse SymbolObject::handle_instance_write_tag_fragmented(CipInstance& inst, const CipServiceRequest& req) {
    auto* tag = tag_from_instance(inst);
    if (tag == nullptr) return CipServiceResponse::error(req.service_code, CipStatus::error(0x05));
    return tag_services::handle_write_tag_fragmented(*tag, req.service_code, req.data);
}

CipServiceResponse SymbolObject::handle_instance_read_modify_write(CipInstance& inst, const CipServiceRequest& req) {
    auto* tag = tag_from_instance(inst);
    if (tag == nullptr) return CipServiceResponse::error(req.service_code, CipStatus::error(0x05));
    return tag_services::handle_read_modify_write(*tag, req.service_code, req.data);
}

// Class-level Get_Instance_Attribute_List (0x55) — paginated tag enumeration.
CipServiceResponse SymbolObject::handle_get_instance_attribute_list(
        CipInstance& /*class_instance*/, const CipServiceRequest& req) {
    if (req.data.size() < 2) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0x13));
    }
    uint16_t attr_count = ser::read_uint(req.data);
    if (req.data.size() < static_cast<size_t>(2 + attr_count * 2)) {
        return CipServiceResponse::error(req.service_code, CipStatus::error(0x13));
    }
    std::vector<uint16_t> requested(attr_count);
    for (uint16_t i = 0; i < attr_count; ++i) {
        requested[i] = ser::read_uint(req.data.subspan(2u + i * 2u));
    }

    uint32_t start_instance = req.path.instance_id.value_or(0);

    // All tags with instance ID > start, sorted ascending.
    auto tags = tags_.all_tags();
    tags.erase(std::remove_if(tags.begin(), tags.end(),
        [start_instance](Tag* t) { return t->instance_id() <= start_instance; }),
        tags.end());
    std::sort(tags.begin(), tags.end(),
        [](Tag* a, Tag* b) { return a->instance_id() < b->instance_id(); });

    for (Tag* t : tags) ensure_instance(*t);

    constexpr int max_response = 480;
    std::vector<uint8_t> buf(4096);
    int offset = 0;
    int tags_packed = 0;
    bool truncated = false;

    for (Tag* tag : tags) {
        int entry_start = offset;
        // Instance ID (UDINT)
        if (offset + 4 > max_response && tags_packed > 0) { truncated = true; break; }
        ser::write_udint(std::span<uint8_t>(buf).subspan(offset), tag->instance_id());
        offset += 4;

        bool rolled_back = false;
        for (uint16_t attr_id : requested) {
            // Compute the bytes this attribute will contribute.
            int entry = 0;
            switch (attr_id) {
                case 1: entry = 2 + static_cast<int>(tag->name().size()); break;
                case 2: entry = 2; break;                              // Symbol Type (UINT)
                case 3: case 5: case 6: entry = 4; break;             // Symbol/Object Address, Software Control (UDINT)
                case 8: entry = 12; break;                            // Array Dimensions (3x UDINT)
                case 10: entry = 1; break;                            // External Access (USINT)
                default: entry = 0; break;
            }
            if (entry > 0 && offset + entry > max_response && tags_packed > 0) {
                offset = entry_start; truncated = true; rolled_back = true; break;
            }
            switch (attr_id) {
                case 1: {  // Symbol Name (STRING — UINT length + chars)
                    ser::write_uint(std::span<uint8_t>(buf).subspan(offset),
                                     static_cast<uint16_t>(tag->name().size()));
                    offset += 2;
                    std::memcpy(buf.data() + offset, tag->name().data(), tag->name().size());
                    offset += static_cast<int>(tag->name().size());
                    break;
                }
                case 2:  // Symbol Type (UINT)
                    ser::write_uint(std::span<uint8_t>(buf).subspan(offset), tag->symbol_type());
                    offset += 2;
                    break;
                case 3:  // Symbol Address (UDINT) — not tracked; report 0
                case 5:  // Symbol Object Address (UDINT)
                case 6:  // Software Control (UDINT)
                    ser::write_udint(std::span<uint8_t>(buf).subspan(offset), 0u);
                    offset += 4;
                    break;
                case 8: {  // Array Dimensions — 3x UDINT. Tags here are at most 1-D.
                    uint32_t d1 = tag->element_count() > 1 ? static_cast<uint32_t>(tag->element_count()) : 0u;
                    ser::write_udint(std::span<uint8_t>(buf).subspan(offset),     d1);
                    ser::write_udint(std::span<uint8_t>(buf).subspan(offset + 4), 0u);
                    ser::write_udint(std::span<uint8_t>(buf).subspan(offset + 8), 0u);
                    offset += 12;
                    break;
                }
                case 10:  // External Access (USINT). 3 = Read/Write.
                    buf[offset++] = 0x03;
                    break;
                default:
                    break;
            }
        }
        if (rolled_back) break;
        ++tags_packed;
    }

    bool more_data = truncated && tags_packed < static_cast<int>(tags.size());
    buf.resize(offset);
    if (more_data) {
        return CipServiceResponse{
            static_cast<uint8_t>(req.service_code | 0x80),
            CipStatus::error(0x06),
            std::move(buf),
        };
    }
    return CipServiceResponse::success(req.service_code, std::move(buf));
}

} // namespace ethernetip::logix
