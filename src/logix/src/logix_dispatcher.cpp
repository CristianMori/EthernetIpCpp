#include "ethernetip/logix/logix_dispatcher.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/logix/multi_service_handler.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace ethernetip::logix {

using cip::CipAttribute;
using cip::CipClass;
using cip::CipDataType;
using cip::CipInstance;
using cip::CipPath;
using cip::CipServiceDefinition;
using cip::CipServiceRequest;
using cip::CipServiceResponse;
using cip::CipStatus;
using cip::AttributeAccess;

namespace {
std::string to_lower(std::string_view s) {
    std::string out(s.size(), '\0');
    std::transform(s.begin(), s.end(), out.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}
} // namespace

LogixDispatcher::LogixDispatcher()
    : LogixDispatcher(std::make_shared<TagDatabase>(), std::nullopt) {}

LogixDispatcher::LogixDispatcher(std::shared_ptr<TagDatabase> tags)
    : LogixDispatcher(std::move(tags), std::nullopt) {}

LogixDispatcher::LogixDispatcher(std::shared_ptr<TagDatabase> tags,
                                  std::optional<cip::IdentityInfo> identity)
    : tags_(std::move(tags)) {
    symbol_object_   = std::make_unique<SymbolObject>(*tags_);
    template_object_ = std::make_unique<TemplateObject>(*tags_);
    symbol_view_     = symbol_object_.get();
    template_view_   = template_object_.get();

    register_class(symbol_object_->release_cip_class());
    register_class(template_object_->release_cip_class());

    // Message Router (0x02) with Multiple_Service_Packet.
    auto msg_router = std::make_unique<CipClass>(0x02u, "Message Router", uint16_t{1});
    msg_router->add_standard_instance_services();
    msg_router->create_instance(1);
    msg_router->add_instance_service(CipServiceDefinition{
        multi_service_handler::ServiceCode, "Multiple_Service_Packet",
        [this](CipInstance&, const CipServiceRequest& r) {
            return multi_service_handler::handle(*this, r);
        }});
    register_class(std::move(msg_router));

    // Connection Manager — its handler lambdas capture [this] referring to
    // ConnectionManagerObject, so we MUST keep the object alive after handing
    // its CipClass to the dispatcher.
    connection_manager_ = std::make_unique<connections::ConnectionManagerObject>();
    connection_manager_->dispatch_request =
        [this](uint8_t svc, const CipPath& path, std::span<const uint8_t> d) {
            return this->dispatch(svc, path, d);
        };
    register_class(connection_manager_->release_cip_class());

    if (identity.has_value()) {
        const auto& id = *identity;
        auto id_class = std::make_unique<CipClass>(cip::IdentityInfo::ClassCode,
                                                     "Identity", uint16_t{1});
        id_class->add_standard_instance_services();
        auto& id_inst = id_class->create_instance(1);
        id_inst.add_attribute(CipAttribute::create_uint(
            1, CipDataType::Uint,
            AttributeAccess::GetSingle | AttributeAccess::GetAll, id.vendor_id));
        id_inst.add_attribute(CipAttribute::create_uint(
            2, CipDataType::Uint,
            AttributeAccess::GetSingle | AttributeAccess::GetAll, id.device_type));
        id_inst.add_attribute(CipAttribute::create_uint(
            3, CipDataType::Uint,
            AttributeAccess::GetSingle | AttributeAccess::GetAll, id.product_code));
        id_inst.add_attribute(std::make_unique<CipAttribute>(
            uint16_t{4}, CipDataType::Usint,
            AttributeAccess::GetSingle | AttributeAccess::GetAll,
            std::vector<uint8_t>{id.major_revision, id.minor_revision}));
        id_inst.add_attribute(CipAttribute::create_uint(
            5, CipDataType::Word,
            AttributeAccess::GetSingle | AttributeAccess::GetAll, id.status));
        id_inst.add_attribute(CipAttribute::create_udint(
            6, CipDataType::Udint,
            AttributeAccess::GetSingle | AttributeAccess::GetAll, id.serial_number));
        id_inst.add_attribute(CipAttribute::create_short_string(
            7, AttributeAccess::GetSingle | AttributeAccess::GetAll, id.product_name));
        register_class(std::move(id_class));

        // Program Name object (Class 0x64, Rockwell KB 23341). pycomm3
        // queries this via GetAttributesAll during connect to get
        // LogixDriver.info["name"]. Attribute 1 = controller program name
        // as CIP STRING (2-byte UINT length + ASCII chars).
        auto pn_class = std::make_unique<CipClass>(0x64u, "Program Name", uint16_t{1});
        pn_class->add_standard_instance_services();
        auto& pn_inst = pn_class->create_instance(1);
        const std::string& pn = id.product_name;
        std::vector<uint8_t> pn_data(2u + pn.size());
        pn_data[0] = static_cast<uint8_t>(pn.size() & 0xFF);
        pn_data[1] = static_cast<uint8_t>((pn.size() >> 8) & 0xFF);
        std::memcpy(pn_data.data() + 2, pn.data(), pn.size());
        pn_inst.add_attribute(std::make_unique<CipAttribute>(
            uint16_t{1}, CipDataType::String,
            AttributeAccess::GetSingle | AttributeAccess::GetAll,
            std::move(pn_data)));
        register_class(std::move(pn_class));
    }

    tags_->add_tag_added_handler([this](Tag& tag) {
        symbol_view_->ensure_instance(tag);
        std::scoped_lock lock(symbol_cache_mu_);
        symbol_cache_[to_lower(tag.name())] = &tag;
    });
    tags_->add_template_added_handler([this](const TemplateDefinition& t) {
        template_view_->ensure_instance(t);
    });

    sync_cip_instances();
}

void LogixDispatcher::sync_cip_instances() {
    for (Tag* tag : tags_->all_tags()) {
        symbol_view_->ensure_instance(*tag);
        std::scoped_lock lock(symbol_cache_mu_);
        symbol_cache_[to_lower(tag->name())] = tag;
    }
    for (const TemplateDefinition* t : tags_->all_templates()) {
        template_view_->ensure_instance(*t);
    }
}

CipServiceResponse LogixDispatcher::on_unhandled(uint8_t service_code,
                                                   const CipPath& path,
                                                   std::span<const uint8_t> data,
                                                   uint8_t default_status) {
    if (path.symbolic_name.has_value()) {
        std::string key = to_lower(*path.symbolic_name);
        Tag* tag = nullptr;
        {
            std::scoped_lock lock(symbol_cache_mu_);
            auto it = symbol_cache_.find(key);
            if (it != symbol_cache_.end()) tag = it->second;
        }
        if (tag == nullptr) {
            tag = tags_->find_by_name(*path.symbolic_name);
            if (tag == nullptr) {
                return CipServiceResponse::error(service_code, CipStatus::error(0x05));
            }
            std::scoped_lock lock(symbol_cache_mu_);
            symbol_cache_[std::move(key)] = tag;
        }
        int elem = static_cast<int>(path.element_id.value_or(0));
        return dispatch_tag_service(*tag, service_code, data, elem);
    }
    return cip::CipDispatcher::on_unhandled(service_code, path, data, default_status);
}

CipServiceResponse LogixDispatcher::dispatch_tag_service(Tag& tag, uint8_t service_code,
                                                           std::span<const uint8_t> data,
                                                           int element_offset) {
    switch (service_code) {
        case tag_services::ReadTag:            return tag_services::handle_read_tag(tag, service_code, data, element_offset);
        case tag_services::WriteTag:           return tag_services::handle_write_tag(tag, service_code, data, element_offset);
        case tag_services::ReadTagFragmented:  return tag_services::handle_read_tag_fragmented(tag, service_code, data);
        case tag_services::WriteTagFragmented: return tag_services::handle_write_tag_fragmented(tag, service_code, data);
        case tag_services::ReadModifyWrite:    return tag_services::handle_read_modify_write(tag, service_code, data);
        default:                                return CipServiceResponse::error(service_code,
                                                          CipStatus::error(CipStatus::ServiceNotSupported));
    }
}

} // namespace ethernetip::logix
