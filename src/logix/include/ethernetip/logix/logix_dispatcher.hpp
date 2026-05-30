#pragma once

#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/connections/connection_manager.hpp"
#include "ethernetip/logix/symbol_object.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/template_object.hpp"

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace ethernetip::logix {

/// CipDispatcher subclass that models a Logix 5000 controller. Handles
/// symbolic-segment addressing by overriding on_unhandled(). Registers
/// Symbol (0x6B), Template (0x6C), Message Router (0x02, with
/// Multiple_Service_Packet), Connection Manager (0x06), and Identity (0x01).
class LogixDispatcher : public cip::CipDispatcher {
public:
    LogixDispatcher();
    explicit LogixDispatcher(std::shared_ptr<TagDatabase> tags);
    LogixDispatcher(std::shared_ptr<TagDatabase> tags,
                    std::optional<cip::IdentityInfo> identity);

    [[nodiscard]] TagDatabase&       tags() noexcept { return *tags_; }
    [[nodiscard]] const TagDatabase& tags() const noexcept { return *tags_; }

    /// Ensure CIP instances exist for all tags / templates currently in the DB.
    void sync_cip_instances();

protected:
    cip::CipServiceResponse on_unhandled(uint8_t service_code,
                                           const cip::CipPath& path,
                                           std::span<const uint8_t> data,
                                           uint8_t default_status = cip::CipStatus::PathDestinationUnknown) override;

private:
    static cip::CipServiceResponse dispatch_tag_service(Tag& tag, uint8_t service_code,
                                                         std::span<const uint8_t> data,
                                                         int element_offset);

    std::shared_ptr<TagDatabase>     tags_;
    std::unique_ptr<SymbolObject>    symbol_object_;
    std::unique_ptr<TemplateObject>  template_object_;
    std::unique_ptr<connections::ConnectionManagerObject> connection_manager_;
    SymbolObject*   symbol_view_   = nullptr;   ///< survives release_cip_class()
    TemplateObject* template_view_ = nullptr;

    // Symbolic-name → Tag cache for fast OnUnhandled lookup.
    std::mutex symbol_cache_mu_;
    std::unordered_map<std::string, Tag*> symbol_cache_;
};

} // namespace ethernetip::logix
