#include "ethernetip/cip/cip_instance.hpp"

#include <algorithm>

namespace ethernetip::cip {

void CipInstance::add_attribute(std::unique_ptr<CipAttribute> attr) {
    uint16_t id = attr->id();
    attributes_[id] = std::move(attr);
    get_all_cache_valid_ = false;
}

CipAttribute* CipInstance::get_attribute(uint16_t id) const {
    auto it = attributes_.find(id);
    return it == attributes_.end() ? nullptr : it->second.get();
}

void CipInstance::rebuild_get_all_cache() const {
    get_all_cache_.clear();
    for (const auto& [_, attr] : attributes_) {
        if (has_flag(attr->access(), AttributeAccess::GetAll)) {
            get_all_cache_.push_back(attr.get());
        }
    }
    std::sort(get_all_cache_.begin(), get_all_cache_.end(),
              [](const CipAttribute* a, const CipAttribute* b) {
                  return a->id() < b->id();
              });
    get_all_cache_valid_ = true;
}

int CipInstance::encode_all_attributes(std::span<uint8_t> dst) {
    if (!get_all_cache_valid_) {
        rebuild_get_all_cache();
    }
    int offset = 0;
    for (CipAttribute* attr : get_all_cache_) {
        offset += attr->encode_to(dst.subspan(offset));
    }
    return offset;
}

} // namespace ethernetip::cip
