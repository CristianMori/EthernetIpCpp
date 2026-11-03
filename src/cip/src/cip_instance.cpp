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
    size_t offset = 0;
    for (CipAttribute* attr : get_all_cache_) {
        // CipAttribute::encode_to does an unchecked memcpy of data_length()
        // bytes into dst.data(). Current configurations stay well under the
        // caller's 4 KB buffer, but a future large attribute (e.g. an array
        // of structures) must not silently overrun. Match the pattern from
        // a478c61 / 8fe2921 and stop at the buffer boundary. Callers of
        // Get_Attribute_All already resize their buffer to the returned
        // length, so a short write surfaces as a truncated response rather
        // than a heap overflow.
        if (offset + attr->data_length() > dst.size()) break;
        offset += static_cast<size_t>(attr->encode_to(dst.subspan(offset)));
    }
    return static_cast<int>(offset);
}

} // namespace ethernetip::cip
