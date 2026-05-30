#include "ethernetip/cip/cip_attribute.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <cstring>

namespace ethernetip::cip {

void CipAttribute::set_data(std::span<const uint8_t> value) {
    if (value.size() != data_.size()) {
        data_.assign(value.begin(), value.end());
        return;
    }
    if (!value.empty()) {
        std::memcpy(data_.data(), value.data(), value.size());
    }
}

int CipAttribute::encode_to(std::span<uint8_t> dst) const {
    if (!data_.empty()) {
        std::memcpy(dst.data(), data_.data(), data_.size());
    }
    return static_cast<int>(data_.size());
}

std::unique_ptr<CipAttribute>
CipAttribute::create_byte(uint16_t id, CipDataType type, AttributeAccess access, uint8_t value) {
    return std::make_unique<CipAttribute>(id, type, access, std::vector<uint8_t>{value});
}

std::unique_ptr<CipAttribute>
CipAttribute::create_uint(uint16_t id, CipDataType type, AttributeAccess access, uint16_t value) {
    std::vector<uint8_t> buf(2);
    serializer::write_uint(buf, value);
    return std::make_unique<CipAttribute>(id, type, access, std::move(buf));
}

std::unique_ptr<CipAttribute>
CipAttribute::create_udint(uint16_t id, CipDataType type, AttributeAccess access, uint32_t value) {
    std::vector<uint8_t> buf(4);
    serializer::write_udint(buf, value);
    return std::make_unique<CipAttribute>(id, type, access, std::move(buf));
}

std::unique_ptr<CipAttribute>
CipAttribute::create_short_string(uint16_t id, AttributeAccess access, std::string_view value) {
    std::vector<uint8_t> buf(1 + value.size());
    serializer::write_short_string(buf, value);
    return std::make_unique<CipAttribute>(id, CipDataType::ShortString, access, std::move(buf));
}

} // namespace ethernetip::cip
