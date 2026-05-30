#include "ethernetip/cip/cpf.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <cstring>
#include <stdexcept>

namespace ethernetip::cip::cpf {

std::vector<CpfItem> parse(std::span<const uint8_t> data) {
    if (data.size() < 2) {
        return {};
    }
    uint16_t item_count = serializer::read_uint(data);
    std::vector<CpfItem> items;
    items.reserve(item_count);

    size_t offset = 2;
    for (uint16_t i = 0; i < item_count; ++i) {
        if (offset + 4 > data.size()) {
            break;
        }
        auto type_id = static_cast<CpfItemType>(serializer::read_uint(data.subspan(offset)));
        uint16_t length = serializer::read_uint(data.subspan(offset + 2));
        offset += 4;
        if (offset + length > data.size()) {
            break;
        }
        items.emplace_back(type_id, data.subspan(offset, length));
        offset += length;
    }
    return items;
}

size_t size_for(std::span<const CpfItem> items) {
    size_t required = 2;
    for (const auto& item : items) {
        required += 4 + item.data.size();
    }
    return required;
}

int write(std::span<uint8_t> dst, std::span<const CpfItem> items) {
    size_t required = size_for(items);
    if (dst.size() < required) {
        throw std::invalid_argument("CPF write: destination buffer too small");
    }

    size_t offset = 0;
    serializer::write_uint(dst, static_cast<uint16_t>(items.size()));
    offset += 2;

    for (const auto& item : items) {
        serializer::write_uint(dst.subspan(offset), static_cast<uint16_t>(item.type_id));
        serializer::write_uint(dst.subspan(offset + 2), static_cast<uint16_t>(item.data.size()));
        offset += 4;
        if (!item.data.empty()) {
            std::memcpy(dst.data() + offset, item.data.data(), item.data.size());
            offset += item.data.size();
        }
    }
    return static_cast<int>(offset);
}

} // namespace ethernetip::cip::cpf
