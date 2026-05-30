#pragma once

#include "ethernetip/cip/data_serializer.hpp"

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace ethernetip::protocol::cpf_helpers {

/// Light builder that accumulates a CPF item list and produces wire bytes
/// in a single allocation. Used by EipAdapter to build response CPFs without
/// instantiating CpfItem objects for every reply.
class CpfBuilder {
public:
    void add_item(uint16_t type_id, std::span<const uint8_t> data) {
        items_.push_back({type_id, std::vector<uint8_t>(data.begin(), data.end())});
    }

    [[nodiscard]] std::vector<uint8_t> build() const {
        size_t total = 2;
        for (const auto& [_, d] : items_) total += 4 + d.size();
        std::vector<uint8_t> buf(total);
        namespace ser = ethernetip::cip::serializer;
        size_t off = 0;
        ser::write_uint(buf, static_cast<uint16_t>(items_.size())); off += 2;
        for (const auto& [type_id, d] : items_) {
            ser::write_uint(std::span<uint8_t>(buf).subspan(off), type_id);              off += 2;
            ser::write_uint(std::span<uint8_t>(buf).subspan(off),
                             static_cast<uint16_t>(d.size()));                                off += 2;
            if (!d.empty()) {
                std::memcpy(buf.data() + off, d.data(), d.size());
                off += d.size();
            }
        }
        return buf;
    }

private:
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> items_;
};

} // namespace ethernetip::protocol::cpf_helpers
