#pragma once

#include "ethernetip/logix/tag_client.hpp"

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ethernetip::logix {

/// Typed view over a structure tag's bytes. Bound to a TemplateInfo for
/// member offsets / types. Construct empty to fill in for writes, or pass
/// raw bytes (from TagClient::read_struct) for reads.
class StructureValue {
public:
    /// Empty buffer sized to the template's structure_size, for building a write.
    explicit StructureValue(const TemplateInfo& tmpl)
        : template_(tmpl), data_(tmpl.structure_size) {}

    /// Wrap existing structure bytes (typically from TagClient::read_struct).
    StructureValue(const TemplateInfo& tmpl, std::vector<uint8_t> raw)
        : template_(tmpl), data_(std::move(raw)) {}

    [[nodiscard]] const TemplateInfo&        template_info() const noexcept { return template_; }
    [[nodiscard]] const std::vector<uint8_t>& raw_data()      const noexcept { return data_; }
    [[nodiscard]] std::vector<uint8_t>&       raw_data()             noexcept { return data_; }

    [[nodiscard]] const TemplateMemberDetail* find_member(std::string_view name) const noexcept {
        for (const auto& m : template_.members) {
            if (m.name.size() == name.size()
                && std::equal(m.name.begin(), m.name.end(), name.begin(),
                                 [](char a, char b) {
                                     return (a | 0x20) == (b | 0x20);
                                 })) {
                return &m;
            }
        }
        return nullptr;
    }

    /// Read a trivially-copyable scalar member. Throws on missing / out-of-range.
    template <class T>
    [[nodiscard]] T get(std::string_view member) const {
        static_assert(std::is_trivially_copyable_v<T>);
        auto* m = require(member);
        if (m->offset + sizeof(T) > data_.size()) {
            throw std::runtime_error(std::string("StructureValue::get: '") + std::string(member)
                + "' offset " + std::to_string(m->offset) + " exceeds buffer");
        }
        T out{};
        std::memcpy(&out, data_.data() + m->offset, sizeof(T));
        return out;
    }

    /// Write a trivially-copyable scalar member.
    template <class T>
    void set(std::string_view member, T value) {
        static_assert(std::is_trivially_copyable_v<T>);
        auto* m = require(member);
        if (m->offset + sizeof(T) > data_.size()) {
            throw std::runtime_error(std::string("StructureValue::set: '") + std::string(member)
                + "' offset " + std::to_string(m->offset) + " exceeds buffer");
        }
        std::memcpy(data_.data() + m->offset, &value, sizeof(T));
    }

    /// Read a BOOL member (bit within a host SINT byte).
    [[nodiscard]] bool get_bool(std::string_view member) const {
        auto* m = require(member);
        if (m->data_type != logix_data_types::Bool) {
            throw std::runtime_error(std::string("StructureValue::get_bool: '") + std::string(member)
                + "' is not BOOL");
        }
        if (m->offset >= data_.size()) return false;
        return (data_[m->offset] & (1u << (m->info & 0x07))) != 0;
    }

    /// Write a BOOL member (set/clear bit within a host SINT byte).
    void set_bool(std::string_view member, bool value) {
        auto* m = require(member);
        if (m->data_type != logix_data_types::Bool) {
            throw std::runtime_error(std::string("StructureValue::set_bool: '") + std::string(member)
                + "' is not BOOL");
        }
        if (m->offset >= data_.size()) {
            throw std::runtime_error("StructureValue::set_bool: offset out of range");
        }
        uint8_t mask = static_cast<uint8_t>(1u << (m->info & 0x07));
        if (value) data_[m->offset] |= mask;
        else       data_[m->offset] = static_cast<uint8_t>(data_[m->offset] & ~mask);
    }

    /// Read a nested Logix STRING member (88-byte UDT: LEN + DATA + pad).
    [[nodiscard]] std::string get_string(std::string_view member) const {
        auto* m = require(member);
        size_t off = m->offset;
        if (off + logix_data_types::StringDataOffset >= data_.size()) return "";
        int32_t len = 0;
        std::memcpy(&len, data_.data() + off + logix_data_types::StringLenOffset, 4);
        if (len <= 0) return "";
        int max_len = std::min<int>(len,
            std::min<int>(logix_data_types::StringMaxLength,
                           static_cast<int>(data_.size() - off - logix_data_types::StringDataOffset)));
        return std::string(reinterpret_cast<const char*>(data_.data() + off + logix_data_types::StringDataOffset),
                             max_len);
    }

    /// Write a nested Logix STRING member.
    void set_string(std::string_view member, std::string_view value) {
        auto* m = require(member);
        size_t off = m->offset;
        if (off + logix_data_types::StringStructureSize > data_.size()) {
            throw std::runtime_error("StructureValue::set_string: structure buffer too small");
        }
        int len = std::min<int>(static_cast<int>(value.size()),
                                  logix_data_types::StringMaxLength);
        int32_t len32 = len;
        std::memcpy(data_.data() + off + logix_data_types::StringLenOffset, &len32, 4);
        // Zero the DATA region then copy chars.
        std::memset(data_.data() + off + logix_data_types::StringDataOffset, 0,
                     logix_data_types::StringMaxLength);
        if (len > 0) {
            std::memcpy(data_.data() + off + logix_data_types::StringDataOffset, value.data(), len);
        }
    }

private:
    [[nodiscard]] const TemplateMemberDetail* require(std::string_view name) const {
        auto* m = find_member(name);
        if (m == nullptr) {
            throw std::runtime_error(std::string("StructureValue: member '") + std::string(name)
                + "' not found in template '" + template_.name + "'");
        }
        return m;
    }

    const TemplateInfo&  template_;
    std::vector<uint8_t> data_;
};

} // namespace ethernetip::logix
