#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace ethernetip::logix {

/// Region of a tag's data that was modified.
struct TagChangeInfo {
    int byte_offset = 0;
    int byte_length = 0;
};

/// A single Logix controller tag — owns a byte buffer + change notifications.
/// One Tag corresponds to one instance of the Symbol Object (class 0x6B).
class Tag {
public:
    using ValueChangedHandler = std::function<void(const Tag&, TagChangeInfo)>;

    Tag(uint32_t instance_id, std::string name, uint16_t symbol_type,
        uint16_t tag_type, int element_size, int element_count = 1)
        : instance_id_(instance_id),
          name_(std::move(name)),
          symbol_type_(symbol_type),
          tag_type_(tag_type),
          element_size_(element_size),
          element_count_(element_count),
          data_(static_cast<size_t>(element_size) * element_count) {}

    [[nodiscard]] uint32_t           instance_id()   const noexcept { return instance_id_; }
    [[nodiscard]] const std::string& name()          const noexcept { return name_; }
    /// SymbolType attribute (attr 2 of Symbol Object).
    /// Bit 15: 1=struct, 0=atomic. Bits 14-13: array dims. Bit 12: system.
    /// Bits 0-11: CIP type code (atomic) or template instance ID (struct).
    [[nodiscard]] uint16_t           symbol_type()   const noexcept { return symbol_type_; }
    /// Tag type parameter for Read/Write Tag services. Atomic: CIP type code.
    /// Struct: structure handle from Template attr 1.
    [[nodiscard]] uint16_t           tag_type()      const noexcept { return tag_type_; }
    [[nodiscard]] int                element_count() const noexcept { return element_count_; }
    [[nodiscard]] int                element_size()  const noexcept { return element_size_; }
    [[nodiscard]] int                data_size()     const noexcept { return static_cast<int>(data_.size()); }

    [[nodiscard]] std::span<const uint8_t> get_data() const noexcept { return data_; }
    [[nodiscard]] std::span<const uint8_t> get_data(int byte_offset, int length) const {
        return std::span<const uint8_t>(data_).subspan(byte_offset, length);
    }

    template <class T>
    [[nodiscard]] T read(int byte_offset = 0) const {
        static_assert(std::is_trivially_copyable_v<T>);
        T out{};
        std::memcpy(&out, data_.data() + byte_offset, sizeof(T));
        return out;
    }

    template <class T>
    void write(int byte_offset, T value) {
        static_assert(std::is_trivially_copyable_v<T>);
        std::memcpy(data_.data() + byte_offset, &value, sizeof(T));
        fire_changed({byte_offset, static_cast<int>(sizeof(T))});
    }

    /// Bulk write into the tag's data buffer. Fires value_changed once.
    void set_data(std::span<const uint8_t> source, int byte_offset = 0) {
        int len = static_cast<int>(source.size());
        int max = static_cast<int>(data_.size()) - byte_offset;
        if (len > max) len = max;
        if (len > 0) {
            std::memcpy(data_.data() + byte_offset, source.data(),
                        static_cast<size_t>(len));
        }
        fire_changed({byte_offset, len});
    }

    /// Subscribe to writes. WARNING: fires on whichever thread wrote.
    void add_value_changed_handler(ValueChangedHandler h) {
        handlers_.push_back(std::move(h));
    }

private:
    void fire_changed(TagChangeInfo info) {
        for (auto& h : handlers_) h(*this, info);
    }

    uint32_t    instance_id_;
    std::string name_;
    uint16_t    symbol_type_;
    uint16_t    tag_type_;
    int         element_size_;
    int         element_count_;
    std::vector<uint8_t> data_;
    std::vector<ValueChangedHandler> handlers_;
};

} // namespace ethernetip::logix
