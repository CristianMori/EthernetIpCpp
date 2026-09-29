#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace ethernetip::logix {

class TemplateDefinition;

/// Region of a tag's data that was modified.
struct TagChangeInfo {
    int byte_offset = 0;
    int byte_length = 0;
};

/// A single Logix controller tag — owns a byte buffer + change notifications.
///
/// <b>Concurrency model</b> (mirrors the C# reference): tag memory is a plain
/// byte buffer with no snapshot boundary.  Scalar reads and writes on
/// naturally aligned offsets are effectively atomic on x86/x64; multi-scalar
/// and struct reads MAY tear if a scan-side writer races a CIP-side reader.
/// That matches how a real 1756 behaves, and clients that need atomic
/// multi-member reads coordinate via an application-level flag rather than
/// expecting the controller to snapshot.  Do NOT wrap the read/write path in
/// a lock — the transpiler-generated scan writes 10⁵–10⁶ times per scan.
///
/// The one place synchronization IS worth the cost is BOOL bit RMW on a host
/// byte shared by multiple BOOL members; use atomic_set_bit for those writes.
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
          data_(static_cast<size_t>(element_size) * element_count) {
        if (element_count > 1) dims_.push_back(static_cast<uint32_t>(element_count));
    }

    /// Multi-dimensional ctor — takes explicit dims (0..3 entries) and
    /// optional data_size override for BOOL[]-style DWORD-packed storage.
    Tag(uint32_t instance_id, std::string name, uint16_t symbol_type,
        uint16_t tag_type, int element_size, std::vector<uint32_t> dims,
        std::optional<int> data_size = std::nullopt)
        : instance_id_(instance_id),
          name_(std::move(name)),
          symbol_type_(symbol_type),
          tag_type_(tag_type),
          element_size_(element_size),
          dims_(std::move(dims)) {
        int total = 1;
        for (auto d : dims_) total *= static_cast<int>(d);
        element_count_ = dims_.empty() ? 1 : total;
        int size = data_size.value_or(element_size_ * element_count_);
        data_.resize(static_cast<size_t>(size));
    }

    [[nodiscard]] uint32_t           instance_id()   const noexcept { return instance_id_; }
    [[nodiscard]] const std::string& name()          const noexcept { return name_; }
    [[nodiscard]] uint16_t           symbol_type()   const noexcept { return symbol_type_; }
    [[nodiscard]] uint16_t           tag_type()      const noexcept { return tag_type_; }
    [[nodiscard]] int                element_count() const noexcept { return element_count_; }
    [[nodiscard]] int                element_size()  const noexcept { return element_size_; }
    [[nodiscard]] int                data_size()     const noexcept { return static_cast<int>(data_.size()); }

    /// Array dimension sizes (empty for scalars, one entry for a 1-D array,
    /// up to three entries for a Logix multi-dim array). Symbol Object
    /// attribute 8 emits these three UDINTs (0-padded).
    [[nodiscard]] const std::vector<uint32_t>& dims() const noexcept { return dims_; }

    /// Backing template for struct-typed tags (null for atomics). Populated
    /// by TagDatabase when the tag is added.
    [[nodiscard]] const TemplateDefinition* tag_template() const noexcept { return template_; }
    void set_template(const TemplateDefinition* t) noexcept { template_ = t; }

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

    /// Silent write: same as write<T> minus the value_changed handler
    /// invocation. Gap 8 — the transpiler-generated scan writes 10⁵–10⁶
    /// times per scan and has no consumer for per-write events.
    template <class T>
    void write_silent(int byte_offset, T value) {
        static_assert(std::is_trivially_copyable_v<T>);
        std::memcpy(data_.data() + byte_offset, &value, sizeof(T));
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

    /// Silent bulk write. See write_silent.
    void set_data_silent(std::span<const uint8_t> source, int byte_offset = 0) {
        int len = static_cast<int>(source.size());
        int max = static_cast<int>(data_.size()) - byte_offset;
        if (len > max) len = max;
        if (len > 0) {
            std::memcpy(data_.data() + byte_offset, source.data(),
                        static_cast<size_t>(len));
        }
    }

    /// Atomically set or clear a single bit inside the tag's buffer. Uses
    /// std::atomic_ref<uint32_t> on the containing 4-byte word so two
    /// writers to different bits of the same host byte can't stomp each
    /// other. Fires value_changed with the 1-byte host range.
    void atomic_set_bit(int byte_offset, int bit_pos, bool value) {
        if (bit_pos < 0 || bit_pos > 7) return;
        if (byte_offset < 0 || byte_offset >= static_cast<int>(data_.size())) return;
        int word_off = byte_offset & ~3;
        int bit_in_word = ((byte_offset - word_off) * 8) + bit_pos;
        uint32_t mask = 1u << bit_in_word;
        if (word_off + 4 <= static_cast<int>(data_.size())) {
            std::atomic_ref<uint32_t> word(*reinterpret_cast<uint32_t*>(data_.data() + word_off));
            if (value) word.fetch_or(mask, std::memory_order_relaxed);
            else word.fetch_and(~mask, std::memory_order_relaxed);
        } else {
            uint8_t m = static_cast<uint8_t>(1u << bit_pos);
            if (value) data_[byte_offset] = static_cast<uint8_t>(data_[byte_offset] | m);
            else data_[byte_offset] = static_cast<uint8_t>(data_[byte_offset] & ~m);
        }
        fire_changed({byte_offset, 1});
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
    std::vector<uint32_t> dims_;
    const TemplateDefinition* template_ = nullptr;
    std::vector<uint8_t> data_;
    std::vector<ValueChangedHandler> handlers_;
};

} // namespace ethernetip::logix
