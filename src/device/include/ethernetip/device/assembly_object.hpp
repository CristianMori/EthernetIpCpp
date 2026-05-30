#pragma once

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/cip_class.hpp"

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace ethernetip::device {

/// An assembly instance — owns a byte buffer for I/O data. Writes are
/// serialized by an internal lock; reads against a stable snapshot can be
/// done concurrently via `copy_data_to`. Fires `on_data_changed` after every
/// write (on whichever thread did the write).
class AssemblyInstance {
public:
    AssemblyInstance(uint32_t instance_id, int data_size, std::optional<std::string> name = {});

    [[nodiscard]] uint32_t instance_id() const noexcept { return instance_id_; }
    [[nodiscard]] int      data_size()   const noexcept { return static_cast<int>(data_.size()); }
    [[nodiscard]] const std::optional<std::string>& name() const noexcept { return name_; }

    /// Copy the current data into a caller buffer.
    void copy_data_to(std::span<uint8_t> dst) const;

    /// Replace the buffer contents with `source` (truncated to data_size()).
    void set_data(std::span<const uint8_t> source);

    /// Typed write at byte offset. Fires on_data_changed.
    template <class T>
    void write(int byte_offset, T value) {
        static_assert(std::is_trivially_copyable_v<T>);
        {
            std::scoped_lock lock(write_mu_);
            std::memcpy(data_.data() + byte_offset, &value, sizeof(T));
        }
        fire_data_changed();
    }

    /// Typed read at byte offset (no locking — single-word reads are atomic).
    template <class T>
    [[nodiscard]] T read(int byte_offset = 0) const {
        static_assert(std::is_trivially_copyable_v<T>);
        T out{};
        std::memcpy(&out, data_.data() + byte_offset, sizeof(T));
        return out;
    }

    /// Direct access to the raw buffer — for the CipAttribute backing.
    [[nodiscard]] std::vector<uint8_t>& raw_buffer() noexcept { return data_; }
    [[nodiscard]] const std::vector<uint8_t>& raw_buffer() const noexcept { return data_; }

    /// Subscribe to data-changed notifications. The callback receives the
    /// instance ID and a snapshot of the data at the moment of the write.
    /// Note: invoked on whichever thread performed the write (UDP receive,
    /// safety dispatch, application thread).
    using DataChangedHandler = std::function<void(uint32_t, std::span<const uint8_t>)>;
    void add_data_changed_handler(DataChangedHandler h);

private:
    void fire_data_changed();

    uint32_t instance_id_;
    std::optional<std::string> name_;
    std::vector<uint8_t> data_;
    mutable std::mutex write_mu_;
    std::vector<DataChangedHandler> handlers_;
};

/// CIP Assembly Object (Class 0x04). Holds a set of AssemblyInstance buffers
/// and exposes them as CIP instances with attribute 3 (Data) wired directly
/// to the underlying buffer so reads/writes operate on the live data.
class AssemblyObject {
public:
    static constexpr uint32_t ClassCode       = 0x04;
    static constexpr uint16_t DataAttributeId = 3;

    AssemblyObject();

    /// Access to the CIP class. Stays valid after release_cip_class() — the
    /// view is a raw pointer that survives ownership transfer to a dispatcher.
    [[nodiscard]] cip::CipClass& cip_class() noexcept { return *cip_class_view_; }

    /// Transfer ownership of the CIP class to a dispatcher. AssemblyObject
    /// keeps the view pointer so add_instance() still works.
    [[nodiscard]] std::unique_ptr<cip::CipClass> release_cip_class();

    /// Create an assembly instance and register it with the CIP class.
    AssemblyInstance& add_instance(uint32_t instance_id, int data_size,
                                     std::optional<std::string> name = {});

    /// Look up by ID. Returns nullptr if not found.
    [[nodiscard]] AssemblyInstance* get_assembly(uint32_t instance_id);

    [[nodiscard]] const std::unordered_map<uint32_t, std::unique_ptr<AssemblyInstance>>&
        assemblies() const noexcept { return assemblies_; }

private:
    std::unique_ptr<cip::CipClass> cip_class_;
    cip::CipClass* cip_class_view_ = nullptr;   ///< survives release
    std::unordered_map<uint32_t, std::unique_ptr<AssemblyInstance>> assemblies_;
};

} // namespace ethernetip::device
