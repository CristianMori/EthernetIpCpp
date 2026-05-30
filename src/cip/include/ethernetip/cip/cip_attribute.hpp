#pragma once

#include "ethernetip/cip/cip_data_type.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace ethernetip::cip {

/// Flags controlling which CIP services can access an attribute.
enum class AttributeAccess : uint8_t {
    None      = 0,
    GetSingle = 1,   ///< Readable via GetAttributeSingle (0x0E)
    SetSingle = 2,   ///< Writable via SetAttributeSingle (0x10)
    GetAll    = 4,   ///< Included in GetAttributeAll (0x01) response
    All       = GetSingle | SetSingle | GetAll,
};

inline AttributeAccess  operator|(AttributeAccess a, AttributeAccess b) noexcept {
    return static_cast<AttributeAccess>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}
inline AttributeAccess  operator&(AttributeAccess a, AttributeAccess b) noexcept {
    return static_cast<AttributeAccess>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}
inline bool has_flag(AttributeAccess a, AttributeAccess b) noexcept {
    return (static_cast<uint8_t>(a) & static_cast<uint8_t>(b)) != 0;
}

/// A single CIP attribute — typed, access-controlled value identified by
/// numeric ID. Stored as raw little-endian wire bytes. Subclassable: a
/// derived class can override encode_to() / set_data() to back the attribute
/// with a live buffer (e.g. an Assembly I/O buffer).
class CipAttribute {
public:
    CipAttribute(uint16_t id, CipDataType data_type, AttributeAccess access,
                 std::vector<uint8_t> initial_data)
        : id_(id), data_type_(data_type), access_(access),
          data_(std::move(initial_data)) {}

    virtual ~CipAttribute() = default;

    [[nodiscard]] uint16_t          id()         const noexcept { return id_; }
    [[nodiscard]] CipDataType       data_type()  const noexcept { return data_type_; }
    [[nodiscard]] AttributeAccess   access()     const noexcept { return access_; }
    [[nodiscard]] std::span<const uint8_t> data() const noexcept { return data_; }
    [[nodiscard]] size_t            data_length() const noexcept { return data_.size(); }

    /// Replace data; reallocates if the size changes.
    virtual void set_data(std::span<const uint8_t> value);

    /// Copy attribute data into dst (must have room for data_length() bytes).
    /// Returns bytes written.
    virtual int encode_to(std::span<uint8_t> dst) const;

    // ---- Convenience factories ----
    [[nodiscard]] static std::unique_ptr<CipAttribute>
        create_byte(uint16_t id, CipDataType type, AttributeAccess access, uint8_t value);
    [[nodiscard]] static std::unique_ptr<CipAttribute>
        create_uint(uint16_t id, CipDataType type, AttributeAccess access, uint16_t value);
    [[nodiscard]] static std::unique_ptr<CipAttribute>
        create_udint(uint16_t id, CipDataType type, AttributeAccess access, uint32_t value);
    [[nodiscard]] static std::unique_ptr<CipAttribute>
        create_short_string(uint16_t id, AttributeAccess access, std::string_view value);

protected:
    uint16_t id_;
    CipDataType data_type_;
    AttributeAccess access_;
    std::vector<uint8_t> data_;
};

} // namespace ethernetip::cip
