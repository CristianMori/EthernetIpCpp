#pragma once

#include "ethernetip/cip/cip_service.hpp"
#include "ethernetip/logix/tag.hpp"

#include <cstdint>
#include <span>

namespace ethernetip::logix::tag_services {

inline constexpr uint8_t ReadTag            = 0x4C;
inline constexpr uint8_t WriteTag           = 0x4D;
inline constexpr uint8_t ReadModifyWrite    = 0x4E;
inline constexpr uint8_t ReadTagFragmented  = 0x52;
inline constexpr uint8_t WriteTagFragmented = 0x53;

/// Max reply data — ~500 bytes minus header overhead.
inline constexpr int MaxReplyData = 480;

/// Read Tag (0x4C). Request: element_count (UINT). Reply: tag_type (UINT) + data.
/// `element_offset` indexes into the tag's array (0 for scalars or whole-tag
/// reads); the byte offset is element_offset * tag.element_size().
[[nodiscard]] cip::CipServiceResponse handle_read_tag(
    const Tag& tag, uint8_t service_code, std::span<const uint8_t> data,
    int element_offset = 0);

/// Write Tag (0x4D). Request: tag_type (UINT) + element_count (UINT) + data.
[[nodiscard]] cip::CipServiceResponse handle_write_tag(
    Tag& tag, uint8_t service_code, std::span<const uint8_t> data,
    int element_offset = 0);

/// Read Tag Fragmented (0x52). Request: element_count (UINT) + byte_offset (UDINT).
[[nodiscard]] cip::CipServiceResponse handle_read_tag_fragmented(
    const Tag& tag, uint8_t service_code, std::span<const uint8_t> data);

/// Write Tag Fragmented (0x53). Request: tag_type + element_count + byte_offset + data.
[[nodiscard]] cip::CipServiceResponse handle_write_tag_fragmented(
    Tag& tag, uint8_t service_code, std::span<const uint8_t> data);

/// Read Modify Write (0x4E). Request: mask_size (UINT) + OR_mask + AND_mask.
[[nodiscard]] cip::CipServiceResponse handle_read_modify_write(
    Tag& tag, uint8_t service_code, std::span<const uint8_t> data);

} // namespace ethernetip::logix::tag_services
