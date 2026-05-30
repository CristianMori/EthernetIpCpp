#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace ethernetip::cip {

/// Build a logical EPATH from class/instance/attribute/element fields.
/// Each field picks the smallest logical-segment format that fits:
///   8-bit  (value <= 0xFF)         — 2 bytes
///   16-bit (value <= 0xFFFF)       — 4 bytes (pad + LE value)
///   32-bit (value <= 0xFFFFFFFF)   — 6 bytes (pad + LE value)
/// Empty optionals are skipped, so this also covers paths like "class only"
/// (Get_Attribute_All on the class) or "class + instance" (whole-instance
/// services such as Read_Tag).
[[nodiscard]] std::vector<uint8_t> build_path(
    std::optional<uint32_t> class_id,
    std::optional<uint32_t> instance_id,
    std::optional<uint16_t> attribute_id = {},
    std::optional<uint32_t> element_id   = {});

} // namespace ethernetip::cip
