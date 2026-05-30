#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ethernetip::cip {

/// Parsed CIP EPATH — logical segments (class, instance, attribute,
/// connection point, element) plus ANSI Extended Symbolic segments and the
/// raw path bytes for pass-through.
struct CipPath {
    std::optional<uint32_t> class_id;
    std::optional<uint32_t> instance_id;
    std::optional<uint16_t> attribute_id;
    std::optional<uint16_t> connection_point;
    std::optional<uint32_t> element_id;

    /// Full symbolic path from ANSI Extended Symbolic segments
    /// (e.g. "MyStruct.member"). Multiple symbolic segments are joined by dot.
    std::optional<std::string> symbolic_name;

    /// Raw EPATH bytes for pass-through or re-parsing.
    std::vector<uint8_t> raw_path;

    /// Parse an EPATH from a byte span.
    /// Returns the parsed path and the number of bytes consumed.
    [[nodiscard]] static std::pair<CipPath, int> parse(std::span<const uint8_t> data);

    /// Encode an 8-bit logical segment. Writes 2 bytes; returns 2.
    static int encode_logical_8(std::span<uint8_t> dst, uint8_t logical_type, uint8_t value);

    /// Human-readable representation: "Class=0x06, Instance=1, Attr=3" etc.
    [[nodiscard]] std::string to_string() const;

    // Segment-type constants exposed for callers that need to build paths.
    static constexpr uint8_t SegmentTypeMask     = 0xE0;
    static constexpr uint8_t LogicalSegment      = 0x20;
    static constexpr uint8_t SymbolicSegmentByte = 0x91;  ///< ANSI Extended Symbolic

    static constexpr uint8_t LogicalTypeMask         = 0x1C;
    static constexpr uint8_t LogicalTypeClassId      = 0x00;
    static constexpr uint8_t LogicalTypeInstanceId   = 0x04;
    static constexpr uint8_t LogicalTypeElementId    = 0x08;
    static constexpr uint8_t LogicalTypeConnectionPoint = 0x0C;
    static constexpr uint8_t LogicalTypeAttributeId  = 0x10;

    static constexpr uint8_t LogicalFormatMask  = 0x03;
    static constexpr uint8_t LogicalFormat8Bit  = 0x00;
    static constexpr uint8_t LogicalFormat16Bit = 0x01;
    static constexpr uint8_t LogicalFormat32Bit = 0x02;
};

} // namespace ethernetip::cip
