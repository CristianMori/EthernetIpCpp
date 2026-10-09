#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace ethernetip::cip {

/// Kind of logical segment (matches the low bits of the segment type nibble).
enum class LogicalKind : uint8_t {
    ClassId         = 0x00,
    InstanceId      = 0x04,
    ConnectionPoint = 0x0C,
    AttributeId     = 0x10,
};

/// ANSI Extended Symbolic (0x91) — a tag name or member name.
struct SymbolicPathSegment { std::string name; };
/// Logical Element ID (0x28/0x29/0x2A) — one array index.
struct ElementPathSegment { uint32_t index; };
/// Any other logical segment.
struct LogicalPathSegment { LogicalKind kind; uint32_t value; };

/// One segment inside a CIP EPATH, in on-wire order.
using PathSegment = std::variant<SymbolicPathSegment, ElementPathSegment, LogicalPathSegment>;

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

    /// Every parsed segment in on-wire order. Empty when constructed manually
    /// without going through parse(); the parser populates it so callers can
    /// distinguish, for example, `Program:X.Tag` from `Motor.Timer.PRE`.
    std::vector<PathSegment> segments;

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
