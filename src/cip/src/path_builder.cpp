#include "ethernetip/cip/path_builder.hpp"

namespace ethernetip::cip {

namespace {

// Logical segment format byte = 001 LLL FF where LLL = logical type, FF = format.
//   Class    LLL=000 -> 0x20 (8-bit) / 0x21 (16-bit) / 0x22 (32-bit)
//   Instance LLL=001 -> 0x24 / 0x25 / 0x26
//   Attribute LLL=100 -> 0x30 / 0x31 / 0x32
//   Element  LLL=010 -> 0x28 / 0x29 / 0x2A
constexpr uint8_t Class8  = 0x20, Class16  = 0x21, Class32  = 0x22;
constexpr uint8_t Inst8   = 0x24, Inst16   = 0x25, Inst32   = 0x26;
constexpr uint8_t Attr8   = 0x30, Attr16   = 0x31, Attr32   = 0x32;
constexpr uint8_t Elem8   = 0x28, Elem16   = 0x29, Elem32   = 0x2A;

void emit_logical(std::vector<uint8_t>& out, uint32_t v,
                    uint8_t f8, uint8_t f16, uint8_t f32) {
    if (v <= 0xFFu) {
        out.push_back(f8);
        out.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xFFFFu) {
        out.push_back(f16);
        out.push_back(0);                                // pad
        out.push_back(static_cast<uint8_t>(v));
        out.push_back(static_cast<uint8_t>(v >> 8));
    } else {
        out.push_back(f32);
        out.push_back(0);                                // pad
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
}

} // namespace

std::vector<uint8_t> build_path(std::optional<uint32_t> class_id,
                                  std::optional<uint32_t> instance_id,
                                  std::optional<uint16_t> attribute_id,
                                  std::optional<uint32_t> element_id) {
    std::vector<uint8_t> out;
    out.reserve(12);
    if (class_id.has_value())    emit_logical(out, *class_id,    Class8, Class16, Class32);
    if (instance_id.has_value()) emit_logical(out, *instance_id, Inst8,  Inst16,  Inst32);
    if (attribute_id.has_value())
        emit_logical(out, *attribute_id, Attr8, Attr16, Attr32);
    if (element_id.has_value())  emit_logical(out, *element_id,  Elem8,  Elem16,  Elem32);
    return out;
}

} // namespace ethernetip::cip
