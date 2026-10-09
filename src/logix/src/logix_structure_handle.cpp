#include "ethernetip/logix/logix_structure_handle.hpp"

#include "ethernetip/cip/cip_crc.hpp"

namespace ethernetip::logix {

namespace {

// CIP Vol 1 Section C-6.2.1 Table C-6.3 constants for the
// FormalStrucTypeSpec:
//
//   [0xA2][length][type_code_1][type_code_2]...[type_code_N]
constexpr uint8_t FORMAL_STRUCT_PREFIX = 0xA2;

// Known single-byte atomic type codes. Anything outside these ranges
// means the simple encoding cannot describe the layout — refuse rather
// than ship a wrong handle.
constexpr bool is_known_atomic(uint16_t code) noexcept {
    const uint8_t base = static_cast<uint8_t>(code & 0x00FF);
    // BOOL(C1) .. ULINT(C9), REAL(CA), LREAL(CB)
    if (base >= 0xC1 && base <= 0xCB) return true;
    // BYTE(D1), WORD(D2), DWORD(D3), LWORD(D4)
    if (base >= 0xD1 && base <= 0xD4) return true;
    return false;
}

} // namespace

std::optional<std::vector<uint8_t>>
try_build_formal_struc_spec(const TemplateDefinition& tmpl) {
    std::vector<uint8_t> types;
    types.reserve(tmpl.members().size());

    for (const auto& m : tmpl.members()) {
        // Arrays — out of scope. array_size > 1 means a real array;
        // 0 or 1 is scalar (0 on a scalar BOOL also carries the "packed"
        // signal, caught by the element_size check below).
        if (m.array_size > 1) return std::nullopt;

        // Nested struct — out of scope. data_type's high bit flags it.
        if ((m.data_type & 0x8000) != 0) return std::nullopt;

        // Scalar BOOLs packed into a host byte: element_size == 0 and
        // array_size carries the bit position (0..7). The simple formal
        // encoding can't represent that; refuse rather than ship a
        // plausible wrong handle.
        if (m.data_type == 0x00C1 && m.element_size == 0) return std::nullopt;

        if (!is_known_atomic(m.data_type)) return std::nullopt;

        types.push_back(static_cast<uint8_t>(m.data_type & 0x00FF));
    }

    if (types.empty() || types.size() > 0xFF) return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve(2 + types.size());
    out.push_back(FORMAL_STRUCT_PREFIX);
    out.push_back(static_cast<uint8_t>(types.size()));
    out.insert(out.end(), types.begin(), types.end());
    return out;
}

std::optional<uint16_t>
try_compute_structure_handle(const TemplateDefinition& tmpl) {
    auto spec = try_build_formal_struc_spec(tmpl);
    if (!spec) return std::nullopt;
    return ethernetip::cip::cip_crc16(std::span<const uint8_t>(spec->data(), spec->size()));
}

} // namespace ethernetip::logix
