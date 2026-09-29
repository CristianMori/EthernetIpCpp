#include "ethernetip/logix/walker.hpp"

#include "ethernetip/logix/logix_data_types.hpp"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <variant>

namespace ethernetip::logix {

namespace ldt = logix_data_types;
using namespace ethernetip::cip;

static const TemplateMemberInfo* find_member(const TemplateDefinition& tpl, std::string_view name) {
    for (const auto& m : tpl.members()) {
        if (m.name.size() != name.size()) continue;
        bool eq = true;
        for (size_t i = 0; i < name.size(); ++i) {
            char a = static_cast<char>(std::tolower(static_cast<unsigned char>(m.name[i])));
            char b = static_cast<char>(std::tolower(static_cast<unsigned char>(name[i])));
            if (a != b) { eq = false; break; }
        }
        if (eq) return &m;
    }
    return nullptr;
}

static int atomic_size_of(uint16_t type_code) {
    if (type_code & 0x8000) return 0;
    int s = ldt::element_size(type_code);
    return s > 0 ? s : 0;
}

std::optional<WalkResult> walk(const Tag& root,
                                std::span<const PathSegment> segments,
                                const TagDatabase& db,
                                std::string* err) {
    auto fail = [&](std::string msg) -> std::optional<WalkResult> {
        if (err) *err = std::move(msg);
        return std::nullopt;
    };

    int offset = 0;
    uint16_t type_code = root.tag_type();
    int element_size = root.element_size();
    std::optional<int> bit_pos;
    const TemplateDefinition* tpl = root.tag_template();

    // Multi-dim indexing state.
    std::vector<uint32_t> pending_dims(root.dims().begin(), root.dims().end());
    size_t pending_idx = 0;
    uint64_t pending_running = 0;
    bool pending_active = !pending_dims.empty();

    bool root_is_bool_array = (root.tag_type() == ldt::Bool) && !root.dims().empty();

    for (const auto& seg : segments) {
        if (const auto* sym = std::get_if<SymbolicPathSegment>(&seg)) {
            if (bit_pos.has_value()) return fail("cannot drill into BOOL member with `" + sym->name + "`");
            if (pending_active) return fail("cannot drill into array element without an index: `" + sym->name + "`");
            if (tpl == nullptr) return fail("cannot resolve `" + sym->name + "` on non-structure type");
            const TemplateMemberInfo* m = find_member(*tpl, sym->name);
            if (m == nullptr) return fail("member `" + sym->name + "` not found in `" + tpl->name() + "`");

            offset += m->offset;
            type_code = m->data_type;

            if (type_code == ldt::Bool && m->element_size == 0) {
                bit_pos = m->array_size;   // scalar BOOL: array_size is bit position
                element_size = 1;
                tpl = nullptr;
            } else if (type_code & 0x8000) {
                uint16_t nested_id = static_cast<uint16_t>(type_code & 0x0FFF);
                const TemplateDefinition* nested = db.find_template(nested_id);
                if (nested == nullptr) {
                    std::ostringstream os; os << "member `" << sym->name
                                              << "` references unknown template 0x" << std::hex << nested_id;
                    return fail(os.str());
                }
                element_size = static_cast<int>(nested->structure_size());
                tpl = nested;
                if (m->array_size > 0) {
                    pending_dims.assign(1, static_cast<uint32_t>(m->array_size));
                    pending_idx = 0;
                    pending_running = 0;
                    pending_active = true;
                }
            } else {
                tpl = nullptr;
                element_size = m->element_size > 0 ? m->element_size : atomic_size_of(type_code);
                if (m->array_size > 0) {
                    pending_dims.assign(1, static_cast<uint32_t>(m->array_size));
                    pending_idx = 0;
                    pending_running = 0;
                    pending_active = true;
                }
            }
        } else if (const auto* el = std::get_if<ElementPathSegment>(&seg)) {
            if (bit_pos.has_value()) return fail("cannot index into a BOOL member");
            if (!pending_active) return fail("element index on non-array target");
            uint32_t dim = pending_dims[pending_idx];
            if (el->index >= dim) {
                std::ostringstream os; os << "element index " << el->index
                                          << " out of range for dim " << pending_idx
                                          << " (size " << dim << ")";
                return fail(os.str());
            }
            pending_running = pending_running * dim + el->index;
            ++pending_idx;
            if (pending_idx == pending_dims.size()) {
                if (root_is_bool_array) {
                    offset += static_cast<int>(pending_running / 8);
                    bit_pos = static_cast<int>(pending_running % 8);
                } else {
                    offset += static_cast<int>(pending_running * element_size);
                }
                pending_dims.clear();
                pending_idx = 0;
                pending_running = 0;
                pending_active = false;
            }
        } else {
            // LogicalPathSegment — handled by outer dispatcher.
        }
    }

    if (pending_active) {
        std::ostringstream os; os << "under-indexed array: expected "
                                  << pending_dims.size() << " element segments, got " << pending_idx;
        return fail(os.str());
    }

    WalkResult r{offset, type_code, element_size, bit_pos, tpl};
    return r;
}

} // namespace ethernetip::logix
