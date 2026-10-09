#pragma once

#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/logix/tag.hpp"
#include "ethernetip/logix/tag_database.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace ethernetip::logix {

/// Result of a successful walker resolve.
struct WalkResult {
    int offset = 0;
    uint16_t type_code = 0;
    int element_size = 0;
    std::optional<int> bit_pos;   ///< set for BOOL member / BOOL[] bit reads
    const TemplateDefinition* tpl = nullptr;
};

/// Walk a sequence of CIP path segments over a root Tag → WalkResult.
///
/// Returns nullopt with `err` filled in on any failure. Mirrors the C#
/// TagPathWalker: member drilling, element indexing, BOOL bit position
/// (0..7 from a scalar BOOL member's array_size field), multi-dim
/// row-major with under-index detection, BOOL[] bit-index/8 collapse.
std::optional<WalkResult> walk(const Tag& root,
                                std::span<const ethernetip::cip::PathSegment> segments,
                                const TagDatabase& db,
                                std::string* err);

} // namespace ethernetip::logix
