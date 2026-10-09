#pragma once

#include "ethernetip/logix/tag_database.hpp"

#include <istream>
#include <ostream>
#include <string>
#include <vector>

namespace ethernetip::logix::persistence {

/// Report of what happened during load().
struct LoadResult {
    int tags_restored = 0;
    int tags_skipped  = 0;
    std::vector<std::string> warnings;
};

/// Write every controller-scope and program-scope tag's buffer to `os`.
/// Format v1: header magic "EIPS" + version=1 + LE tag records, byte-for-
/// byte compatible with the C#, Rust, and Python ports.
void save(TagDatabase& db, std::ostream& os);

/// Restore tag buffer contents from a stream written by save().  Tolerant
/// of missing/mismatched/added tags between versions.
[[nodiscard]] LoadResult load(TagDatabase& db, std::istream& is);

} // namespace ethernetip::logix::persistence
