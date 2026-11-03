#pragma once

// Shared re-entrant CIP dispatch depth counter.
//
// Several CIP services unwrap an embedded MR and re-enter the dispatcher
// recursively (Multiple_Service_Packet 0x0A, Unconnected_Send 0x52, and any
// future encapsulating service). Each of those is a hop on the native call
// stack; a hostile client that nests them — even mixing types in one chain —
// can keep each outer payload small while still exhausting the C stack
// through the dispatch call chain.
//
// A per-service counter is not enough: MSP's own cap does not fire on a
// UCS→UCS chain, and vice versa. Every re-entrant service uses the same
// thread-local counter below, so the cap applies to the combined chain.
//
// Three levels is slack for pathological legitimate traffic — real clients
// never nest these services at all.

namespace ethernetip::cip::dispatch_depth {

inline constexpr int kMaxDepth = 3;

namespace detail {
inline thread_local int g_depth = 0;
}  // namespace detail

/// Returns true if the current thread is already at or above kMaxDepth.
/// A re-entrant service handler must call this on entry and, if true, fail
/// the nested dispatch with CIP Service Not Supported (0x08) WITHOUT
/// constructing a Guard.
[[nodiscard]] inline bool exceeded() noexcept {
    return detail::g_depth >= kMaxDepth;
}

/// RAII counter. Construct exactly once per re-entrant handler invocation,
/// after exceeded() has returned false. Must not be constructed from a
/// handler that will return the cap-exceeded error.
class Guard {
public:
    Guard() noexcept  { ++detail::g_depth; }
    ~Guard() noexcept { --detail::g_depth; }
    Guard(const Guard&)            = delete;
    Guard& operator=(const Guard&) = delete;
    Guard(Guard&&)                 = delete;
    Guard& operator=(Guard&&)      = delete;
};

}  // namespace ethernetip::cip::dispatch_depth
