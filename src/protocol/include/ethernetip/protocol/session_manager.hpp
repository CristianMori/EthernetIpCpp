#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace ethernetip::protocol {

/// Information about an active encapsulation session.
struct SessionInfo {
    uint32_t handle = 0;
    std::chrono::steady_clock::time_point created;
};

/// Encapsulation session management. Each TCP connection registers a session
/// via RegisterSession and receives a unique handle. The handle is validated
/// on every SendRRData and released on UnregisterSession or disconnect.
/// Thread-safe.
class SessionManager {
public:
    /// Allocate a new session and return its handle.
    uint32_t register_session();

    /// Release a session. Returns true if it existed.
    bool unregister_session(uint32_t handle);

    /// Check if a session handle is currently valid.
    [[nodiscard]] bool is_valid(uint32_t handle) const;

    [[nodiscard]] size_t active_count() const;

private:
    std::atomic<uint32_t> next_handle_{0};
    mutable std::mutex mu_;
    std::unordered_map<uint32_t, SessionInfo> sessions_;
};

} // namespace ethernetip::protocol
