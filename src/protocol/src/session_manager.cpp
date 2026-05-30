#include "ethernetip/protocol/session_manager.hpp"

namespace ethernetip::protocol {

uint32_t SessionManager::register_session() {
    uint32_t h = next_handle_.fetch_add(1) + 1;
    std::scoped_lock lock(mu_);
    sessions_[h] = SessionInfo{h, std::chrono::steady_clock::now()};
    return h;
}

bool SessionManager::unregister_session(uint32_t handle) {
    std::scoped_lock lock(mu_);
    return sessions_.erase(handle) > 0;
}

bool SessionManager::is_valid(uint32_t handle) const {
    std::scoped_lock lock(mu_);
    return sessions_.find(handle) != sessions_.end();
}

size_t SessionManager::active_count() const {
    std::scoped_lock lock(mu_);
    return sessions_.size();
}

} // namespace ethernetip::protocol
