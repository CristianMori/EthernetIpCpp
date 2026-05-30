#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <cstring>
#include <stdexcept>

namespace ethernetip::protocol::sock {

#ifdef _WIN32
namespace {
std::atomic<bool> g_initialized{false};
} // namespace

void ensure_initialized() {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) return;
    WSADATA wsa{};
    int err = ::WSAStartup(MAKEWORD(2, 2), &wsa);
    if (err != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
}
#else
void ensure_initialized() {}
#endif

void to_sockaddr(const IpEndpoint& ep, sockaddr_in& addr) noexcept {
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ep.port);
    if (ep.host.empty() || ep.host == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        inet_pton(AF_INET, ep.host.c_str(), &addr.sin_addr);
    }
}

IpEndpoint from_sockaddr(const sockaddr_in& addr) {
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return {std::string(buf), ntohs(addr.sin_port)};
}

} // namespace ethernetip::protocol::sock
