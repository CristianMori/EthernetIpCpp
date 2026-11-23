#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <cstring>
#ifndef _WIN32
#  include <poll.h>
#endif
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

bool wait_readable(socket_t s, std::chrono::milliseconds timeout) {
    long long ms = timeout.count();
    if (ms < 0) ms = 0;
    if (ms > 0x7FFFFFFF) ms = 0x7FFFFFFF;
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd     = s;
    pfd.events = POLLRDNORM;
    int r = ::WSAPoll(&pfd, 1, static_cast<INT>(ms));
#else
    pollfd pfd{};
    pfd.fd     = s;
    pfd.events = POLLIN;
    int r;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    for (;;) {
        r = ::poll(&pfd, 1, static_cast<int>(ms));
        if (r >= 0 || errno != EINTR) break;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        ms = left > 0 ? left : 0;
    }
#endif
    // 0 = timeout; >0 readable/hup/err; <0 error -> let recv() report it.
    return r != 0;
}

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
