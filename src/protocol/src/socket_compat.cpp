#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <cstring>
#include <optional>
#ifndef _WIN32
#  include <fcntl.h>
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

namespace {

// Poll one socket for readability or writability for up to `timeout`.
bool wait_fd(socket_t s, bool for_write, std::chrono::milliseconds timeout) {
    long long ms = timeout.count();
    if (ms < 0) ms = 0;
    if (ms > 0x7FFFFFFF) ms = 0x7FFFFFFF;
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd     = s;
    pfd.events = for_write ? POLLWRNORM : POLLRDNORM;
    int r = ::WSAPoll(&pfd, 1, static_cast<INT>(ms));
#else
    pollfd pfd{};
    pfd.fd     = s;
    pfd.events = for_write ? POLLOUT : POLLIN;
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
    // 0 = timeout; >0 ready/hup/err; <0 error -> let the next call report it.
    return r != 0;
}

// Puts s in non-blocking mode; restores blocking mode on destruction.
class NonBlocking {
public:
    explicit NonBlocking(socket_t s) noexcept : s_(s) {
#ifdef _WIN32
        u_long on = 1;
        ok_ = ::ioctlsocket(s_, FIONBIO, &on) == 0;
#else
        flags_ = ::fcntl(s_, F_GETFL, 0);
        ok_ = flags_ != -1 && ::fcntl(s_, F_SETFL, flags_ | O_NONBLOCK) != -1;
#endif
    }
    ~NonBlocking() {
        if (!ok_) return;
#ifdef _WIN32
        u_long off = 0;
        ::ioctlsocket(s_, FIONBIO, &off);
#else
        ::fcntl(s_, F_SETFL, flags_);
#endif
    }
    NonBlocking(const NonBlocking&) = delete;
    NonBlocking& operator=(const NonBlocking&) = delete;
    [[nodiscard]] bool ok() const noexcept { return ok_; }
private:
    socket_t s_;
    bool     ok_ = false;
#ifndef _WIN32
    int      flags_ = 0;
#endif
};

bool would_block(int e) noexcept {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

} // namespace

bool wait_readable(socket_t s, std::chrono::milliseconds timeout) {
    return wait_fd(s, false, timeout);
}

bool wait_writable(socket_t s, std::chrono::milliseconds timeout) {
    return wait_fd(s, true, timeout);
}

ConnectResult connect_timed(socket_t s, const sockaddr_in& addr,
                            std::chrono::milliseconds timeout, int& err) {
    const auto* sa = reinterpret_cast<const sockaddr*>(&addr);
    if (timeout.count() <= 0) {
        if (::connect(s, sa, sizeof(addr)) == sockerr) {
            err = last_error();
            return ConnectResult::Failed;
        }
        return ConnectResult::Ok;
    }
    NonBlocking nb(s);
    if (!nb.ok()) { err = last_error(); return ConnectResult::Failed; }
    if (::connect(s, sa, sizeof(addr)) == 0) return ConnectResult::Ok;
    err = last_error();
#ifdef _WIN32
    const bool pending = err == WSAEWOULDBLOCK;
#else
    const bool pending = err == EINPROGRESS || err == EINTR;
#endif
    if (!pending) return ConnectResult::Failed;   // refused/unreachable: fail fast
    if (!wait_writable(s, timeout)) return ConnectResult::TimedOut;
    int so_err = 0;
    socklen_t len = sizeof(so_err);
    if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &len) != 0) {
        err = last_error();
        return ConnectResult::Failed;
    }
    if (so_err != 0) { err = so_err; return ConnectResult::Failed; }
    return ConnectResult::Ok;
}

SendResult send_all(socket_t s, const uint8_t* data, size_t n,
                    std::chrono::steady_clock::time_point deadline, int& err) {
    const bool bounded = deadline != std::chrono::steady_clock::time_point::max();
    // A bounded send must never block in the kernel. MSG_DONTWAIT is not
    // enough: Darwin ignores it on a blocking socket, and Winsock has no
    // per-call flag at all. So every platform puts the socket in non-blocking
    // mode for the duration of the call (restored by the RAII guard on every
    // exit path) and waits for writability itself.
    std::optional<NonBlocking> nb;
    if (bounded) {
        nb.emplace(s);
        if (!nb->ok()) { err = last_error(); return SendResult::Failed; }
    }
    int flags = 0;
#ifndef _WIN32
#  ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#  endif
#  ifdef SO_NOSIGPIPE
    {   // macOS/BSD have no MSG_NOSIGNAL: suppress SIGPIPE per socket instead.
        int on = 1;
        (void)::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    }
#  endif
#endif
    auto left_ms = [&] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
    };
    size_t off = 0;
    while (off < n) {
        int r = ::send(s, reinterpret_cast<const char*>(data + off),
                       static_cast<int>(n - off), flags);
        if (r == sockerr) {
            int e = last_error();
#ifndef _WIN32
            if (e == EINTR) continue;
#endif
            if (bounded && would_block(e)) {
                if (!wait_writable(s, left_ms())) return SendResult::TimedOut;
                continue;
            }
            err = e;
            return SendResult::Failed;
        }
        off += static_cast<size_t>(r);
    }
    return SendResult::Ok;
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
