#pragma once

// Cross-platform socket wrapper — Winsock on Windows, BSD sockets on Linux/macOS.
// Callers use the BSD-flavored API throughout; this header smooths over the
// type and header differences.

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
namespace ethernetip::protocol::sock {
using socket_t = SOCKET;
constexpr socket_t invalid = INVALID_SOCKET;
constexpr int      sockerr = SOCKET_ERROR;
inline int  last_error() noexcept { return WSAGetLastError(); }
inline int  close(socket_t s) noexcept { return ::closesocket(s); }
inline int  shutdown_read(socket_t s) noexcept { return ::shutdown(s, SD_RECEIVE); }
} // namespace ethernetip::protocol::sock
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <errno.h>
namespace ethernetip::protocol::sock {
using socket_t = int;
constexpr socket_t invalid = -1;
constexpr int      sockerr = -1;
inline int  last_error() noexcept { return errno; }
inline int  close(socket_t s) noexcept { return ::close(s); }
/// Wake any thread blocked in recv/recvfrom/accept on this socket.
/// POSIX close() does not do this (Winsock closesocket() does), so
/// teardown must shutdown_read() first, join the I/O thread, then close().
/// Only the read side is shut down: shutting down the write side would
/// make a concurrent send()/sendto() raise SIGPIPE.
/// The return value is ignored by callers: unconnected UDP sockets
/// report ENOTCONN on Linux but still wake blocked readers.
inline int  shutdown_read(socket_t s) noexcept { return ::shutdown(s, SHUT_RD); }
} // namespace ethernetip::protocol::sock
#endif

#include "ethernetip/protocol/ip_endpoint.hpp"

namespace ethernetip::protocol::sock {

/// Initialize sockets library (no-op on POSIX, WSAStartup on Windows).
/// Idempotent — safe to call once per program at startup.
void ensure_initialized();

/// Convert an IpEndpoint to sockaddr_in (IPv4). Empty / "0.0.0.0" host
/// becomes INADDR_ANY.
void to_sockaddr(const IpEndpoint& ep, sockaddr_in& addr) noexcept;

/// Convert sockaddr_in to IpEndpoint (dotted-decimal host + port).
[[nodiscard]] IpEndpoint from_sockaddr(const sockaddr_in& addr);

} // namespace ethernetip::protocol::sock
