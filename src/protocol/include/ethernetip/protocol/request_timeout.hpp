#pragma once

#include <chrono>
#include <stdexcept>
#include <string>

namespace ethernetip::protocol {

/// Default time a client waits for the reply to one request/response
/// exchange (RegisterSession, SendRRData, SendUnitData, Forward_Open,
/// Forward_Close). Zero disables the timeout.
inline constexpr std::chrono::milliseconds DefaultRequestTimeout{5000};

/// Thrown when a client request gets no complete reply within the request
/// timeout. Derives from std::runtime_error so existing handlers keep
/// working. After it is thrown the TCP connection has been closed (the
/// byte stream is out of sync) and the session is gone: reconnect to
/// continue.
class RequestTimeoutError : public std::runtime_error {
public:
    explicit RequestTimeoutError(const std::string& what)
        : std::runtime_error(what) {}
};

/// Default time a client waits for the TCP connect() to complete. Zero
/// disables the timeout (the OS connect timeout applies).
inline constexpr std::chrono::milliseconds DefaultConnectTimeout{5000};

/// Thrown when the TCP connect does not complete within the connect
/// timeout. Derives from RequestTimeoutError so one `catch
/// (RequestTimeoutError&)` handles every client timeout, while callers that
/// care can catch this type first. Refused / unreachable targets still fail
/// fast with a plain std::runtime_error. The client stays not connected.
class ConnectTimeoutError : public RequestTimeoutError {
public:
    explicit ConnectTimeoutError(const std::string& what)
        : RequestTimeoutError(what) {}
};

} // namespace ethernetip::protocol
