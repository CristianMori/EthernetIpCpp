#pragma once

#include <cstdint>
#include <string>

namespace ethernetip::protocol {

/// IPv4 endpoint = dotted-decimal host + port. Trivial value type used at
/// every public protocol boundary so callers never deal with sockaddr.
struct IpEndpoint {
    std::string host;   ///< e.g. "192.168.1.84"
    uint16_t    port = 0;

    [[nodiscard]] bool operator==(const IpEndpoint&) const = default;
};

} // namespace ethernetip::protocol
