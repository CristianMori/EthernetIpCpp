#pragma once

#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/cip_status.hpp"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace ethernetip::cip {

class CipInstance;  // forward

/// A CIP service request — service code, target EPATH, and request-specific
/// data. Passed to service handlers by the dispatcher.
struct CipServiceRequest {
    uint8_t service_code = 0;
    CipPath path;
    /// Service-specific payload. Stored as a span — request data is borrowed
    /// from the caller's buffer for the lifetime of the dispatch call.
    std::span<const uint8_t> data;
};

/// A CIP service response — reply service code (with bit 7 set), status, and
/// response payload.
struct CipServiceResponse {
    uint8_t service_code = 0;
    CipStatus status;
    std::vector<uint8_t> data;

    /// Build a success response with the reply bit set.
    [[nodiscard]] static CipServiceResponse success(uint8_t service_code,
                                                     std::vector<uint8_t> payload = {}) {
        return {
            static_cast<uint8_t>(service_code | 0x80),
            CipStatus::success(),
            std::move(payload),
        };
    }

    /// Build an error response with the reply bit set.
    [[nodiscard]] static CipServiceResponse error(uint8_t service_code, CipStatus status) {
        return {
            static_cast<uint8_t>(service_code | 0x80),
            std::move(status),
            {},
        };
    }

    /// Encode to MR response wire format:
    ///   reply_service(1) + reserved(1) + general_status(1) + add_status_size(1)
    ///   + add_status(N*2) + data
    int encode(std::span<uint8_t> dst) const;
};

/// Service handler signature — receives the target instance and the request,
/// returns the response.
using CipServiceHandler =
    std::function<CipServiceResponse(CipInstance&, const CipServiceRequest&)>;

/// Binds a service code, name, and handler. Registered on a CipClass at
/// either the class level (instance 0) or the instance level.
struct CipServiceDefinition {
    uint8_t service_code = 0;
    std::string name;
    CipServiceHandler handler;
};

} // namespace ethernetip::cip
