#pragma once

#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/cip_service.hpp"

#include <cstdint>

namespace ethernetip::logix::multi_service_handler {

inline constexpr uint8_t ServiceCode = 0x0A;

/// Multiple Service Packet (0x0A) — bundles multiple CIP requests into one
/// MR frame, dispatched via `dispatch`. Each sub-response is encoded and
/// concatenated; the outer reply lists the offsets to each sub-response.
[[nodiscard]] cip::CipServiceResponse handle(cip::ICipDispatch& dispatch,
                                                const cip::CipServiceRequest& request);

} // namespace ethernetip::logix::multi_service_handler
