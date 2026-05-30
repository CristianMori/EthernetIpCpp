#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/cip/identity_info.hpp"

#include <memory>

namespace ethernetip::device::identity_object {

/// Create the CIP Identity Object (Class 0x01) populated from `identity`.
/// Returns the class as owned by the caller — usually transferred to a
/// CipDispatcher via `register_class`.
[[nodiscard]] std::unique_ptr<cip::CipClass> create(const cip::IdentityInfo& identity);

} // namespace ethernetip::device::identity_object
