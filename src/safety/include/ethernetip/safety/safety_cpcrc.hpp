#pragma once

#include "ethernetip/connections/forward_open_request.hpp"

#include <cstdint>
#include <span>

namespace ethernetip::safety::cpcrc {

/// Compute CPCRC (CRC-S4) from the raw Forward Open service-data bytes
/// plus the per-instance pieces — this is the exact computation both the
/// originator (builder) and target (validator) use to agree on a CPCRC.
///
/// CRC input layout (matches the HMS/IXXAT CSS reference and the field
/// extraction baked into the Forward Open service data buffer):
///
///   [raw_service_data 10..14]   conn_serial(2) + orig_vendor(2)             = 4 bytes
///   [raw_service_data 18..36]   timeout_mult, reserved, OT_RPI, OT_params,
///                                TO_RPI, TO_params, transport_class_trigger,
///                                path_size_words                            = 18 bytes
///   [app_path]                  electronic key + assembly path
///                                (route prefix excluded)
///   [nsd_bytes]                 48 bytes for Target / 50 for Extended of
///                                the safety segment starting at its 0x50
///                                header; CPCRC field must be 0 here
///
/// The path_size byte in the 18-byte block is patched to reflect the path
/// the target sees (app_path + safety_segment, no route prefix). Callers
/// pass `effective_path_size_words` to drive this patch.
[[nodiscard]] uint32_t compute_from_raw(
    std::span<const uint8_t> raw_service_data,
    std::span<const uint8_t> app_path,
    std::span<const uint8_t> nsd_bytes,
    uint8_t effective_path_size_words);

/// Re-encode a parsed NetworkConnectionParams back to its 16-bit wire form.
/// Useful when building a Forward Open from a parsed request.
[[nodiscard]] uint16_t encode_network_params(const connections::NetworkConnectionParams& p);

} // namespace ethernetip::safety::cpcrc
