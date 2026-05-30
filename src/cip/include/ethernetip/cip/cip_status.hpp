#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ethernetip::cip {

/// CIP service response status — general status byte plus optional additional
/// status words. Encoded in the MR response after the reply service code and
/// reserved byte.
struct CipStatus {
    uint8_t general_status = 0;
    std::vector<uint16_t> additional_status;

    [[nodiscard]] bool is_success() const noexcept { return general_status == 0; }

    /// Build a success status (general=0, no additional words).
    [[nodiscard]] static CipStatus success() { return CipStatus{}; }

    /// Build an error status with optional additional status words.
    [[nodiscard]] static CipStatus error(uint8_t general,
                                          std::vector<uint16_t> additional = {}) {
        return CipStatus{general, std::move(additional)};
    }

    /// Encode to wire format:
    ///   general_status(1) + additional_status_size(1) + additional_status(N*2)
    /// Returns the number of bytes written.
    int encode(std::span<uint8_t> dst) const;

    // ---- Common general status codes ----
    static constexpr uint8_t PathSegmentError      = 0x04;
    static constexpr uint8_t PathDestinationUnknown = 0x05;
    static constexpr uint8_t ServiceNotSupported   = 0x08;
    static constexpr uint8_t InvalidAttributeValue = 0x09;
    static constexpr uint8_t AttributeNotSettable  = 0x0E;
    static constexpr uint8_t NotEnoughData         = 0x13;
    static constexpr uint8_t AttributeNotSupported = 0x14;
    static constexpr uint8_t TooMuchData           = 0x15;
    static constexpr uint8_t ObjectDoesNotExist    = 0x16;
    static constexpr uint8_t InvalidParameter      = 0x20;
};

} // namespace ethernetip::cip
