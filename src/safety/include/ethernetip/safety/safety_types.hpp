#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace ethernetip::safety {

/// Safety wire format selection.
enum class SafetyFormat : uint8_t {
    Base     = 0,
    Extended = 1,
};

/// CIP Safety Mode Byte. Bit layout (verified against real 1734 PointIO):
///   7    Run_Idle
///   6-5  TBD_2_Bit (reserved, 0)
///   4    N_Run_Idle (complement of bit 7)
///   3    TBD_Bit (reserved, 0)
///   2    N_TBD_Bit (complement of bit 3, always 1)
///   1-0  Ping_Count
struct ModeByte {
    uint8_t raw = 0;

    constexpr ModeByte() = default;
    explicit constexpr ModeByte(uint8_t v) : raw(v) {}

    [[nodiscard]] constexpr bool    run_idle()  const noexcept { return (raw & 0x80) != 0; }
    [[nodiscard]] constexpr uint8_t ping_count() const noexcept { return static_cast<uint8_t>(raw & 0x03); }
    [[nodiscard]] constexpr uint8_t value()      const noexcept { return raw; }

    /// Bits used in actual/complement data CRC: ModeByte AND 0xE0.
    [[nodiscard]] constexpr uint8_t data_crc_mask() const noexcept {
        return static_cast<uint8_t>(raw & 0xE0);
    }
    /// Bits used in complement data CRC (base format): (ModeByte XOR 0xFF) AND 0xE0.
    [[nodiscard]] constexpr uint8_t complement_data_crc_mask() const noexcept {
        return static_cast<uint8_t>((raw ^ 0xFF) & 0xE0);
    }
    /// Bits used in timestamp CRC: ModeByte AND 0x1F.
    [[nodiscard]] constexpr uint8_t timestamp_crc_mask() const noexcept {
        return static_cast<uint8_t>(raw & 0x1F);
    }

    /// Build a mode byte with auto-computed redundant bits.
    [[nodiscard]] static constexpr ModeByte create(bool run_idle, uint8_t ping_count) noexcept {
        uint8_t r = 0;
        if (run_idle) r |= 0x80;
        r |= static_cast<uint8_t>(ping_count & 0x03);
        return ModeByte{compute_redundant_bits(r)};
    }

    /// Bit 4 = NOT(bit 7); bit 2 = NOT(bit 3).
    [[nodiscard]] static constexpr uint8_t compute_redundant_bits(uint8_t raw) noexcept {
        if ((raw & 0x80) == 0) raw |= 0x10;
        else                    raw = static_cast<uint8_t>(raw & ~0x10);
        if ((raw & 0x08) == 0) raw |= 0x04;
        else                    raw = static_cast<uint8_t>(raw & ~0x04);
        return raw;
    }

    /// True iff redundant bits are complements of their pairs.
    [[nodiscard]] constexpr bool validate() const noexcept {
        bool run = (raw & 0x80) != 0;
        bool n_run = (raw & 0x10) != 0;
        if (run == n_run) return false;
        bool tbd = (raw & 0x08) != 0;
        bool n_tbd = (raw & 0x04) != 0;
        if (tbd == n_tbd) return false;
        return true;
    }
};

/// 6-byte unique identifier for a safety network.
struct SafetyNetworkNumber {
    std::array<uint8_t, 6> data{};

    SafetyNetworkNumber() = default;
    explicit SafetyNetworkNumber(std::span<const uint8_t> bytes) {
        if (bytes.size() != 6) {
            throw std::invalid_argument("SNN must be exactly 6 bytes");
        }
        for (size_t i = 0; i < 6; ++i) data[i] = bytes[i];
    }
    explicit SafetyNetworkNumber(const std::array<uint8_t, 6>& bytes) : data(bytes) {}

    void copy_to(std::span<uint8_t> dst) const noexcept {
        for (size_t i = 0; i < 6; ++i) dst[i] = data[i];
    }

    [[nodiscard]] static SafetyNetworkNumber zero() noexcept { return {}; }
};

inline bool operator==(const SafetyNetworkNumber& a, const SafetyNetworkNumber& b) noexcept {
    return a.data == b.data;
}

/// SCID = SCCRC (4 bytes) + SCTS (6 bytes) = 10 bytes.
struct SafetyConfigurationId {
    static constexpr int Size = 10;
    uint32_t sccrc = 0;
    SafetyNetworkNumber scts{};

    void copy_to(std::span<uint8_t> dst) const noexcept;
    [[nodiscard]] static SafetyConfigurationId parse(std::span<const uint8_t> data);
};

/// UNID = SNN(6) + NodeAddress(4) = 10 bytes.
struct UniqueNetworkId {
    static constexpr int Size = 10;
    SafetyNetworkNumber snn{};
    uint32_t node_address = 0;

    void copy_to(std::span<uint8_t> dst) const noexcept;
    [[nodiscard]] static UniqueNetworkId parse(std::span<const uint8_t> data);
};

inline bool operator==(const UniqueNetworkId& a, const UniqueNetworkId& b) noexcept {
    return a.snn == b.snn && a.node_address == b.node_address;
}

} // namespace ethernetip::safety
