#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ethernetip::cip {

/// Common Packet Format item type IDs.
enum class CpfItemType : uint16_t {
    NullAddress          = 0x0000,
    CipIdentity          = 0x000C,
    ConnectedAddress     = 0x00A1,
    ConnectedData        = 0x00B1,
    UnconnectedData      = 0x00B2,
    ListServicesResponse = 0x0100,
    SockaddrInfoOtoT     = 0x8000,
    SockaddrInfoTtoO     = 0x8001,
    SequencedAddress     = 0x8002,
};

/// A single CPF item. Owns its data via std::vector for lifetime simplicity —
/// items are typically built once and consumed many times.
struct CpfItem {
    CpfItemType type_id = CpfItemType::NullAddress;
    std::vector<uint8_t> data;

    CpfItem() = default;
    CpfItem(CpfItemType type, std::vector<uint8_t> bytes)
        : type_id(type), data(std::move(bytes)) {}
    CpfItem(CpfItemType type, std::span<const uint8_t> bytes)
        : type_id(type), data(bytes.begin(), bytes.end()) {}
};

/// CPF wire format:
///   item_count (UINT) + array of { type_id (UINT), length (UINT), data (byte[length]) }.
/// Used inside SendRRData, SendUnitData, and Class 0/1 UDP packets.
namespace cpf {

/// Parse CPF items. Returns an empty vector if the buffer is too short.
/// Stops at the first truncated item — returned vector may be shorter than the
/// declared item count.
[[nodiscard]] std::vector<CpfItem> parse(std::span<const uint8_t> data);

/// Write CPF items into `dst`. Returns bytes written.
/// Throws std::invalid_argument if dst is too small.
int write(std::span<uint8_t> dst, std::span<const CpfItem> items);

/// Computed byte-size of the CPF representation of `items`.
[[nodiscard]] size_t size_for(std::span<const CpfItem> items);

} // namespace cpf

} // namespace ethernetip::cip
