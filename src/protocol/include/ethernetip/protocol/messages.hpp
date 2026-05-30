#pragma once

#include "ethernetip/cip/encapsulation.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace ethernetip::protocol::messages {

/// Discriminator for typed encapsulation messages.
enum class MessageKind {
    Generic,           ///< Unknown command — fall-through.
    Nop,
    ListIdentity,
    ListServices,
    RegisterSession,
    UnregisterSession,
    SendRRData,
    SendUnitData,
    /// CPF SequencedAddress + ConnectedData over UDP (I/O data).
    CpfConnectedData,
};

/// Common base for every parsed/sent message. Public fields rather than
/// virtual getters to keep things value-oriented and trivially copyable
/// where possible.
struct Message {
    MessageKind kind = MessageKind::Generic;
    IpEndpoint  remote_endpoint;
    virtual ~Message() = default;

    /// Wire size required to serialize this message. Subclasses override.
    [[nodiscard]] virtual int wire_size() const = 0;
    /// Serialize into dst (which must be at least wire_size() bytes).
    virtual void write_to(std::span<uint8_t> dst) const = 0;
};

/// Generic encapsulation message — header + raw payload. Used as a fallback
/// for commands not recognized by typed dispatch.
struct EncapsulationMessage : Message {
    cip::EncapsulationHeader header;
    std::vector<uint8_t> payload;

    EncapsulationMessage() { kind = MessageKind::Generic; }
    [[nodiscard]] int wire_size() const override {
        return cip::EncapsulationHeader::Size + static_cast<int>(payload.size());
    }
    void write_to(std::span<uint8_t> dst) const override;
};

struct NopMessage : Message {
    uint64_t sender_context = 0;
    NopMessage() { kind = MessageKind::Nop; }
    [[nodiscard]] int wire_size() const override { return cip::EncapsulationHeader::Size; }
    void write_to(std::span<uint8_t> dst) const override;
};

struct ListIdentityMessage : Message {
    uint32_t session_handle = 0;
    cip::EncapsulationStatus status = cip::EncapsulationStatus::Success;
    uint64_t sender_context = 0;
    std::vector<uint8_t> response_payload;   ///< non-empty = response

    ListIdentityMessage() { kind = MessageKind::ListIdentity; }
    [[nodiscard]] int wire_size() const override {
        return cip::EncapsulationHeader::Size + static_cast<int>(response_payload.size());
    }
    void write_to(std::span<uint8_t> dst) const override;
};

struct ListServicesMessage : Message {
    uint32_t session_handle = 0;
    cip::EncapsulationStatus status = cip::EncapsulationStatus::Success;
    uint64_t sender_context = 0;
    std::vector<uint8_t> response_payload;

    ListServicesMessage() { kind = MessageKind::ListServices; }
    [[nodiscard]] int wire_size() const override {
        return cip::EncapsulationHeader::Size + static_cast<int>(response_payload.size());
    }
    void write_to(std::span<uint8_t> dst) const override;
};

struct RegisterSessionMessage : Message {
    uint32_t session_handle = 0;
    cip::EncapsulationStatus status = cip::EncapsulationStatus::Success;
    uint64_t sender_context = 0;
    uint16_t protocol_version = 1;
    uint16_t options_flags = 0;

    RegisterSessionMessage() { kind = MessageKind::RegisterSession; }
    [[nodiscard]] int wire_size() const override { return cip::EncapsulationHeader::Size + 4; }
    void write_to(std::span<uint8_t> dst) const override;
};

struct UnregisterSessionMessage : Message {
    uint32_t session_handle = 0;
    uint64_t sender_context = 0;

    UnregisterSessionMessage() { kind = MessageKind::UnregisterSession; }
    [[nodiscard]] int wire_size() const override { return cip::EncapsulationHeader::Size; }
    void write_to(std::span<uint8_t> dst) const override;
};

struct SendRRDataMessage : Message {
    uint32_t session_handle = 0;
    cip::EncapsulationStatus status = cip::EncapsulationStatus::Success;
    uint64_t sender_context = 0;
    uint32_t interface_handle = 0;
    uint16_t timeout = 0;
    std::vector<uint8_t> cip_data;  ///< CIP MR bytes inside the CPF UnconnectedData item

    static constexpr int CpfHeaderOverhead = 2 + 4 + 4;  // count + null-addr hdr + data hdr
    static constexpr int PreambleSize      = 6;          // interface_handle + timeout

    SendRRDataMessage() { kind = MessageKind::SendRRData; }
    [[nodiscard]] int wire_size() const override {
        return cip::EncapsulationHeader::Size + PreambleSize
             + CpfHeaderOverhead + static_cast<int>(cip_data.size());
    }
    void write_to(std::span<uint8_t> dst) const override;
};

struct SendUnitDataMessage : Message {
    uint32_t session_handle = 0;
    cip::EncapsulationStatus status = cip::EncapsulationStatus::Success;
    uint64_t sender_context = 0;
    uint32_t interface_handle = 0;
    uint16_t timeout = 0;
    uint32_t connection_id = 0;
    std::vector<uint8_t> cip_data;

    static constexpr int CpfHeaderOverhead = 2 + 4 + 4 + 4;  // count + addr hdr + addr data + data hdr
    static constexpr int PreambleSize      = 6;

    SendUnitDataMessage() { kind = MessageKind::SendUnitData; }
    [[nodiscard]] int wire_size() const override {
        return cip::EncapsulationHeader::Size + PreambleSize
             + CpfHeaderOverhead + static_cast<int>(cip_data.size());
    }
    void write_to(std::span<uint8_t> dst) const override;
};

/// CPF SequencedAddress + ConnectedData — UDP I/O cargo on port 2222.
struct CpfConnectedDataMessage : Message {
    static constexpr int CpfOverhead = 18;
    uint32_t connection_id = 0;
    uint32_t encap_sequence_number = 0;
    std::vector<uint8_t> payload;

    CpfConnectedDataMessage() { kind = MessageKind::CpfConnectedData; }
    [[nodiscard]] int wire_size() const override {
        return CpfOverhead + static_cast<int>(payload.size());
    }
    void write_to(std::span<uint8_t> dst) const override;

    /// Hot-path: build wire bytes without allocating a message object.
    static void write_wire(std::span<uint8_t> dst, uint32_t connection_id,
                            uint32_t encap_sequence_number,
                            std::span<const uint8_t> payload);

    /// Parse a CPF datagram. Returns nullptr if the layout doesn't match.
    [[nodiscard]] static std::unique_ptr<CpfConnectedDataMessage>
        try_parse(std::span<const uint8_t> data, const IpEndpoint& remote);
};

/// Parse an EtherNet/IP encapsulation message from a (possibly partial)
/// TCP byte stream or a UDP datagram. Sets `consumed` to the number of
/// bytes the returned message occupied. Returns nullptr if more bytes are
/// needed (TCP) or the data is unrecognized.
[[nodiscard]] std::unique_ptr<Message>
    try_parse_encapsulation(std::span<const uint8_t> data,
                              const IpEndpoint& remote,
                              int& consumed);

} // namespace ethernetip::protocol::messages
