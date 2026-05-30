#include "ethernetip/protocol/messages.hpp"

#include "ethernetip/cip/data_serializer.hpp"

#include <cstring>

namespace ethernetip::protocol::messages {

namespace ser = ethernetip::cip::serializer;
using cip::EncapsulationHeader;
using cip::EncapsulationCommand;
using cip::EncapsulationStatus;

// ---- write_to implementations --------------------------------------------

void EncapsulationMessage::write_to(std::span<uint8_t> dst) const {
    EncapsulationHeader hdr = header;
    hdr.length = static_cast<uint16_t>(payload.size());
    hdr.write_to(dst);
    if (!payload.empty()) {
        std::memcpy(dst.data() + EncapsulationHeader::Size, payload.data(), payload.size());
    }
}

void NopMessage::write_to(std::span<uint8_t> dst) const {
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::Nop;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);
}

void ListIdentityMessage::write_to(std::span<uint8_t> dst) const {
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::ListIdentity;
    hdr.length = static_cast<uint16_t>(response_payload.size());
    hdr.session_handle = session_handle;
    hdr.status = status;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);
    if (!response_payload.empty()) {
        std::memcpy(dst.data() + EncapsulationHeader::Size,
                     response_payload.data(), response_payload.size());
    }
}

void ListServicesMessage::write_to(std::span<uint8_t> dst) const {
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::ListServices;
    hdr.length = static_cast<uint16_t>(response_payload.size());
    hdr.session_handle = session_handle;
    hdr.status = status;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);
    if (!response_payload.empty()) {
        std::memcpy(dst.data() + EncapsulationHeader::Size,
                     response_payload.data(), response_payload.size());
    }
}

void RegisterSessionMessage::write_to(std::span<uint8_t> dst) const {
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::RegisterSession;
    hdr.length = 4;
    hdr.session_handle = session_handle;
    hdr.status = status;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);
    ser::write_uint(dst.subspan(EncapsulationHeader::Size),     protocol_version);
    ser::write_uint(dst.subspan(EncapsulationHeader::Size + 2), options_flags);
}

void UnregisterSessionMessage::write_to(std::span<uint8_t> dst) const {
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::UnregisterSession;
    hdr.session_handle = session_handle;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);
}

void SendRRDataMessage::write_to(std::span<uint8_t> dst) const {
    int payload_len = PreambleSize + CpfHeaderOverhead + static_cast<int>(cip_data.size());
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::SendRRData;
    hdr.length = static_cast<uint16_t>(payload_len);
    hdr.session_handle = session_handle;
    hdr.status = status;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);

    size_t o = EncapsulationHeader::Size;
    ser::write_udint(dst.subspan(o), interface_handle); o += 4;
    ser::write_uint (dst.subspan(o), timeout);          o += 2;
    ser::write_uint (dst.subspan(o), uint16_t{2});      o += 2;        // item count
    ser::write_uint (dst.subspan(o), uint16_t{0x0000}); o += 2;        // null address type
    ser::write_uint (dst.subspan(o), uint16_t{0});      o += 2;        // null address length
    ser::write_uint (dst.subspan(o), uint16_t{0x00B2}); o += 2;        // unconnected data type
    ser::write_uint (dst.subspan(o), static_cast<uint16_t>(cip_data.size())); o += 2;
    if (!cip_data.empty()) {
        std::memcpy(dst.data() + o, cip_data.data(), cip_data.size());
    }
}

void SendUnitDataMessage::write_to(std::span<uint8_t> dst) const {
    int payload_len = PreambleSize + CpfHeaderOverhead + static_cast<int>(cip_data.size());
    EncapsulationHeader hdr;
    hdr.command = EncapsulationCommand::SendUnitData;
    hdr.length = static_cast<uint16_t>(payload_len);
    hdr.session_handle = session_handle;
    hdr.status = status;
    hdr.sender_context = sender_context;
    hdr.write_to(dst);

    size_t o = EncapsulationHeader::Size;
    ser::write_udint(dst.subspan(o), interface_handle); o += 4;
    ser::write_uint (dst.subspan(o), timeout);          o += 2;
    ser::write_uint (dst.subspan(o), uint16_t{2});      o += 2;
    ser::write_uint (dst.subspan(o), uint16_t{0x00A1}); o += 2;        // connected address
    ser::write_uint (dst.subspan(o), uint16_t{4});      o += 2;
    ser::write_udint(dst.subspan(o), connection_id);    o += 4;
    ser::write_uint (dst.subspan(o), uint16_t{0x00B1}); o += 2;        // connected data
    ser::write_uint (dst.subspan(o), static_cast<uint16_t>(cip_data.size())); o += 2;
    if (!cip_data.empty()) {
        std::memcpy(dst.data() + o, cip_data.data(), cip_data.size());
    }
}

// ---- CPF connected data ---------------------------------------------------

void CpfConnectedDataMessage::write_wire(std::span<uint8_t> dst, uint32_t connection_id,
                                          uint32_t encap_sequence_number,
                                          std::span<const uint8_t> payload) {
    size_t o = 0;
    ser::write_uint (dst.subspan(o), uint16_t{2});      o += 2;        // item count
    ser::write_uint (dst.subspan(o), uint16_t{0x8002}); o += 2;        // sequenced address type
    ser::write_uint (dst.subspan(o), uint16_t{8});      o += 2;        // address length
    ser::write_udint(dst.subspan(o), connection_id);    o += 4;
    ser::write_udint(dst.subspan(o), encap_sequence_number); o += 4;
    ser::write_uint (dst.subspan(o), uint16_t{0x00B1}); o += 2;        // connected data type
    ser::write_uint (dst.subspan(o), static_cast<uint16_t>(payload.size())); o += 2;
    if (!payload.empty()) {
        std::memcpy(dst.data() + o, payload.data(), payload.size());
    }
}

void CpfConnectedDataMessage::write_to(std::span<uint8_t> dst) const {
    write_wire(dst, connection_id, encap_sequence_number, payload);
}

std::unique_ptr<CpfConnectedDataMessage>
CpfConnectedDataMessage::try_parse(std::span<const uint8_t> data, const IpEndpoint& remote) {
    if (data.size() < static_cast<size_t>(CpfOverhead)) return nullptr;

    uint16_t item_count = ser::read_uint(data);
    if (item_count < 2) return nullptr;

    size_t o = 2;
    uint16_t addr_type = ser::read_uint(data.subspan(o)); o += 2;
    uint16_t addr_len  = ser::read_uint(data.subspan(o)); o += 2;
    if (addr_type != 0x8002 || addr_len != 8) return nullptr;

    uint32_t conn_id  = ser::read_udint(data.subspan(o)); o += 4;
    uint32_t encap    = ser::read_udint(data.subspan(o)); o += 4;

    if (o + 4 > data.size()) return nullptr;
    uint16_t data_type = ser::read_uint(data.subspan(o)); o += 2;
    uint16_t data_len  = ser::read_uint(data.subspan(o)); o += 2;
    if (data_type != 0x00B1) return nullptr;
    if (o + data_len > data.size()) return nullptr;

    auto msg = std::make_unique<CpfConnectedDataMessage>();
    msg->remote_endpoint = remote;
    msg->connection_id = conn_id;
    msg->encap_sequence_number = encap;
    msg->payload.assign(data.begin() + o, data.begin() + o + data_len);
    return msg;
}

// ---- Encapsulation parser -------------------------------------------------

namespace {

template <class T>
T fill_common(EncapsulationHeader& h, const IpEndpoint& remote) {
    T msg;
    msg.session_handle = h.session_handle;
    msg.status         = h.status;
    msg.sender_context = h.sender_context;
    msg.remote_endpoint = remote;
    return msg;
}

std::unique_ptr<Message> parse_send_rr(EncapsulationHeader& hdr,
                                         std::span<const uint8_t> payload,
                                         const IpEndpoint& remote) {
    constexpr int min_size = SendRRDataMessage::PreambleSize
                                + SendRRDataMessage::CpfHeaderOverhead;
    if (payload.size() < static_cast<size_t>(min_size)) return nullptr;

    size_t o = 0;
    uint32_t iface = ser::read_udint(payload.subspan(o)); o += 4;
    uint16_t tmo   = ser::read_uint (payload.subspan(o)); o += 2;
    uint16_t ic    = ser::read_uint (payload.subspan(o)); o += 2;
    if (ic < 2) return nullptr;
    uint16_t addr_type = ser::read_uint(payload.subspan(o)); o += 2;
    uint16_t addr_len  = ser::read_uint(payload.subspan(o)); o += 2;
    if (addr_type != 0x0000 || addr_len != 0) return nullptr;
    if (o + 4 > payload.size()) return nullptr;
    uint16_t data_type = ser::read_uint(payload.subspan(o)); o += 2;
    uint16_t data_len  = ser::read_uint(payload.subspan(o)); o += 2;
    if (data_type != 0x00B2) return nullptr;
    if (o + data_len > payload.size()) return nullptr;

    auto msg = std::make_unique<SendRRDataMessage>();
    msg->session_handle  = hdr.session_handle;
    msg->status          = hdr.status;
    msg->sender_context  = hdr.sender_context;
    msg->remote_endpoint = remote;
    msg->interface_handle = iface;
    msg->timeout = tmo;
    msg->cip_data.assign(payload.begin() + o, payload.begin() + o + data_len);
    return msg;
}

std::unique_ptr<Message> parse_send_unit(EncapsulationHeader& hdr,
                                          std::span<const uint8_t> payload,
                                          const IpEndpoint& remote) {
    constexpr int min_size = SendUnitDataMessage::PreambleSize
                                + SendUnitDataMessage::CpfHeaderOverhead;
    if (payload.size() < static_cast<size_t>(min_size)) return nullptr;

    size_t o = 0;
    uint32_t iface = ser::read_udint(payload.subspan(o)); o += 4;
    uint16_t tmo   = ser::read_uint (payload.subspan(o)); o += 2;
    uint16_t ic    = ser::read_uint (payload.subspan(o)); o += 2;
    if (ic < 2) return nullptr;
    uint16_t addr_type = ser::read_uint(payload.subspan(o)); o += 2;
    uint16_t addr_len  = ser::read_uint(payload.subspan(o)); o += 2;
    if (addr_type != 0x00A1 || addr_len != 4) return nullptr;
    uint32_t conn_id   = ser::read_udint(payload.subspan(o)); o += 4;
    if (o + 4 > payload.size()) return nullptr;
    uint16_t data_type = ser::read_uint(payload.subspan(o)); o += 2;
    uint16_t data_len  = ser::read_uint(payload.subspan(o)); o += 2;
    if (data_type != 0x00B1) return nullptr;
    if (o + data_len > payload.size()) return nullptr;

    auto msg = std::make_unique<SendUnitDataMessage>();
    msg->session_handle  = hdr.session_handle;
    msg->status          = hdr.status;
    msg->sender_context  = hdr.sender_context;
    msg->remote_endpoint = remote;
    msg->interface_handle = iface;
    msg->timeout = tmo;
    msg->connection_id = conn_id;
    msg->cip_data.assign(payload.begin() + o, payload.begin() + o + data_len);
    return msg;
}

} // namespace

std::unique_ptr<Message> try_parse_encapsulation(std::span<const uint8_t> data,
                                                    const IpEndpoint& remote,
                                                    int& consumed) {
    consumed = 0;
    if (data.size() < static_cast<size_t>(EncapsulationHeader::Size)) return nullptr;
    auto hdr = EncapsulationHeader::parse(data);
    int total = EncapsulationHeader::Size + hdr.length;
    if (data.size() < static_cast<size_t>(total)) return nullptr;
    auto payload = data.subspan(EncapsulationHeader::Size, hdr.length);
    consumed = total;

    switch (hdr.command) {
        case EncapsulationCommand::Nop: {
            auto m = std::make_unique<NopMessage>();
            m->sender_context = hdr.sender_context;
            m->remote_endpoint = remote;
            return m;
        }
        case EncapsulationCommand::ListIdentity: {
            auto m = std::make_unique<ListIdentityMessage>();
            m->session_handle = hdr.session_handle;
            m->status = hdr.status;
            m->sender_context = hdr.sender_context;
            m->response_payload.assign(payload.begin(), payload.end());
            m->remote_endpoint = remote;
            return m;
        }
        case EncapsulationCommand::ListServices: {
            auto m = std::make_unique<ListServicesMessage>();
            m->session_handle = hdr.session_handle;
            m->status = hdr.status;
            m->sender_context = hdr.sender_context;
            m->response_payload.assign(payload.begin(), payload.end());
            m->remote_endpoint = remote;
            return m;
        }
        case EncapsulationCommand::RegisterSession: {
            if (payload.size() < 4) return nullptr;
            auto m = std::make_unique<RegisterSessionMessage>();
            m->session_handle = hdr.session_handle;
            m->status = hdr.status;
            m->sender_context = hdr.sender_context;
            m->protocol_version = ser::read_uint(payload);
            m->options_flags    = ser::read_uint(payload.subspan(2));
            m->remote_endpoint = remote;
            return m;
        }
        case EncapsulationCommand::UnregisterSession: {
            auto m = std::make_unique<UnregisterSessionMessage>();
            m->session_handle = hdr.session_handle;
            m->sender_context = hdr.sender_context;
            m->remote_endpoint = remote;
            return m;
        }
        case EncapsulationCommand::SendRRData:   return parse_send_rr(hdr, payload, remote);
        case EncapsulationCommand::SendUnitData: return parse_send_unit(hdr, payload, remote);
        default: {
            auto m = std::make_unique<EncapsulationMessage>();
            m->header = hdr;
            m->payload.assign(payload.begin(), payload.end());
            m->remote_endpoint = remote;
            return m;
        }
    }
}

} // namespace ethernetip::protocol::messages
