#include "ethernetip/protocol/eip_adapter.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/cip/mr_codec.hpp"
#include "ethernetip/cip/standard_services.hpp"
#include "ethernetip/protocol/cpf_helpers.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <cstring>
#include <vector>

namespace ethernetip::protocol {

namespace ser = ethernetip::cip::serializer;
using cip::EncapsulationCommand;
using cip::EncapsulationStatus;

// ---- Per-client framing accumulator ----

struct EipAdapter::PerClient {
    std::vector<uint8_t> accum;          ///< partial-message buffer for TCP
    uint32_t session_handle = 0;
};

namespace {
void accum_append(std::vector<uint8_t>& accum, std::span<const uint8_t> data) {
    accum.insert(accum.end(), data.begin(), data.end());
}
void accum_advance(std::vector<uint8_t>& accum, int consumed) {
    if (consumed >= static_cast<int>(accum.size())) {
        accum.clear();
    } else if (consumed > 0) {
        accum.erase(accum.begin(), accum.begin() + consumed);
    }
}
} // namespace

// ---- Construction / listening ----

EipAdapter::EipAdapter(cip::ICipDispatch& dispatch, cip::IdentityInfo identity,
                          cip::ICipDispatch* identity_source)
    : dispatch_(dispatch), identity_(std::move(identity)),
      identity_source_(identity_source ? identity_source : &dispatch) {}

EipAdapter::~EipAdapter() { stop(); }

void EipAdapter::listen(const IpEndpoint& bind) {
    socket_.set_on_accept([this](std::shared_ptr<TcpSocketConnection> c) {
        on_client_connected(std::move(c));
    });
    socket_.start(bind);
}

void EipAdapter::stop() {
    socket_.stop();
}

void EipAdapter::on_client_connected(std::shared_ptr<TcpSocketConnection> conn) {
    auto pc = std::make_shared<PerClient>();
    auto self = this;
    auto local_ep = conn->local_endpoint();
    auto remote_ep = conn->remote_endpoint();

    conn->set_on_bytes(
        [self, pc, local_ep, remote_ep](TcpSocketConnection& c, std::span<const uint8_t> chunk) {
            accum_append(pc->accum, chunk);
            while (true) {
                int consumed = 0;
                auto msg = messages::try_parse_encapsulation(pc->accum, c.remote_endpoint(), consumed);
                if (!msg) break;     // need more bytes
                accum_advance(pc->accum, consumed);
                auto resp = self->dispatch_message(*msg, *pc, local_ep, remote_ep);
                if (!resp.empty()) c.send(resp);
            }
        });
    conn->set_on_closed([self, pc](TcpSocketConnection&) {
        if (pc->session_handle != 0) self->sessions_.unregister_session(pc->session_handle);
    });
}

// ---- Per-message dispatch ----

std::vector<uint8_t> EipAdapter::dispatch_message(messages::Message& msg, PerClient& pc,
                                                      const IpEndpoint& local_ep,
                                                      const IpEndpoint& remote_ep) {
    using K = messages::MessageKind;
    switch (msg.kind) {
        case K::Nop:               return {};
        case K::ListIdentity:      return handle_list_identity(static_cast<messages::ListIdentityMessage&>(msg), local_ep);
        case K::ListServices:      return handle_list_services(static_cast<messages::ListServicesMessage&>(msg));
        case K::RegisterSession:   return handle_register_session(static_cast<messages::RegisterSessionMessage&>(msg), pc);
        case K::UnregisterSession: return handle_unregister_session(static_cast<messages::UnregisterSessionMessage&>(msg), pc);
        case K::SendRRData:        return handle_send_rr_data(static_cast<messages::SendRRDataMessage&>(msg), pc, local_ep, remote_ep);
        case K::SendUnitData:      return handle_send_unit_data(static_cast<messages::SendUnitDataMessage&>(msg), pc);
        case K::Generic: {
            auto& g = static_cast<messages::EncapsulationMessage&>(msg);
            return build_error_response(g.header.command, g.header.session_handle,
                                          g.header.sender_context,
                                          EncapsulationStatus::InvalidCommand);
        }
        default: return {};
    }
}

// ---- Service handlers ----

std::vector<uint8_t> EipAdapter::handle_list_identity(messages::ListIdentityMessage& msg,
                                                         const IpEndpoint& local_ep) {
    std::vector<uint8_t> identity_data(512);
    size_t off = 0;
    ser::write_uint(std::span<uint8_t>(identity_data).subspan(off), uint16_t{1}); off += 2;

    // Socket address (big-endian sin_family/port/addr).
    identity_data[off++] = 0x00; identity_data[off++] = 0x02;            // AF_INET = 2 BE
    uint16_t port = socket_.actual_port();
    identity_data[off++] = static_cast<uint8_t>(port >> 8);
    identity_data[off++] = static_cast<uint8_t>(port);
    in_addr addr{};
    inet_pton(AF_INET, local_ep.host.c_str(), &addr);
    std::memcpy(identity_data.data() + off, &addr, 4);                    // sin_addr (BE in network byte order)
    off += 4;
    std::memset(identity_data.data() + off, 0, 8); off += 8;             // sin_zero

    // Identity attributes via GetAttributeAll.
    cip::CipPath identity_path;
    identity_path.class_id = cip::IdentityInfo::ClassCode;
    identity_path.instance_id = 1;
    auto get_all = identity_source_->dispatch(cip::standard_services::GetAttributeAll,
                                                 identity_path, std::span<const uint8_t>());
    if (get_all.status.is_success() && !get_all.data.empty()) {
        std::memcpy(identity_data.data() + off, get_all.data.data(), get_all.data.size());
        off += get_all.data.size();
    }

    // State attribute (0xFF = not implemented).
    identity_data[off++] = 0xFF;

    // Wrap in a single CipIdentity CPF item.
    cpf_helpers::CpfBuilder cpf;
    cpf.add_item(0x000C, std::span<const uint8_t>(identity_data.data(), off));
    auto cpf_bytes = cpf.build();

    return build_response(EncapsulationCommand::ListIdentity,
                            msg.session_handle, msg.sender_context, cpf_bytes);
}

std::vector<uint8_t> EipAdapter::handle_list_services(messages::ListServicesMessage& msg) {
    std::vector<uint8_t> service_data(20);
    ser::write_uint(service_data,                  uint16_t{1});       // Version
    ser::write_uint(std::span<uint8_t>(service_data).subspan(2),
                     uint16_t{0x0120});                                   // Capability flags
    // Name padded to 16 bytes
    constexpr const char* kName = "Communications";
    std::memcpy(service_data.data() + 4, kName, std::strlen(kName));

    cpf_helpers::CpfBuilder cpf;
    cpf.add_item(0x0100, service_data);
    auto cpf_bytes = cpf.build();
    return build_response(EncapsulationCommand::ListServices,
                            msg.session_handle, msg.sender_context, cpf_bytes);
}

std::vector<uint8_t> EipAdapter::handle_register_session(messages::RegisterSessionMessage& msg,
                                                            PerClient& pc) {
    if (pc.session_handle != 0) {
        return build_error_response(EncapsulationCommand::RegisterSession,
                                       msg.session_handle, msg.sender_context,
                                       EncapsulationStatus::InvalidCommand);
    }
    pc.session_handle = sessions_.register_session();

    messages::RegisterSessionMessage reply;
    reply.session_handle = pc.session_handle;
    reply.status = EncapsulationStatus::Success;
    reply.sender_context = msg.sender_context;
    reply.protocol_version = 1;
    reply.options_flags = 0;
    std::vector<uint8_t> buf(reply.wire_size());
    reply.write_to(buf);
    return buf;
}

std::vector<uint8_t> EipAdapter::handle_unregister_session(messages::UnregisterSessionMessage& msg,
                                                              PerClient& pc) {
    sessions_.unregister_session(msg.session_handle);
    pc.session_handle = 0;
    return {};
}

std::vector<uint8_t> EipAdapter::handle_send_rr_data(messages::SendRRDataMessage& msg,
                                                        PerClient& pc,
                                                        const IpEndpoint& local_ep,
                                                        const IpEndpoint& remote_ep) {
    if (pc.session_handle == 0 || !sessions_.is_valid(msg.session_handle)) {
        return build_error_response(EncapsulationCommand::SendRRData,
                                       msg.session_handle, msg.sender_context,
                                       EncapsulationStatus::InvalidSessionHandle);
    }

    auto parsed = cip::mr_codec::try_parse_request(msg.cip_data);
    if (!parsed.has_value()) {
        return build_error_response(EncapsulationCommand::SendRRData,
                                       msg.session_handle, msg.sender_context,
                                       EncapsulationStatus::IncorrectData);
    }

    auto cip_response = dispatch_.dispatch(parsed->service_code, parsed->path, parsed->data);

    // Encode MR response.
    std::vector<uint8_t> mr_buf(4096);
    int mr_len = cip_response.encode(mr_buf);
    mr_buf.resize(mr_len);

    cpf_helpers::CpfBuilder cpf;
    cpf.add_item(0x0000, {});                  // null address
    cpf.add_item(0x00B2, mr_buf);              // unconnected data

    // Successful Forward Open → let subclasses (IoEipAdapter) attach
    // Sockaddr Info items and fire their on_connection_opened callback.
    bool is_forward_open = cip_response.status.is_success()
        && (parsed->service_code == 0x54 || parsed->service_code == 0x5B);
    if (is_forward_open) {
        on_forward_open_reply(cpf, parsed->service_code, parsed->data,
                                cip_response, local_ep, remote_ep);
    }

    auto cpf_bytes = cpf.build();
    std::vector<uint8_t> payload(6 + cpf_bytes.size());   // interface_handle + timeout + CPF
    std::memcpy(payload.data() + 6, cpf_bytes.data(), cpf_bytes.size());
    return build_response(EncapsulationCommand::SendRRData, pc.session_handle,
                            msg.sender_context, payload);
}

std::vector<uint8_t> EipAdapter::handle_send_unit_data(messages::SendUnitDataMessage& msg,
                                                          PerClient& pc) {
    if (pc.session_handle == 0 || !sessions_.is_valid(msg.session_handle)) {
        return build_error_response(EncapsulationCommand::SendUnitData,
                                       msg.session_handle, msg.sender_context,
                                       EncapsulationStatus::InvalidSessionHandle);
    }
    // ConnectedData payload = 2-byte sequence count + MR request.
    if (msg.cip_data.size() < 2) {
        return build_error_response(EncapsulationCommand::SendUnitData,
                                       msg.session_handle, msg.sender_context,
                                       EncapsulationStatus::IncorrectData);
    }
    uint16_t seq_count = ser::read_uint(msg.cip_data);
    std::span<const uint8_t> mr_in(msg.cip_data.data() + 2, msg.cip_data.size() - 2);

    auto parsed = cip::mr_codec::try_parse_request(mr_in);
    if (!parsed.has_value()) {
        return build_error_response(EncapsulationCommand::SendUnitData,
                                       msg.session_handle, msg.sender_context,
                                       EncapsulationStatus::IncorrectData);
    }
    auto cip_response = dispatch_.dispatch(parsed->service_code, parsed->path, parsed->data);

    std::vector<uint8_t> mr_buf(4096);
    int mr_len = cip_response.encode(mr_buf);
    mr_buf.resize(mr_len);

    // Echo the sequence count back at the head of the ConnectedData payload.
    // The reply's connection_id must be the TO_conn_id (the ID PLC assigned
    // for us-to-PLC traffic) — not the OT_conn_id the PLC put in the request
    // (which identifies our endpoint). Use the connection-id lookup; fall
    // back to echoing if no lookup is wired (loopback tests).
    uint32_t reply_conn_id = msg.connection_id;
    if (connection_id_lookup_) {
        uint32_t tto_o = connection_id_lookup_(msg.connection_id);
        if (tto_o != 0) reply_conn_id = tto_o;
    }

    messages::SendUnitDataMessage reply;
    reply.session_handle = pc.session_handle;
    reply.sender_context = msg.sender_context;
    reply.connection_id  = reply_conn_id;
    reply.cip_data.resize(2 + mr_buf.size());
    ser::write_uint(reply.cip_data, seq_count);
    std::memcpy(reply.cip_data.data() + 2, mr_buf.data(), mr_buf.size());

    std::vector<uint8_t> out(reply.wire_size());
    reply.write_to(out);
    return out;
}

// ---- IoEipAdapter ----

void IoEipAdapter::on_forward_open_reply(cpf_helpers::CpfBuilder& cpf,
                                            uint8_t service_code,
                                            std::span<const uint8_t> request_data,
                                            const cip::CipServiceResponse& response,
                                            const IpEndpoint& local_ep,
                                            const IpEndpoint& remote_ep) {
    // Sockaddr Info items belong only on Class 0/1 I/O connections. For
    // Class 3 explicit messaging, including them makes Logix's MSG
    // instruction reject the FwdOpen reply with extended status 0x0205.
    // Peek transport_class_trigger to skip Class 3.
    size_t tct_off = (service_code == 0x5B) ? 36u : 34u;
    if (request_data.size() > tct_off
        && (request_data[tct_off] & 0x0F) == 3) {
        return;
    }
    auto sockaddr = build_sockaddr_info(local_ep.host, udp_port_);
    cpf.add_item(0x8000, sockaddr);   // Sockaddr Info O->T
    cpf.add_item(0x8001, sockaddr);   // Sockaddr Info T->O
    if (on_connection_opened_) {
        on_connection_opened_(response, IpEndpoint{remote_ep.host, 0x08AE});
    }
}

// ---- Helpers ----

std::vector<uint8_t> EipAdapter::build_sockaddr_info(const std::string& host, uint16_t port) {
    std::vector<uint8_t> data(16);
    data[0] = 0x00; data[1] = 0x02;                               // AF_INET BE
    data[2] = static_cast<uint8_t>(port >> 8);
    data[3] = static_cast<uint8_t>(port);
    in_addr addr{};
    inet_pton(AF_INET, host.c_str(), &addr);
    std::memcpy(data.data() + 4, &addr, 4);                       // sin_addr
    return data;
}

std::vector<uint8_t> EipAdapter::build_response(EncapsulationCommand command,
                                                   uint32_t session_handle,
                                                   uint64_t sender_context,
                                                   std::span<const uint8_t> payload) {
    cip::EncapsulationHeader hdr;
    hdr.command = command;
    hdr.length = static_cast<uint16_t>(payload.size());
    hdr.session_handle = session_handle;
    hdr.sender_context = sender_context;

    std::vector<uint8_t> buf(cip::EncapsulationHeader::Size + payload.size());
    hdr.write_to(buf);
    if (!payload.empty()) {
        std::memcpy(buf.data() + cip::EncapsulationHeader::Size, payload.data(), payload.size());
    }
    return buf;
}

std::vector<uint8_t> EipAdapter::build_error_response(EncapsulationCommand command,
                                                         uint32_t session_handle,
                                                         uint64_t sender_context,
                                                         EncapsulationStatus status) {
    cip::EncapsulationHeader hdr;
    hdr.command = command;
    hdr.session_handle = session_handle;
    hdr.status = status;
    hdr.sender_context = sender_context;
    std::vector<uint8_t> buf(cip::EncapsulationHeader::Size);
    hdr.write_to(buf);
    return buf;
}

} // namespace ethernetip::protocol
