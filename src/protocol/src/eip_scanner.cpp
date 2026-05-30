#include "ethernetip/protocol/eip_scanner.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/cip/encapsulation.hpp"
#include "ethernetip/cip/mr_codec.hpp"
#include "ethernetip/protocol/connected_explicit.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace ethernetip::protocol {

namespace ser = cip::serializer;
using cip::EncapsulationCommand;
using cip::EncapsulationHeader;
using cip::EncapsulationStatus;

EipScanner::EipScanner() = default;

EipScanner::~EipScanner() {
    disconnect();
}

bool EipScanner::is_connected() const noexcept {
    return socket_ != sock::invalid && session_handle_ != 0;
}

void EipScanner::connect(const std::string& host, int port) {
    sock::ensure_initialized();
    if (socket_ != sock::invalid) {
        throw std::runtime_error("EipScanner: already connected");
    }

    sock::socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == sock::invalid) {
        throw std::runtime_error("EipScanner: socket() failed");
    }
    sockaddr_in addr{};
    sock::to_sockaddr(IpEndpoint{host, static_cast<uint16_t>(port)}, addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == sock::sockerr) {
        int err = sock::last_error();
        sock::close(s);
        throw std::runtime_error("EipScanner: connect to " + host + " failed (err "
            + std::to_string(err) + ")");
    }
    socket_         = s;
    remote_endpoint_ = IpEndpoint{host, static_cast<uint16_t>(port)};

    sockaddr_in local{};
    socklen_t llen = sizeof(local);
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&local), &llen) == 0) {
        local_endpoint_ = sock::from_sockaddr(local);
    }

    // UDP transport — ephemeral local IPv4 port for I/O traffic.
    udp_transport_ = std::make_unique<EipUdpTransport>();
    udp_transport_->set_on_message(
        [this](std::unique_ptr<messages::Message> m) { on_udp_message_dispatch(std::move(m)); });
    udp_transport_->start(IpEndpoint{"0.0.0.0", 0});

    session_handle_ = register_session();
    if (session_handle_ == 0) {
        throw std::runtime_error("EipScanner: RegisterSession returned 0");
    }
}

void EipScanner::disconnect() noexcept {
    if (socket_ == sock::invalid) return;
    if (session_handle_ != 0) {
        try {
            std::array<uint8_t, EncapsulationHeader::Size> buf{};
            EncapsulationHeader hdr;
            hdr.command        = EncapsulationCommand::UnregisterSession;
            hdr.session_handle = session_handle_;
            hdr.write_to(buf);
            (void)::send(socket_, reinterpret_cast<const char*>(buf.data()),
                          static_cast<int>(buf.size()), 0);
        } catch (...) {}
    }
    sock::close(socket_);
    socket_         = sock::invalid;
    session_handle_ = 0;
    if (udp_transport_) {
        udp_transport_->stop();
        udp_transport_.reset();
    }
}

uint32_t EipScanner::register_session() {
    // RegisterSession payload = protocol_version(2) + options_flags(2)
    std::array<uint8_t, 4> payload{1, 0, 0, 0};
    std::scoped_lock lock(io_mu_);

    EncapsulationHeader hdr;
    hdr.command        = EncapsulationCommand::RegisterSession;
    hdr.length         = static_cast<uint16_t>(payload.size());
    std::vector<uint8_t> out(EncapsulationHeader::Size + payload.size());
    hdr.write_to(out);
    std::memcpy(out.data() + EncapsulationHeader::Size, payload.data(), payload.size());
    int sent = ::send(socket_, reinterpret_cast<const char*>(out.data()),
                       static_cast<int>(out.size()), 0);
    if (sent != static_cast<int>(out.size())) {
        throw std::runtime_error("EipScanner: send failed");
    }
    std::array<uint8_t, EncapsulationHeader::Size> rhdr_buf{};
    read_exact(rhdr_buf.data(), rhdr_buf.size());
    auto rhdr = EncapsulationHeader::parse(rhdr_buf);
    if (rhdr.status != EncapsulationStatus::Success) {
        throw std::runtime_error("EipScanner: RegisterSession failed");
    }
    if (rhdr.length > 0) {
        std::vector<uint8_t> body(rhdr.length);
        read_exact(body.data(), body.size());
    }
    return rhdr.session_handle;
}

void EipScanner::read_exact(uint8_t* dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        int chunk = ::recv(socket_, reinterpret_cast<char*>(dst + got),
                            static_cast<int>(n - got), 0);
        if (chunk == 0) {
            throw std::runtime_error("EipScanner: connection closed");
        }
        if (chunk == sock::sockerr) {
            throw std::runtime_error("EipScanner: recv failed (err "
                + std::to_string(sock::last_error()) + ")");
        }
        got += static_cast<size_t>(chunk);
    }
}

std::vector<uint8_t> EipScanner::send_encapsulated(uint16_t command,
                                                     std::span<const uint8_t> payload) {
    std::scoped_lock lock(io_mu_);

    EncapsulationHeader hdr;
    hdr.command        = static_cast<EncapsulationCommand>(command);
    hdr.length         = static_cast<uint16_t>(payload.size());
    hdr.session_handle = session_handle_;

    std::vector<uint8_t> out(EncapsulationHeader::Size + payload.size());
    hdr.write_to(out);
    if (!payload.empty()) {
        std::memcpy(out.data() + EncapsulationHeader::Size, payload.data(), payload.size());
    }
    int sent = ::send(socket_, reinterpret_cast<const char*>(out.data()),
                       static_cast<int>(out.size()), 0);
    if (sent != static_cast<int>(out.size())) {
        throw std::runtime_error("EipScanner: send failed");
    }
    std::array<uint8_t, EncapsulationHeader::Size> rhdr_buf{};
    read_exact(rhdr_buf.data(), rhdr_buf.size());
    auto rhdr = EncapsulationHeader::parse(rhdr_buf);
    if (rhdr.status != EncapsulationStatus::Success) {
        throw std::runtime_error("EipScanner: encapsulation error 0x"
            + std::to_string(static_cast<uint32_t>(rhdr.status)));
    }
    std::vector<uint8_t> body(rhdr.length);
    if (rhdr.length > 0) read_exact(body.data(), body.size());
    return body;
}

cip::CipServiceResponse EipScanner::send_explicit(uint8_t service_code,
                                                    std::span<const uint8_t> path_bytes,
                                                    std::span<const uint8_t> service_data) {
    return send_explicit_raw(service_code, path_bytes, service_data).response;
}

EipScanner::ExplicitRawResult
EipScanner::send_explicit_raw(uint8_t service_code,
                                std::span<const uint8_t> path_bytes,
                                std::span<const uint8_t> service_data) {
    if (!is_connected()) {
        throw std::runtime_error("EipScanner: not connected");
    }
    // Build MR request: service + path_words + path + data.
    std::vector<uint8_t> mr(2u + path_bytes.size() + service_data.size());
    int mr_len = cip::mr_codec::encode_request(mr, service_code, path_bytes, service_data);
    mr.resize(mr_len);

    // CPF: NullAddress + UnconnectedData(B2).
    std::vector<cip::CpfItem> items;
    items.emplace_back(cip::CpfItemType::NullAddress, std::vector<uint8_t>{});
    items.emplace_back(cip::CpfItemType::UnconnectedData, std::move(mr));
    auto cpf_bytes_size = cip::cpf::size_for(items);
    std::vector<uint8_t> cpf_buf(cpf_bytes_size);
    int cpf_len = cip::cpf::write(cpf_buf, items);
    cpf_buf.resize(cpf_len);

    // SendRRData payload = interface_handle(4) + timeout(2) + CPF.
    std::vector<uint8_t> payload(6 + cpf_buf.size(), 0);
    std::memcpy(payload.data() + 6, cpf_buf.data(), cpf_buf.size());

    auto resp = send_encapsulated(static_cast<uint16_t>(EncapsulationCommand::SendRRData), payload);
    if (resp.size() < 8) {
        throw std::runtime_error("EipScanner: SendRRData reply too short");
    }
    auto resp_cpf = cip::cpf::parse(std::span<const uint8_t>(resp).subspan(6));

    ExplicitRawResult result;
    for (const auto& item : resp_cpf) {
        if (item.type_id == cip::CpfItemType::UnconnectedData) {
            auto parsed = cip::mr_codec::try_parse_response(item.data);
            if (!parsed.has_value()) {
                throw std::runtime_error("EipScanner: malformed MR response");
            }
            result.response.service_code = parsed->reply_service;
            result.response.status       = parsed->status;
            result.response.data         = std::move(parsed->data);
        }
    }
    result.cpf_items = std::move(resp_cpf);
    if (result.response.service_code == 0 && result.response.data.empty()
        && result.response.status.is_success()) {
        throw std::runtime_error("EipScanner: no UnconnectedData item in reply");
    }
    return result;
}

std::unique_ptr<ScannerConnection>
EipScanner::forward_open(const ForwardOpenConfig& config) {
    if (!is_connected()) {
        throw std::runtime_error("EipScanner: not connected");
    }
    uint16_t conn_serial = next_conn_serial_.fetch_add(1);
    uint16_t orig_vendor = 0x0001;  // Rockwell
    uint32_t orig_serial = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    // Connection path: Assembly class + config instance + 2 connection points.
    std::array<uint8_t, 8> path{
        0x20, 0x04,
        0x24, static_cast<uint8_t>(config.config_assembly),
        0x2C, static_cast<uint8_t>(config.consumed_assembly),
        0x2C, static_cast<uint8_t>(config.produced_assembly),
    };

    // O->T wire size includes the 4-byte run/idle header in Class 1.
    uint16_t ot_conn_size = static_cast<uint16_t>(4 + config.consumed_size);
    uint16_t to_conn_size = config.produced_size;
    uint16_t ot_params = static_cast<uint16_t>(0x4200 | (ot_conn_size & 0x01FF));  // P2P + variable
    uint16_t to_params = static_cast<uint16_t>(0x4200 | (to_conn_size & 0x01FF));

    // P2P: originator chooses T->O conn ID.
    uint32_t to_conn_id = 0x10000000u | conn_serial;

    std::vector<uint8_t> fo(36 + path.size());
    int off = 0;
    fo[off++] = 0x0A; fo[off++] = 0x05;
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), 0u);          off += 4;  // OT conn ID (target chooses)
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), to_conn_id);  off += 4;  // TO conn ID (we choose)
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), conn_serial); off += 2;
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), orig_vendor); off += 2;
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), orig_serial); off += 4;
    fo[off++] = config.timeout_multiplier;
    off += 3;  // reserved
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), config.rpi); off += 4;
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), ot_params);  off += 2;
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), config.rpi); off += 4;
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), to_params);  off += 2;
    fo[off++] = config.transport_class;
    fo[off++] = static_cast<uint8_t>(path.size() / 2);
    std::memcpy(fo.data() + off, path.data(), path.size());

    // CM path = Class 0x06 / Instance 1.
    std::array<uint8_t, 4> cm_path{0x20, 0x06, 0x24, 0x01};
    auto raw = send_explicit_raw(0x54, cm_path, fo);
    if (!raw.response.status.is_success()) {
        throw std::runtime_error("Forward Open failed: status 0x"
            + std::to_string(static_cast<unsigned>(raw.response.status.general_status)));
    }
    if (raw.response.data.size() < 8) {
        throw std::runtime_error("Forward Open: response too short");
    }
    uint32_t resp_ot = ser::read_udint(raw.response.data);
    uint32_t resp_to = ser::read_udint(std::span<const uint8_t>(raw.response.data).subspan(4));

    // Target's UDP endpoint comes from Sockaddr Info O->T (item 0x8000).
    IpEndpoint target_udp{remote_endpoint_.host, EipUdpTransport::IoPort};
    for (const auto& item : raw.cpf_items) {
        if (item.type_id == cip::CpfItemType::SockaddrInfoOtoT && item.data.size() >= 8) {
            uint16_t port = static_cast<uint16_t>((item.data[2] << 8) | item.data[3]);
            char ip[64];
            std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                          item.data[4], item.data[5], item.data[6], item.data[7]);
            std::string ip_str(ip);
            if (ip_str != "0.0.0.0") {
                target_udp = IpEndpoint{ip_str, port};
            } else {
                target_udp.port = port;
            }
            break;
        }
    }

    auto conn = std::unique_ptr<ScannerConnection>(new ScannerConnection(
        *this, *udp_transport_, config, target_udp,
        resp_ot, resp_to, conn_serial, orig_vendor, orig_serial));
    conn->start();
    return conn;
}

std::unique_ptr<ConnectedExplicit> EipScanner::open_explicit() {
    if (!is_connected()) {
        throw std::runtime_error("EipScanner: not connected");
    }
    uint16_t conn_serial = next_conn_serial_.fetch_add(1);
    uint16_t orig_vendor = 0x0001;  // Rockwell
    uint32_t orig_serial = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    // Class 3 messaging connection — talks to the Message Router (class 2,
    // instance 1) on the target. Originator picks the T->O conn ID; target
    // assigns the O->T conn ID in its reply.
    std::array<uint8_t, 4> app_path{0x20, 0x02, 0x24, 0x01};
    uint32_t to_conn_id = 0x80000000u | conn_serial;

    // Network params for Class 3 explicit: P2P (bits 14-13 = 10b), priority
    // = high (bits 12-10 = 010b), fixed size (bit 9 = 0), size = 504 bytes
    // (bits 8-0). Matches what Logix MSG instructions and pycomm3 use.
    uint16_t net_params = 0x43F8;
    // Transport class trigger 0xA3 = server direction, application trigger,
    // class 3 (same as Logix scanner FwdOpen).
    uint8_t  transport  = 0xA3;
    uint32_t rpi        = 2500000;  // 2.5 s

    std::vector<uint8_t> fo(36 + app_path.size());
    int off = 0;
    fo[off++] = 0x07; fo[off++] = 0x09;                                   // priority/tick + timeout_ticks
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), 0u);           off += 4;  // OT conn ID (target picks)
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), to_conn_id);   off += 4;  // TO conn ID (we pick)
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), conn_serial);  off += 2;
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), orig_vendor);  off += 2;
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), orig_serial);  off += 4;
    fo[off++] = 0x03;                                                     // conn timeout multiplier (=x32)
    off += 3;                                                              // reserved
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), rpi);          off += 4;
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), net_params);   off += 2;
    ser::write_udint(std::span<uint8_t>(fo).subspan(off), rpi);          off += 4;
    ser::write_uint (std::span<uint8_t>(fo).subspan(off), net_params);   off += 2;
    fo[off++] = transport;
    fo[off++] = static_cast<uint8_t>(app_path.size() / 2);
    std::memcpy(fo.data() + off, app_path.data(), app_path.size());

    std::array<uint8_t, 4> cm_path{0x20, 0x06, 0x24, 0x01};
    auto raw = send_explicit_raw(0x54, cm_path, fo);
    if (!raw.response.status.is_success()) {
        throw std::runtime_error("Class 3 Forward Open failed: status 0x"
            + std::to_string(static_cast<unsigned>(raw.response.status.general_status)));
    }
    if (raw.response.data.size() < 8) {
        throw std::runtime_error("Class 3 Forward Open: response too short");
    }
    uint32_t resp_ot = ser::read_udint(raw.response.data);
    uint32_t resp_to = ser::read_udint(std::span<const uint8_t>(raw.response.data).subspan(4));

    return std::unique_ptr<ConnectedExplicit>(new ConnectedExplicit(
        *this, resp_ot, resp_to, conn_serial, orig_vendor, orig_serial));
}

cip::CipServiceResponse EipScanner::send_connected_mr(uint32_t oto_t_connection_id,
                                                        uint16_t seq_count,
                                                        uint8_t service_code,
                                                        std::span<const uint8_t> path_bytes,
                                                        std::span<const uint8_t> service_data) {
    if (!is_connected()) {
        throw std::runtime_error("EipScanner: not connected");
    }
    // Build MR request.
    std::vector<uint8_t> mr(2u + path_bytes.size() + service_data.size());
    int mr_len = cip::mr_codec::encode_request(mr, service_code, path_bytes, service_data);
    mr.resize(mr_len);

    // ConnectedData payload = seq(2) + MR request.
    std::vector<uint8_t> cd(2u + mr.size());
    ser::write_uint(cd, seq_count);
    std::memcpy(cd.data() + 2, mr.data(), mr.size());

    // SendUnitData payload =
    //   InterfaceHandle(4) + Timeout(2) + CPF { ConnectedAddress(0xA1) + ConnectedData(0xB1) }.
    std::vector<uint8_t> payload(6 + 2 + 4 + 4 + 4 + cd.size(), 0);
    int o = 6;
    ser::write_uint (std::span<uint8_t>(payload).subspan(o), uint16_t{2});                    o += 2;  // item count
    ser::write_uint (std::span<uint8_t>(payload).subspan(o), uint16_t{0x00A1});               o += 2;  // ConnectedAddress
    ser::write_uint (std::span<uint8_t>(payload).subspan(o), uint16_t{4});                    o += 2;  // addr length
    ser::write_udint(std::span<uint8_t>(payload).subspan(o), oto_t_connection_id);            o += 4;
    ser::write_uint (std::span<uint8_t>(payload).subspan(o), uint16_t{0x00B1});               o += 2;  // ConnectedData
    ser::write_uint (std::span<uint8_t>(payload).subspan(o), static_cast<uint16_t>(cd.size())); o += 2;
    std::memcpy(payload.data() + o, cd.data(), cd.size());

    auto resp = send_encapsulated(static_cast<uint16_t>(EncapsulationCommand::SendUnitData), payload);

    // Skip 6-byte preamble, parse CPF, pull ConnectedData -> seq + MR response.
    if (resp.size() < 8) {
        throw std::runtime_error("EipScanner: SendUnitData reply too short");
    }
    size_t off = 6;
    uint16_t item_count = ser::read_uint(std::span<const uint8_t>(resp).subspan(off)); off += 2;
    for (uint16_t i = 0; i < item_count; ++i) {
        if (off + 4 > resp.size()) break;
        uint16_t type_id = ser::read_uint(std::span<const uint8_t>(resp).subspan(off)); off += 2;
        uint16_t len     = ser::read_uint(std::span<const uint8_t>(resp).subspan(off)); off += 2;
        if (off + len > resp.size()) break;
        if (type_id == 0x00B1 && len >= 2) {
            // Strip the 2-byte sequence count, then parse the MR response.
            auto inner = std::span<const uint8_t>(resp.data() + off + 2, len - 2);
            auto parsed = cip::mr_codec::try_parse_response(inner);
            if (!parsed.has_value()) {
                throw std::runtime_error("EipScanner: malformed MR response");
            }
            cip::CipServiceResponse out;
            out.service_code = parsed->reply_service;
            out.status       = std::move(parsed->status);
            out.data         = std::move(parsed->data);
            return out;
        }
        off += len;
    }
    throw std::runtime_error("EipScanner: no ConnectedData item in reply");
}

void EipScanner::forward_close(uint16_t connection_serial,
                                 uint16_t originator_vendor,
                                 uint32_t originator_serial) {
    std::array<uint8_t, 12> close_data{};
    close_data[0] = 0x0A; close_data[1] = 0x05;
    ser::write_uint (std::span<uint8_t>(close_data).subspan(2),  connection_serial);
    ser::write_uint (std::span<uint8_t>(close_data).subspan(4),  originator_vendor);
    ser::write_udint(std::span<uint8_t>(close_data).subspan(6),  originator_serial);
    close_data[10] = 0; close_data[11] = 0;
    std::array<uint8_t, 4> cm_path{0x20, 0x06, 0x24, 0x01};
    try {
        (void)send_explicit(0x4E, cm_path, close_data);
    } catch (...) {
        // best effort
    }
}

void EipScanner::register_udp_route(uint32_t tto_o_connection_id, UdpRouteHandler h) {
    std::scoped_lock lock(routes_mu_);
    routes_[tto_o_connection_id] = std::move(h);
}

void EipScanner::unregister_udp_route(uint32_t tto_o_connection_id) {
    std::scoped_lock lock(routes_mu_);
    routes_.erase(tto_o_connection_id);
}

void EipScanner::on_udp_message_dispatch(std::unique_ptr<messages::Message> msg) {
    if (msg->kind != messages::MessageKind::CpfConnectedData) return;
    auto& cpf = static_cast<messages::CpfConnectedDataMessage&>(*msg);
    UdpRouteHandler h;
    {
        std::scoped_lock lock(routes_mu_);
        auto it = routes_.find(cpf.connection_id);
        if (it == routes_.end()) return;
        h = it->second;
    }
    if (h) h(*msg);
}

} // namespace ethernetip::protocol
