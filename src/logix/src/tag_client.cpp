#include "ethernetip/logix/tag_client.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/cip/encapsulation.hpp"
#include "ethernetip/cip/mr_codec.hpp"
#include "ethernetip/protocol/cpf_helpers.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>

namespace ethernetip::logix {

namespace ser  = cip::serializer;
namespace sock = protocol::sock;
using cip::EncapsulationCommand;
using cip::EncapsulationHeader;
using cip::EncapsulationStatus;

TagClient::TagClient(std::string host, int port)
    : host_(std::move(host)), port_(port) {}

TagClient::~TagClient() {
    disconnect();
}

bool TagClient::is_connected() const noexcept {
    return socket_ != sock::invalid && session_handle_ != 0;
}

void TagClient::connect() {
    sock::ensure_initialized();
    if (socket_ != sock::invalid) {
        throw std::runtime_error("TagClient: already connected");
    }

    sock::socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == sock::invalid) {
        throw std::runtime_error("TagClient: socket() failed");
    }
    sockaddr_in addr{};
    protocol::sock::to_sockaddr(protocol::IpEndpoint{host_, static_cast<uint16_t>(port_)}, addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == sock::sockerr) {
        int err = sock::last_error();
        sock::close(s);
        throw std::runtime_error("TagClient: connect to " + host_ + " failed (err " + std::to_string(err) + ")");
    }
    socket_ = s;

    // RegisterSession: payload = protocol_version(2) + options_flags(2)
    std::array<uint8_t, 4> payload{1, 0, 0, 0};
    auto reply = send_encapsulated(static_cast<uint16_t>(EncapsulationCommand::RegisterSession),
                                     std::span<const uint8_t>(payload.data(), payload.size()));
    (void)reply;  // session handle is captured inside send_encapsulated
    if (session_handle_ == 0) {
        throw std::runtime_error("TagClient: RegisterSession returned session handle 0");
    }
}

void TagClient::disconnect() noexcept {
    if (socket_ == sock::invalid) return;
    if (session_handle_ != 0) {
        try {
            // UnregisterSession is fire-and-forget — no reply expected.
            std::array<uint8_t, EncapsulationHeader::Size> buf{};
            EncapsulationHeader hdr;
            hdr.command        = EncapsulationCommand::UnregisterSession;
            hdr.session_handle = session_handle_;
            hdr.write_to(buf);
            (void)::send(socket_, reinterpret_cast<const char*>(buf.data()),
                          static_cast<int>(buf.size()), 0);
        } catch (...) {
            // swallow — we're closing anyway
        }
    }
    sock::close(socket_);
    socket_         = sock::invalid;
    session_handle_ = 0;
}

void TagClient::read_exact(uint8_t* dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        int chunk = ::recv(socket_, reinterpret_cast<char*>(dst + got),
                            static_cast<int>(n - got), 0);
        if (chunk == 0) {
            throw std::runtime_error("TagClient: connection closed by peer");
        }
        if (chunk == sock::sockerr) {
            throw std::runtime_error("TagClient: recv failed (err "
                + std::to_string(sock::last_error()) + ")");
        }
        got += static_cast<size_t>(chunk);
    }
}

std::vector<uint8_t> TagClient::send_encapsulated(uint16_t command,
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
        throw std::runtime_error("TagClient: send failed (err "
            + std::to_string(sock::last_error()) + ")");
    }

    std::array<uint8_t, EncapsulationHeader::Size> rhdr_buf{};
    read_exact(rhdr_buf.data(), rhdr_buf.size());
    auto rhdr = EncapsulationHeader::parse(rhdr_buf);
    if (rhdr.session_handle != 0 && session_handle_ == 0) {
        session_handle_ = rhdr.session_handle;
    }
    if (rhdr.status != EncapsulationStatus::Success) {
        throw std::runtime_error("TagClient: encapsulation error 0x"
            + std::to_string(static_cast<uint32_t>(rhdr.status)));
    }
    std::vector<uint8_t> body(rhdr.length);
    if (rhdr.length > 0) read_exact(body.data(), body.size());
    return body;
}

std::pair<uint8_t, std::vector<uint8_t>>
TagClient::send_cip_with_status(uint8_t service_code,
                                  std::span<const uint8_t> cip_path,
                                  std::span<const uint8_t> service_data) {
    // Build MR request: service(1) + path_size_words(1) + path + data
    int path_words = static_cast<int>(cip_path.size()) / 2;
    std::vector<uint8_t> mr(2u + cip_path.size() + service_data.size());
    mr[0] = service_code;
    mr[1] = static_cast<uint8_t>(path_words);
    std::memcpy(mr.data() + 2, cip_path.data(), cip_path.size());
    std::memcpy(mr.data() + 2 + cip_path.size(), service_data.data(), service_data.size());

    // CPF: NullAddress(0x0000) + UnconnectedData(0x00B2)
    protocol::cpf_helpers::CpfBuilder cpf;
    cpf.add_item(0x0000, std::span<const uint8_t>());
    cpf.add_item(0x00B2, mr);
    auto cpf_bytes = cpf.build();

    // SendRRData payload: interface_handle(4) + timeout(2) + CPF
    std::vector<uint8_t> payload(6 + cpf_bytes.size(), 0);
    std::memcpy(payload.data() + 6, cpf_bytes.data(), cpf_bytes.size());

    auto resp = send_encapsulated(static_cast<uint16_t>(EncapsulationCommand::SendRRData), payload);

    // Skip interface_handle + timeout = 6 bytes, parse CPF.
    if (resp.size() < 8) {
        throw std::runtime_error("TagClient: SendRRData reply too short");
    }
    size_t off = 6;
    uint16_t item_count = ser::read_uint(std::span<const uint8_t>(resp).subspan(off)); off += 2;
    for (uint16_t i = 0; i < item_count; ++i) {
        if (off + 4 > resp.size()) break;
        uint16_t type_id = ser::read_uint(std::span<const uint8_t>(resp).subspan(off)); off += 2;
        uint16_t len     = ser::read_uint(std::span<const uint8_t>(resp).subspan(off)); off += 2;
        if (off + len > resp.size()) break;
        if (type_id == 0x00B2) {  // UnconnectedData — the inner MR response.
            auto inner = std::span<const uint8_t>(resp.data() + off, len);
            auto parsed = cip::mr_codec::try_parse_response(inner);
            if (!parsed.has_value()) {
                throw std::runtime_error("TagClient: malformed MR response");
            }
            return {parsed->status.general_status, std::move(parsed->data)};
        }
        off += len;
    }
    throw std::runtime_error("TagClient: no UnconnectedData item in reply");
}

std::vector<uint8_t> TagClient::send_cip(uint8_t service_code,
                                          std::span<const uint8_t> cip_path,
                                          std::span<const uint8_t> service_data) {
    auto [status, data] = send_cip_with_status(service_code, cip_path, service_data);
    if (status != 0x00 && status != 0x06) {  // 0x06 = "more data" still has valid bytes
        throw std::runtime_error("TagClient: CIP error 0x"
            + std::to_string(static_cast<unsigned>(status))
            + " for service 0x" + std::to_string(static_cast<unsigned>(service_code)));
    }
    return data;
}

// ---- Tag read/write ----

std::vector<uint8_t> TagClient::read_tag_raw(std::string_view tag_name,
                                              uint16_t element_count) {
    auto path = build_tag_path(tag_name);
    std::array<uint8_t, 2> req{};
    ser::write_uint(req, element_count);
    return send_cip(0x4C /*Read_Tag*/, path, req);
}

void TagClient::write_raw(std::string_view tag_name, uint16_t tag_type,
                           uint16_t element_count, std::span<const uint8_t> value) {
    auto path = build_tag_path(tag_name);
    std::vector<uint8_t> req(4 + value.size());
    ser::write_uint(req,                                       tag_type);
    ser::write_uint(std::span<uint8_t>(req).subspan(2),       element_count);
    if (!value.empty()) std::memcpy(req.data() + 4, value.data(), value.size());
    (void)send_cip(0x4D /*Write_Tag*/, path, req);
}

// ---- Logix STRING (Logix STRING is a UDT, NOT CIP STRING 0xD0) ----

std::string TagClient::read_string(std::string_view tag_name) {
    auto raw = read_tag_raw(tag_name, 1);
    // Layout: tag_type(2) + struct_handle(2) + LEN(DINT) + DATA(82) + pad
    constexpr int header = 4;
    if (raw.size() < header + logix_data_types::StringDataOffset) return "";
    int32_t len = 0;
    std::memcpy(&len, raw.data() + header + logix_data_types::StringLenOffset, 4);
    if (len <= 0) return "";
    int max_len = std::min<int>(len,
        std::min<int>(logix_data_types::StringMaxLength,
                       static_cast<int>(raw.size()) - header - logix_data_types::StringDataOffset));
    return std::string(reinterpret_cast<const char*>(raw.data() + header + logix_data_types::StringDataOffset),
                         max_len);
}

void TagClient::write_string(std::string_view tag_name, std::string_view value,
                               uint16_t structure_handle) {
    std::vector<uint8_t> struct_data(logix_data_types::StringStructureSize, 0);
    int len = std::min<int>(static_cast<int>(value.size()), logix_data_types::StringMaxLength);
    int32_t len32 = len;
    std::memcpy(struct_data.data(), &len32, 4);
    if (len > 0) {
        std::memcpy(struct_data.data() + logix_data_types::StringDataOffset, value.data(), len);
    }
    write_struct(tag_name, structure_handle, 1, struct_data);
}

void TagClient::write_struct(std::string_view tag_name, uint16_t structure_handle,
                               uint16_t element_count, std::span<const uint8_t> value) {
    // Structure write: tag_type(2) = 0x02A0 + struct_handle(2) + element_count(2) + data
    auto path = build_tag_path(tag_name);
    std::vector<uint8_t> req(6 + value.size());
    ser::write_uint(req,                                  uint16_t{0x02A0});
    ser::write_uint(std::span<uint8_t>(req).subspan(2),  structure_handle);
    ser::write_uint(std::span<uint8_t>(req).subspan(4),  element_count);
    if (!value.empty()) std::memcpy(req.data() + 6, value.data(), value.size());
    (void)send_cip(0x4D, path, req);
}

std::vector<uint8_t> TagClient::read_struct_bytes(std::string_view tag_name) {
    // Read_Tag (0x4C) is single-shot and the controller silently drops the
    // body when the reply would exceed its packet limit. Use Read_Tag_Fragmented
    // (0x52) in a loop. First fragment carries tag_type(2)+struct_handle(2);
    // subsequent fragments carry just tag_type(2).
    auto path = build_tag_path(tag_name);
    std::vector<uint8_t> out;
    uint32_t byte_offset = 0;
    bool first = true;

    while (true) {
        std::array<uint8_t, 6> req{};
        ser::write_uint(req,                                    1);            // element_count
        ser::write_udint(std::span<uint8_t>(req).subspan(2),   byte_offset);   // byte offset

        auto [status, data] = send_cip_with_status(0x52, path, req);
        if (status != 0x00 && status != 0x06) {
            throw std::runtime_error("read_struct_bytes: CIP status 0x"
                                       + std::to_string(static_cast<int>(status)));
        }

        size_t header_size = first ? 4u : 2u;
        if (data.size() <= header_size) break;
        size_t added = data.size() - header_size;
        out.insert(out.end(), data.begin() + header_size, data.end());
        byte_offset += static_cast<uint32_t>(added);
        first = false;

        if (status == 0x00) break;
    }
    return out;
}

// ---- Multiple Service Packet (0x0A) ----

namespace {
// Build an MR sub-request (service + path + data) for embedding inside a
// Multiple Service Packet.
std::vector<uint8_t> build_mr_sub_request(uint8_t service_code,
                                            std::span<const uint8_t> path,
                                            std::span<const uint8_t> data) {
    std::vector<uint8_t> mr(2u + path.size() + data.size());
    mr[0] = service_code;
    mr[1] = static_cast<uint8_t>(path.size() / 2);
    std::memcpy(mr.data() + 2, path.data(), path.size());
    if (!data.empty()) std::memcpy(mr.data() + 2 + path.size(), data.data(), data.size());
    return mr;
}

// Send the assembled Multiple Service Packet and return per-subreq (status, data).
// Throws on encapsulation / outer CIP error.
} // namespace

std::map<std::string, std::vector<uint8_t>>
TagClient::read_multiple(const std::vector<std::string>& tag_names) {
    std::map<std::string, std::vector<uint8_t>> result;
    if (tag_names.empty()) return result;

    // Each sub-request is a Read Tag (0x4C) with element_count = 1.
    std::vector<std::vector<uint8_t>> subs;
    subs.reserve(tag_names.size());
    for (const auto& n : tag_names) {
        auto path = build_tag_path(n);
        std::array<uint8_t, 2> req{0x01, 0x00};
        subs.push_back(build_mr_sub_request(0x4C, path, req));
    }

    // Aggregate Multiple Service Packet body: count(2) + offsets[](2 each) + subs.
    size_t header = 2 + subs.size() * 2;
    size_t total  = header;
    for (const auto& s : subs) total += s.size();
    std::vector<uint8_t> body(total);
    ser::write_uint(body, static_cast<uint16_t>(subs.size()));
    size_t off = 2;
    size_t cur = header;
    for (const auto& s : subs) {
        ser::write_uint(std::span<uint8_t>(body).subspan(off),
                         static_cast<uint16_t>(cur));
        off += 2;
        cur += s.size();
    }
    size_t data_off = header;
    for (const auto& s : subs) {
        std::memcpy(body.data() + data_off, s.data(), s.size());
        data_off += s.size();
    }

    // Send to Message Router (Class 0x02, Instance 1) with service 0x0A.
    std::array<uint8_t, 4> mr_path{0x20, 0x02, 0x24, 0x01};
    auto [outer_status, resp] = send_cip_with_status(0x0A, mr_path, body);
    if (outer_status != 0x00) {
        // 0x1E = "embedded service error" — partial result still parseable.
        if (outer_status != 0x1E) {
            throw std::runtime_error("read_multiple: outer status 0x"
                + std::to_string(static_cast<unsigned>(outer_status)));
        }
    }
    if (resp.size() < 2) return result;

    uint16_t resp_count = ser::read_uint(resp);
    if (resp_count == 0) return result;
    std::vector<uint16_t> offsets(resp_count);
    if (resp.size() < static_cast<size_t>(2 + resp_count * 2)) return result;
    for (uint16_t i = 0; i < resp_count; ++i) {
        offsets[i] = ser::read_uint(std::span<const uint8_t>(resp).subspan(2u + i * 2u));
    }

    for (uint16_t i = 0; i < resp_count && i < tag_names.size(); ++i) {
        size_t start = offsets[i];
        size_t end   = (i + 1 < resp_count) ? offsets[i + 1] : resp.size();
        if (start + 4 > resp.size() || end > resp.size() || start > end) continue;
        // MR response: reply_service(1) + reserved(1) + general_status(1) + addl_size(1) + addl(2*N) + data.
        uint8_t sub_status = resp[start + 2];
        uint8_t addl_size  = resp[start + 3];
        size_t data_start  = start + 4 + static_cast<size_t>(addl_size) * 2;
        if (sub_status == 0x00 || sub_status == 0x06) {
            if (data_start < end) {
                result.emplace(tag_names[i],
                                std::vector<uint8_t>(resp.begin() + data_start, resp.begin() + end));
            } else {
                result.emplace(tag_names[i], std::vector<uint8_t>{});
            }
        }
    }
    return result;
}

std::map<std::string, uint8_t>
TagClient::write_multiple(const std::vector<WriteEntry>& writes) {
    std::map<std::string, uint8_t> result;
    if (writes.empty()) return result;

    std::vector<std::vector<uint8_t>> subs;
    subs.reserve(writes.size());
    for (const auto& w : writes) {
        auto path = build_tag_path(w.name);
        std::vector<uint8_t> data(4 + w.value.size());
        ser::write_uint(data,                                  w.tag_type);
        ser::write_uint(std::span<uint8_t>(data).subspan(2),  w.element_count);
        if (!w.value.empty()) {
            std::memcpy(data.data() + 4, w.value.data(), w.value.size());
        }
        subs.push_back(build_mr_sub_request(0x4D, path, data));
    }

    size_t header = 2 + subs.size() * 2;
    size_t total  = header;
    for (const auto& s : subs) total += s.size();
    std::vector<uint8_t> body(total);
    ser::write_uint(body, static_cast<uint16_t>(subs.size()));
    size_t off = 2;
    size_t cur = header;
    for (const auto& s : subs) {
        ser::write_uint(std::span<uint8_t>(body).subspan(off),
                         static_cast<uint16_t>(cur));
        off += 2;
        cur += s.size();
    }
    size_t data_off = header;
    for (const auto& s : subs) {
        std::memcpy(body.data() + data_off, s.data(), s.size());
        data_off += s.size();
    }

    std::array<uint8_t, 4> mr_path{0x20, 0x02, 0x24, 0x01};
    auto [outer_status, resp] = send_cip_with_status(0x0A, mr_path, body);
    if (outer_status != 0x00 && outer_status != 0x1E) {
        throw std::runtime_error("write_multiple: outer status 0x"
            + std::to_string(static_cast<unsigned>(outer_status)));
    }
    if (resp.size() < 2) return result;
    uint16_t resp_count = ser::read_uint(resp);
    if (resp_count == 0) return result;
    std::vector<uint16_t> offsets(resp_count);
    if (resp.size() < static_cast<size_t>(2 + resp_count * 2)) return result;
    for (uint16_t i = 0; i < resp_count; ++i) {
        offsets[i] = ser::read_uint(std::span<const uint8_t>(resp).subspan(2u + i * 2u));
    }
    for (uint16_t i = 0; i < resp_count && i < writes.size(); ++i) {
        size_t start = offsets[i];
        if (start + 3 > resp.size()) continue;
        uint8_t sub_status = resp[start + 2];
        result.emplace(writes[i].name, sub_status);
    }
    return result;
}

// ---- Browse + Template ----

std::vector<TagInfo> TagClient::browse(std::optional<std::string_view> program) {
    std::vector<TagInfo> tags;
    uint32_t start_instance = 0;

    // Optional program-scope prefix: ANSI Extended Symbolic segment of the
    // form "Program:<name>". Prepended to every paginated request.
    std::vector<uint8_t> prefix;
    if (program.has_value() && !program->empty()) {
        size_t n   = program->size();
        size_t pad = (n % 2 == 0) ? 0 : 1;
        prefix.resize(2 + n + pad);
        prefix[0] = 0x91;
        prefix[1] = static_cast<uint8_t>(n);
        std::memcpy(prefix.data() + 2, program->data(), n);
    }

    while (true) {
        // Path: [optional program prefix] + class 0x6B (Symbol) + instance (16-bit).
        std::array<uint8_t, 6> class_inst{};
        class_inst[0] = 0x20; class_inst[1] = 0x6B;
        class_inst[2] = 0x25; class_inst[3] = 0x00;
        ser::write_uint(std::span<uint8_t>(class_inst).subspan(4),
                         static_cast<uint16_t>(start_instance));

        std::vector<uint8_t> path(prefix.size() + class_inst.size());
        if (!prefix.empty()) std::memcpy(path.data(), prefix.data(), prefix.size());
        std::memcpy(path.data() + prefix.size(), class_inst.data(), class_inst.size());

        // Request: attr_count + attr_id[] — ask for [name, type].
        std::array<uint8_t, 6> req{};
        ser::write_uint(req,                                  uint16_t{2});
        ser::write_uint(std::span<uint8_t>(req).subspan(2),  uint16_t{1}); // Symbol Name
        ser::write_uint(std::span<uint8_t>(req).subspan(4),  uint16_t{2}); // Symbol Type

        auto [status, data] = send_cip_with_status(0x55, path, req);
        if (status != 0x00 && status != 0x06) break;

        size_t off = 0;
        while (off + 6 < data.size()) {
            uint32_t inst_id = ser::read_udint(std::span<const uint8_t>(data).subspan(off)); off += 4;
            uint16_t name_len = ser::read_uint (std::span<const uint8_t>(data).subspan(off)); off += 2;
            if (off + name_len + 2 > data.size()) break;
            std::string name(reinterpret_cast<const char*>(data.data() + off), name_len);
            off += name_len;
            uint16_t sym_type = ser::read_uint(std::span<const uint8_t>(data).subspan(off)); off += 2;

            TagInfo info;
            info.name             = std::move(name);
            info.instance_id      = inst_id;
            info.symbol_type      = sym_type;
            info.is_struct        = (sym_type & 0x8000) != 0;
            info.is_system        = (sym_type & 0x1000) != 0;
            info.array_dimensions = (sym_type >> 13) & 0x03;
            info.type_code        = static_cast<uint16_t>(sym_type & 0x0FFF);

            // Populate the instance-ID cache used by build_tag_path. Skip
            // system tags and internal __-prefixed names (Logix uses these
            // for default values, containers, etc — not user-addressable).
            if (!info.is_system && info.name.rfind("__", 0) != 0) {
                if (program.has_value() && !program->empty()) {
                    program_atoms_[{std::string(*program), info.name}] = info.instance_id;
                } else {
                    controller_atoms_[info.name] = info.instance_id;
                }
            }

            tags.push_back(std::move(info));
            start_instance = inst_id;
        }

        if (status == 0x00) break;
        ++start_instance;
    }
    return tags;
}

TemplateInfo TagClient::read_template(uint16_t template_instance_id) {
    // Step 1: GetAttributeList — handle, member count, def size, struct size.
    std::array<uint8_t, 6> attr_path{};
    attr_path[0] = 0x20; attr_path[1] = 0x6C; // Class 0x6C (Template)
    attr_path[2] = 0x25; attr_path[3] = 0x00;
    ser::write_uint(std::span<uint8_t>(attr_path).subspan(4), template_instance_id);

    std::array<uint8_t, 10> attr_req{};
    ser::write_uint(attr_req,                                  uint16_t{4});
    ser::write_uint(std::span<uint8_t>(attr_req).subspan(2),  uint16_t{1});  // handle
    ser::write_uint(std::span<uint8_t>(attr_req).subspan(4),  uint16_t{2});  // member count
    ser::write_uint(std::span<uint8_t>(attr_req).subspan(6),  uint16_t{4});  // def size
    ser::write_uint(std::span<uint8_t>(attr_req).subspan(8),  uint16_t{5});  // struct size

    auto attr_data = send_cip(0x03 /*GetAttributeList*/, attr_path, attr_req);

    TemplateInfo info;
    info.instance_id = template_instance_id;

    size_t off = 2;  // skip count
    for (int i = 0; i < 4 && off + 4 <= attr_data.size(); ++i) {
        uint16_t attr_id     = ser::read_uint(std::span<const uint8_t>(attr_data).subspan(off)); off += 2;
        uint16_t attr_status = ser::read_uint(std::span<const uint8_t>(attr_data).subspan(off)); off += 2;
        if (attr_status != 0) continue;
        switch (attr_id) {
            case 1: info.structure_handle = ser::read_uint (std::span<const uint8_t>(attr_data).subspan(off)); off += 2; break;
            case 2: info.member_count     = ser::read_uint (std::span<const uint8_t>(attr_data).subspan(off)); off += 2; break;
            case 4: info.definition_size  = ser::read_udint(std::span<const uint8_t>(attr_data).subspan(off)); off += 4; break;
            case 5: info.structure_size   = ser::read_udint(std::span<const uint8_t>(attr_data).subspan(off)); off += 4; break;
            default: break;
        }
    }

    // Step 2: Template_Read (0x4C) with fragmentation. Total size to fetch
    // is definition_size_words * 4 - 23 (Rockwell convention).
    int read_size = static_cast<int>(info.definition_size) * 4 - 23;
    if (read_size <= 0) read_size = 256;

    std::vector<uint8_t> all;
    uint32_t read_off = 0;
    while (true) {
        std::array<uint8_t, 6> req{};
        ser::write_udint(req, read_off);
        int remaining = read_size - static_cast<int>(read_off);
        if (remaining <= 0) break;
        ser::write_uint(std::span<uint8_t>(req).subspan(4),
                         static_cast<uint16_t>(std::min<int>(remaining, 0xFFFF)));
        auto [status, chunk] = send_cip_with_status(0x4C, attr_path, req);
        if (status != 0x00 && status != 0x06) break;
        all.insert(all.end(), chunk.begin(), chunk.end());
        read_off += static_cast<uint32_t>(chunk.size());
        if (status == 0x00) break;
    }

    // Parse members: member_count * 8 bytes of (type_and_info, offset), then
    // null-terminated names — first is the template name, then each member.
    size_t p = 0;
    info.members.reserve(info.member_count);
    for (uint16_t i = 0; i < info.member_count && p + 8 <= all.size(); ++i) {
        TemplateMemberDetail m;
        uint32_t type_and_info = ser::read_udint(std::span<const uint8_t>(all).subspan(p)); p += 4;
        m.offset    = ser::read_udint(std::span<const uint8_t>(all).subspan(p)); p += 4;
        m.data_type = static_cast<uint16_t>(type_and_info >> 16);
        m.info      = static_cast<uint16_t>(type_and_info & 0xFFFF);
        info.members.push_back(std::move(m));
    }

    std::vector<std::string> names;
    while (p < all.size()) {
        size_t end = p;
        while (end < all.size() && all[end] != 0) ++end;
        if (end > p) names.emplace_back(reinterpret_cast<const char*>(all.data() + p), end - p);
        else if (end == p) {  // empty string before terminator — still consume
            names.emplace_back();
        }
        p = end + 1;
        if (end == all.size()) break;
    }
    if (!names.empty()) info.name = std::move(names[0]);
    for (size_t i = 0; i < info.members.size() && i + 1 < names.size(); ++i) {
        info.members[i].name = std::move(names[i + 1]);
    }
    return info;
}

// ---- Symbolic path builder ----

namespace {

void emit_symbolic_into(std::vector<uint8_t>& path, std::string_view part) {
    size_t n = part.size();
    path.push_back(0x91);
    path.push_back(static_cast<uint8_t>(n));
    path.insert(path.end(), part.begin(), part.end());
    if (n % 2 != 0) path.push_back(0);
}

void emit_element_into(std::vector<uint8_t>& path, uint32_t v) {
    if (v <= 0xFF) {
        path.push_back(0x28);
        path.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xFFFF) {
        path.push_back(0x29); path.push_back(0x00);
        path.push_back(static_cast<uint8_t>(v));
        path.push_back(static_cast<uint8_t>(v >> 8));
    } else {
        path.push_back(0x2A); path.push_back(0x00);
        for (int i = 0; i < 4; ++i)
            path.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
}

void emit_symbol_instance_into(std::vector<uint8_t>& path, uint32_t inst) {
    // Logical Class 0x6B + 16-bit Instance.
    path.push_back(0x20); path.push_back(0x6B);
    path.push_back(0x25); path.push_back(0x00);
    path.push_back(static_cast<uint8_t>(inst & 0xFF));
    path.push_back(static_cast<uint8_t>((inst >> 8) & 0xFF));
}

// Parse a comma-separated index list (e.g. "1,2,3" or "0x10,2").
// Returns true if every element parses cleanly as an unsigned integer.
bool parse_indices(std::string_view s, std::vector<uint32_t>& out) {
    out.clear();
    size_t start = 0;
    while (start <= s.size()) {
        size_t comma = s.find(',', start);
        std::string_view tok = s.substr(start,
            (comma == std::string_view::npos ? s.size() : comma) - start);
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t')) tok.remove_prefix(1);
        while (!tok.empty() && (tok.back()  == ' ' || tok.back()  == '\t')) tok.remove_suffix(1);
        if (tok.empty()) return false;
        uint32_t v = 0;
        int base = 10;
        size_t k = 0;
        if (tok.size() >= 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
            base = 16; k = 2;
            if (k >= tok.size()) return false;
        }
        for (; k < tok.size(); ++k) {
            char c = tok[k];
            int d;
            if      (c >= '0' && c <= '9') d = c - '0';
            else if (base == 16 && c >= 'a' && c <= 'f') d = 10 + (c - 'a');
            else if (base == 16 && c >= 'A' && c <= 'F') d = 10 + (c - 'A');
            else return false;
            if (d >= base) return false;
            v = v * static_cast<uint32_t>(base) + static_cast<uint32_t>(d);
        }
        out.push_back(v);
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return !out.empty();
}

// Split a dotted piece into (base, bracket_groups_in_source_order).
std::pair<std::string_view, std::vector<std::vector<uint32_t>>>
split_brackets(std::string_view piece) {
    std::vector<std::vector<uint32_t>> bracket_groups;
    std::string_view base = piece;
    while (!base.empty() && base.back() == ']') {
        size_t open = base.rfind('[');
        if (open == std::string_view::npos) break;
        std::string_view inside = base.substr(open + 1, base.size() - open - 2);
        std::vector<uint32_t> indices;
        if (!parse_indices(inside, indices)) break;
        bracket_groups.push_back(std::move(indices));
        base = base.substr(0, open);
    }
    std::reverse(bracket_groups.begin(), bracket_groups.end());
    return {base, std::move(bracket_groups)};
}

// Iterate the dotted pieces of a tag name, invoking `fn(piece)` for each.
template <class F>
void for_each_dotted(std::string_view name, F fn) {
    size_t i = 0;
    while (i <= name.size()) {
        size_t dot = name.find('.', i);
        size_t end = (dot == std::string_view::npos) ? name.size() : dot;
        fn(name.substr(i, end - i));
        if (dot == std::string_view::npos) break;
        i = dot + 1;
    }
}

} // namespace

std::vector<uint8_t> TagClient::build_symbolic_path(std::string_view name) {
    std::vector<uint8_t> path;
    path.reserve(name.size() + 8);
    for_each_dotted(name, [&](std::string_view piece) {
        auto [base, groups] = split_brackets(piece);
        if (!base.empty()) emit_symbolic_into(path, base);
        for (const auto& grp : groups)
            for (uint32_t idx : grp) emit_element_into(path, idx);
    });
    return path;
}

std::vector<uint8_t> TagClient::build_tag_path(std::string_view name) const {
    // Split into the head piece and the rest of the dotted suffix.
    size_t first_dot = name.find('.');
    std::string_view head = (first_dot == std::string_view::npos)
                              ? name : name.substr(0, first_dot);
    auto [head_base, head_brackets] = split_brackets(head);
    std::string head_base_str(head_base);

    std::vector<uint8_t> path;
    path.reserve(name.size() + 8);

    // (2) Program-scope drilling: head_base looks like "Program:Foo" and we
    //     have a second piece to look up.
    if (head_base_str.rfind("Program:", 0) == 0 && first_dot != std::string_view::npos) {
        // Find second-piece end (next dot or end of name).
        size_t second_start = first_dot + 1;
        size_t second_dot = name.find('.', second_start);
        std::string_view second = (second_dot == std::string_view::npos)
                                    ? name.substr(second_start)
                                    : name.substr(second_start, second_dot - second_start);
        auto [leaf_base, leaf_brackets] = split_brackets(second);
        auto it = program_atoms_.find({head_base_str, std::string(leaf_base)});
        if (it != program_atoms_.end()) {
            emit_symbolic_into(path, head_base_str);
            for (const auto& grp : head_brackets)
                for (uint32_t idx : grp) emit_element_into(path, idx);
            emit_symbol_instance_into(path, it->second);
            for (const auto& grp : leaf_brackets)
                for (uint32_t idx : grp) emit_element_into(path, idx);
            // Emit remaining dotted pieces (after the leaf) as symbolic+element.
            if (second_dot != std::string_view::npos) {
                std::string_view rest = name.substr(second_dot + 1);
                for_each_dotted(rest, [&](std::string_view piece) {
                    auto [pb, pgroups] = split_brackets(piece);
                    if (!pb.empty()) emit_symbolic_into(path, pb);
                    for (const auto& grp : pgroups)
                        for (uint32_t idx : grp) emit_element_into(path, idx);
                });
            }
            return path;
        }
        // Leaf not in cache — fall back to symbolic for the entire name.
        return build_symbolic_path(name);
    }

    // (1) Controller-scope root.
    auto it = controller_atoms_.find(head_base_str);
    if (it != controller_atoms_.end()) {
        emit_symbol_instance_into(path, it->second);
        for (const auto& grp : head_brackets)
            for (uint32_t idx : grp) emit_element_into(path, idx);
        if (first_dot != std::string_view::npos) {
            std::string_view rest = name.substr(first_dot + 1);
            for_each_dotted(rest, [&](std::string_view piece) {
                auto [pb, pgroups] = split_brackets(piece);
                if (!pb.empty()) emit_symbolic_into(path, pb);
                for (const auto& grp : pgroups)
                    for (uint32_t idx : grp) emit_element_into(path, idx);
            });
        }
        return path;
    }

    // (3) Cache miss.
    return build_symbolic_path(name);
}

} // namespace ethernetip::logix
