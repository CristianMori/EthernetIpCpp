#include "ethernetip/connections/connection_manager.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/cip/mr_codec.hpp"
#include "ethernetip/cip/standard_services.hpp"
#include "ethernetip/connections/connection_path_parser.hpp"

namespace ethernetip::connections {

using namespace ethernetip::cip;

ConnectionManagerObject::ConnectionManagerObject() {
    cip_class_ = std::make_unique<CipClass>(ClassCode, "Connection Manager", uint16_t{1});
    cip_class_view_ = cip_class_.get();
    cip_class_->add_standard_instance_services();

    // Instance 1 with 8 placeholder counter attributes (matches the C# port —
    // they exist mostly to round out GetAttributeAll responses).
    auto& inst = cip_class_->create_instance(1);
    for (uint16_t i = 1; i <= 8; ++i) {
        inst.add_attribute(CipAttribute::create_uint(
            i, CipDataType::Uint,
            AttributeAccess::GetSingle | AttributeAccess::GetAll, uint16_t{0}));
    }

    cip_class_->add_instance_service({
        ForwardOpenService, "Forward_Open",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_forward_open(i, r);
        }});
    cip_class_->add_instance_service({
        ForwardCloseService, "Forward_Close",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_forward_close(i, r);
        }});
    cip_class_->add_instance_service({
        LargeForwardOpenService, "Large_Forward_Open",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_large_forward_open(i, r);
        }});
    cip_class_->add_instance_service({
        UnconnectedSendService, "Unconnected_Send",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_unconnected_send(i, r);
        }});
}

std::unique_ptr<CipClass> ConnectionManagerObject::release_cip_class() {
    return std::move(cip_class_);
}

std::vector<IoConnection*> ConnectionManagerObject::active_connections() {
    std::scoped_lock lock(mu_);
    std::vector<IoConnection*> out;
    out.reserve(connections_.size());
    for (auto& [_, conn] : connections_) {
        out.push_back(conn.get());
    }
    return out;
}

IoConnection* ConnectionManagerObject::find_by_oto_t_id(uint32_t connection_id) {
    std::scoped_lock lock(mu_);
    auto it = connections_.find(connection_id);
    return it == connections_.end() ? nullptr : it->second.get();
}

void ConnectionManagerObject::remove_connection(IoConnection& conn) {
    std::unique_ptr<IoConnection> popped;
    {
        std::scoped_lock lock(mu_);
        auto it = connections_.find(conn.oto_t_connection_id);
        if (it != connections_.end()) {
            popped = std::move(it->second);
            connections_.erase(it);
        }
    }
    conn.close();
    for (auto& cb : on_connection_removed) {
        cb(conn);
    }
    // popped is destroyed here, after callbacks have observed the connection.
}

void ConnectionManagerObject::timeout_connection(IoConnection& conn) {
    conn.state = ConnectionState::TimedOut;
    remove_connection(conn);
}

CipServiceResponse ConnectionManagerObject::handle_forward_open(
        CipInstance&, const CipServiceRequest& request) {
    return process_forward_open(request, /*is_large=*/false);
}

CipServiceResponse ConnectionManagerObject::handle_large_forward_open(
        CipInstance&, const CipServiceRequest& request) {
    return process_forward_open(request, /*is_large=*/true);
}

CipServiceResponse ConnectionManagerObject::process_forward_open(
        const CipServiceRequest& request, bool is_large) {
    namespace ser = ethernetip::cip::serializer;

    ForwardOpenRequest fwd_open;
    try {
        fwd_open = ForwardOpenRequest::parse(request.data, is_large);
    } catch (const std::invalid_argument&) {
        return forward_open_error(request.service_code, 0x0118);  // Bad params
    }

    auto path_result = parse_connection_path(fwd_open.connection_path, fwd_open);

    // ---- Safety validation (TUNID, CPCRC, SCID) ----
    if (!path_result.safety_segment.empty() && safety_handler_ != nullptr) {
        auto reject = safety_handler_->validate_safety_open(
            path_result.safety_segment, fwd_open);
        if (reject.has_value()) {
            return forward_open_error(request.service_code, *reject);
        }
    }

    // ---- Validate assembly instances exist ----
    if (validate_assembly) {
        if (path_result.consumed_assembly_instance.has_value()) {
            if (validate_assembly(*path_result.consumed_assembly_instance) < 0) {
                return forward_open_error(request.service_code, 0x0116);
            }
        }
        if (path_result.produced_assembly_instance.has_value()) {
            if (validate_assembly(*path_result.produced_assembly_instance) < 0) {
                return forward_open_error(request.service_code, 0x0116);
            }
        }
    }

    // ---- Refuse if O->T and T->O reference the same assembly instance ----
    // Logix safety configs do legitimately overlap the config instance with one
    // of the data instances, so we only reject the data/data clash here.
    if (path_result.consumed_assembly_instance.has_value()
        && path_result.produced_assembly_instance.has_value()
        && *path_result.consumed_assembly_instance == *path_result.produced_assembly_instance) {
        return forward_open_error(request.service_code, 0x0116);
    }

    // ---- Duplicate-triad check ----
    {
        std::scoped_lock lock(mu_);
        for (auto& [_, existing] : connections_) {
            if (existing->connection_serial_number == fwd_open.connection_serial_number
                && existing->originator_vendor_id  == fwd_open.originator_vendor_id
                && existing->originator_serial_number == fwd_open.originator_serial_number) {
                return forward_open_error(request.service_code, 0x0100);  // Conn in use
            }
        }
    }

    // ---- Allocate connection ----
    uint32_t oto_t_id = next_connection_id_.fetch_add(1) + 1;
    uint32_t tto_o_id = fwd_open.tto_o_connection_id;

    auto conn = std::make_unique<IoConnection>();
    conn->connection_serial_number   = fwd_open.connection_serial_number;
    conn->originator_vendor_id       = fwd_open.originator_vendor_id;
    conn->originator_serial_number   = fwd_open.originator_serial_number;
    conn->oto_t_connection_id        = oto_t_id;
    conn->tto_o_connection_id        = tto_o_id;
    conn->consumed_assembly_instance = path_result.consumed_assembly_instance.value_or(0);
    conn->produced_assembly_instance = path_result.produced_assembly_instance.value_or(0);
    conn->config_assembly_instance   = path_result.config_assembly_instance.value_or(0);
    conn->config_data                = std::move(path_result.config_data);
    conn->oto_t_rpi   = fwd_open.oto_t_rpi;
    conn->tto_o_rpi   = fwd_open.tto_o_rpi;
    conn->oto_t_size  = fwd_open.oto_t_params.connection_size;
    conn->tto_o_size  = fwd_open.tto_o_params.connection_size;
    conn->transport_class    = fwd_open.transport_class();
    conn->timeout_multiplier = fwd_open.connection_timeout_multiplier;
    conn->state              = ConnectionState::Established;

    if (!path_result.safety_segment.empty()) {
        conn->is_safety           = true;
        conn->safety_segment_data = path_result.safety_segment;
        if (conn->safety_segment_data.size() >= 3) {
            conn->safety_format = conn->safety_segment_data[2];
        }
        if (safety_handler_ != nullptr) {
            safety_handler_->configure_safety_connection(*conn, fwd_open);
        }
    }

    IoConnection* conn_view = conn.get();
    {
        std::scoped_lock lock(mu_);
        connections_[oto_t_id] = std::move(conn);
    }

    for (auto& cb : on_connection_established) {
        cb(*conn_view);
    }

    // ---- Build Forward Open success response ----
    // Safety connections carry an Application Reply: 5 words (Base) or 7
    // words (Extended). Non-safety responses are 26 bytes flat.
    bool is_extended = conn_view->safety_format == 0x02;
    int  app_reply_words = conn_view->is_safety ? (is_extended ? 7 : 5) : 0;

    std::vector<uint8_t> resp(26 + app_reply_words * 2);
    ser::write_udint(resp,                oto_t_id);
    ser::write_udint(std::span<uint8_t>(resp).subspan(4),  tto_o_id);
    ser::write_uint (std::span<uint8_t>(resp).subspan(8),  fwd_open.connection_serial_number);
    ser::write_uint (std::span<uint8_t>(resp).subspan(10), fwd_open.originator_vendor_id);
    ser::write_udint(std::span<uint8_t>(resp).subspan(12), fwd_open.originator_serial_number);
    ser::write_udint(std::span<uint8_t>(resp).subspan(16), fwd_open.oto_t_rpi);
    ser::write_udint(std::span<uint8_t>(resp).subspan(20), fwd_open.tto_o_rpi);
    resp[24] = static_cast<uint8_t>(app_reply_words);
    resp[25] = 0;  // reserved

    if (conn_view->is_safety) {
        size_t off = 26;
        // Consumer_Number = 0xFFFF for single-cast.
        ser::write_uint(std::span<uint8_t>(resp).subspan(off), uint16_t{0xFFFF}); off += 2;
        uint16_t tgt_vendor = safety_handler_ ? safety_handler_->vendor_id() : uint16_t{0x0001};
        uint32_t tgt_serial = safety_handler_ ? safety_handler_->serial_number() : 0xC0FFEE42u;
        ser::write_uint (std::span<uint8_t>(resp).subspan(off), tgt_vendor); off += 2;
        ser::write_udint(std::span<uint8_t>(resp).subspan(off), tgt_serial); off += 4;
        ser::write_uint (std::span<uint8_t>(resp).subspan(off), conn_view->safety_validator_instance_id); off += 2;
        if (is_extended) {
            ser::write_uint(std::span<uint8_t>(resp).subspan(off),
                             conn_view->safety_initial_timestamp); off += 2;
            ser::write_uint(std::span<uint8_t>(resp).subspan(off),
                             conn_view->safety_initial_rollover_value); off += 2;
        }
    }

    return CipServiceResponse::success(request.service_code, std::move(resp));
}

CipServiceResponse ConnectionManagerObject::handle_forward_close(
        CipInstance&, const CipServiceRequest& request) {
    namespace ser = ethernetip::cip::serializer;

    if (request.data.size() < 10) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::NotEnoughData));
    }

    uint16_t conn_serial = ser::read_uint(request.data.subspan(2));
    uint16_t orig_vendor = ser::read_uint(request.data.subspan(4));
    uint32_t orig_serial = ser::read_udint(request.data.subspan(6));

    IoConnection* found = nullptr;
    {
        std::scoped_lock lock(mu_);
        for (auto& [_, conn] : connections_) {
            if (conn->connection_serial_number == conn_serial
                && conn->originator_vendor_id  == orig_vendor
                && conn->originator_serial_number == orig_serial) {
                found = conn.get();
                break;
            }
        }
    }
    if (found == nullptr) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(0x01, std::vector<uint16_t>{0x0107}));
    }

    remove_connection(*found);

    std::vector<uint8_t> resp(10);
    ser::write_uint (resp,                                conn_serial);
    ser::write_uint (std::span<uint8_t>(resp).subspan(2),  orig_vendor);
    ser::write_udint(std::span<uint8_t>(resp).subspan(4),  orig_serial);
    resp[8] = 0;  resp[9] = 0;
    return CipServiceResponse::success(request.service_code, std::move(resp));
}

CipServiceResponse ConnectionManagerObject::handle_unconnected_send(
        CipInstance&, const CipServiceRequest& request) {
    namespace ser = ethernetip::cip::serializer;
    if (!dispatch_request) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::ServiceNotSupported));
    }
    if (request.data.size() < 4) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::NotEnoughData));
    }

    // Skip priority/time_tick(1) + timeout_ticks(1).
    uint16_t msg_length = ser::read_uint(request.data.subspan(2));
    size_t offset = 4;
    if (offset + msg_length > request.data.size()) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::NotEnoughData));
    }

    auto embedded = request.data.subspan(offset, msg_length);
    auto parsed = ethernetip::cip::mr_codec::try_parse_request(embedded);
    if (!parsed.has_value()) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::PathSegmentError));
    }

    return dispatch_request(parsed->service_code, parsed->path, parsed->data);
}

CipServiceResponse ConnectionManagerObject::forward_open_error(uint8_t service_code,
                                                                  uint16_t extended_status) {
    return CipServiceResponse::error(service_code,
        CipStatus::error(0x01, std::vector<uint16_t>{extended_status}));
}

} // namespace ethernetip::connections
