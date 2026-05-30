#pragma once

#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/encapsulation.hpp"
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/protocol/cpf_helpers.hpp"
#include "ethernetip/protocol/messages.hpp"
#include "ethernetip/protocol/session_manager.hpp"
#include "ethernetip/protocol/tcp_socket.hpp"

#include <cstdint>
#include <functional>
#include <memory>

namespace ethernetip::protocol {

/// EtherNet/IP Adapter (server/target). Listens on TCP port 44818 for
/// encapsulation commands from scanners/originators, routes CIP explicit
/// messages through ICipDispatch, handles session management,
/// ListIdentity/ListServices, and Forward Open/Close detection.
///
/// Base class is Class-3-clean by default: Forward Open replies carry only
/// the standard NullAddress + UnconnectedData CPF items. Use the
/// `IoEipAdapter` subclass when serving Class 0/1 I/O connections that need
/// Sockaddr Info O->T / T->O items on the reply.
class EipAdapter {
public:
    static constexpr uint16_t DefaultPort = 44818;

    /// Construct with a dispatch (typically the device dispatcher) and the
    /// device identity. `identity_source` is the dispatcher to query for the
    /// Identity Object's GetAttributeAll response; defaults to `dispatch`.
    EipAdapter(cip::ICipDispatch& dispatch,
                cip::IdentityInfo identity,
                cip::ICipDispatch* identity_source = nullptr);

    virtual ~EipAdapter();

    EipAdapter(const EipAdapter&) = delete;
    EipAdapter& operator=(const EipAdapter&) = delete;

    /// SendUnitData reply requires the reverse of the connection ID the PLC
    /// sent in: PLC ships with OT_conn_id (we assigned), we must reply with
    /// TO_conn_id (PLC assigned). Wire this to ConnectionManager's
    /// find_by_oto_t_id lookup. If unset, the reply echoes the request's
    /// connection_id — fine for loopback tests but rejected by Logix MSG
    /// instructions (which see "not for me" and time out).
    using ConnectionIdLookup = std::function<uint32_t(uint32_t oto_t_id)>;
    void set_connection_id_lookup(ConnectionIdLookup h) { connection_id_lookup_ = std::move(h); }

    /// Listen on `address:port` (default port 44818).
    void listen(const IpEndpoint& bind);

    /// Stop listening.
    void stop();

    [[nodiscard]] uint16_t port() const noexcept { return socket_.actual_port(); }

protected:
    /// Hook invoked on every successful Forward Open just before the reply
    /// CPF is built. The base implementation is a no-op; subclasses may
    /// append extra CPF items (e.g. Sockaddr Info) and fire callbacks.
    ///
    ///   request_data : the raw service data from the FwdOpen request (lets
    ///                    subclasses peek transport_class_trigger etc.)
    ///   response     : the dispatcher's CIP reply (already known successful)
    ///   service_code : 0x54 (regular FwdOpen) or 0x5B (Large FwdOpen)
    virtual void on_forward_open_reply(cpf_helpers::CpfBuilder& /*cpf*/,
                                         uint8_t /*service_code*/,
                                         std::span<const uint8_t> /*request_data*/,
                                         const cip::CipServiceResponse& /*response*/,
                                         const IpEndpoint& /*local_ep*/,
                                         const IpEndpoint& /*remote_ep*/) {}

    /// Build a 16-byte Sockaddr Info CPF item payload — protected so the
    /// IoEipAdapter subclass can reuse it.
    static std::vector<uint8_t> build_sockaddr_info(const std::string& host, uint16_t port);

private:
    struct PerClient;
    void on_client_connected(std::shared_ptr<TcpSocketConnection> conn);
    std::vector<uint8_t> dispatch_message(messages::Message& msg, PerClient& pc,
                                            const IpEndpoint& local_ep,
                                            const IpEndpoint& remote_ep);

    std::vector<uint8_t> handle_list_identity (messages::ListIdentityMessage& msg, const IpEndpoint& local_ep);
    static std::vector<uint8_t> handle_list_services(messages::ListServicesMessage& msg);
    std::vector<uint8_t> handle_register_session(messages::RegisterSessionMessage& msg, PerClient& pc);
    std::vector<uint8_t> handle_unregister_session(messages::UnregisterSessionMessage& msg, PerClient& pc);
    std::vector<uint8_t> handle_send_rr_data(messages::SendRRDataMessage& msg, PerClient& pc,
                                                const IpEndpoint& local_ep,
                                                const IpEndpoint& remote_ep);
    std::vector<uint8_t> handle_send_unit_data(messages::SendUnitDataMessage& msg, PerClient& pc);

    static std::vector<uint8_t> build_response(cip::EncapsulationCommand command,
                                                  uint32_t session_handle,
                                                  uint64_t sender_context,
                                                  std::span<const uint8_t> payload);
    static std::vector<uint8_t> build_error_response(cip::EncapsulationCommand command,
                                                        uint32_t session_handle,
                                                        uint64_t sender_context,
                                                        cip::EncapsulationStatus status);

    cip::ICipDispatch& dispatch_;
    cip::IdentityInfo  identity_;
    cip::ICipDispatch* identity_source_;
    SessionManager     sessions_;
    TcpSocket          socket_;
    ConnectionIdLookup connection_id_lookup_;
};

/// EipAdapter variant for Class 0/1 I/O serving — attaches Sockaddr Info
/// O->T / T->O items to Forward Open replies so the originator knows which
/// UDP endpoint to use, and fires `on_connection_opened` so the host can
/// associate the new IoConnection with its PLC's UDP endpoint. Skips the
/// Sockaddr items for Class 3 explicit FwdOpens since those don't use UDP.
class IoEipAdapter : public EipAdapter {
public:
    using ConnectionOpenedHandler =
        std::function<void(const cip::CipServiceResponse&, const IpEndpoint& plc_udp)>;

    using EipAdapter::EipAdapter;  // inherit ctor

    /// UDP port advertised in Forward Open Sockaddr Info items (default 2222).
    void set_udp_port(uint16_t port) noexcept { udp_port_ = port; }
    [[nodiscard]] uint16_t udp_port() const noexcept { return udp_port_; }

    /// Register a callback for "Forward Open accepted" on a non-Class-3
    /// connection. The PLC's UDP endpoint passed in is `(plc_ip, 2222)`.
    void set_on_connection_opened(ConnectionOpenedHandler h) {
        on_connection_opened_ = std::move(h);
    }

protected:
    void on_forward_open_reply(cpf_helpers::CpfBuilder& cpf,
                                uint8_t service_code,
                                std::span<const uint8_t> request_data,
                                const cip::CipServiceResponse& response,
                                const IpEndpoint& local_ep,
                                const IpEndpoint& remote_ep) override;

private:
    uint16_t                udp_port_ = 0x08AE;
    ConnectionOpenedHandler on_connection_opened_;
};

} // namespace ethernetip::protocol
