#pragma once

#include "ethernetip/cip/cip_service.hpp"
#include "ethernetip/cip/cpf.hpp"
#include "ethernetip/protocol/eip_udp_transport.hpp"
#include "ethernetip/protocol/forward_open_config.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/scanner_connection.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ethernetip::protocol {

/// EtherNet/IP scanner (originator) — TCP client. Connect, register a
/// session, send explicit CIP messages, open I/O connections via Forward
/// Open. Owns an internal UDP transport bound to an ephemeral port for the
/// resulting I/O traffic.
///
/// Methods throw std::runtime_error on transport / encapsulation failure.
class EipScanner {
public:
    static constexpr int DefaultTcpPort = 44818;

    EipScanner();
    ~EipScanner();

    EipScanner(const EipScanner&)            = delete;
    EipScanner& operator=(const EipScanner&) = delete;

    void connect(const std::string& host, int port = DefaultTcpPort);
    void disconnect() noexcept;

    [[nodiscard]] bool          is_connected()   const noexcept;
    [[nodiscard]] uint32_t      session_handle() const noexcept { return session_handle_; }
    [[nodiscard]] const IpEndpoint& local_endpoint()  const noexcept { return local_endpoint_; }
    [[nodiscard]] const IpEndpoint& remote_endpoint() const noexcept { return remote_endpoint_; }

    /// Internal UDP transport — bound to local IPv4 + ephemeral port. Used
    /// by ScannerConnection / SafetyScannerConnection for I/O traffic.
    [[nodiscard]] EipUdpTransport* udp_transport() noexcept { return udp_transport_.get(); }

    /// Send an explicit CIP message (UCMM via SendRRData). Returns the inner
    /// CIP response. Throws on transport failure.
    cip::CipServiceResponse send_explicit(uint8_t service_code,
                                            std::span<const uint8_t> path_bytes,
                                            std::span<const uint8_t> service_data);

    struct ExplicitRawResult {
        cip::CipServiceResponse response;
        std::vector<cip::CpfItem> cpf_items;
    };

    /// Same as send_explicit but also returns the parsed CPF items (used by
    /// callers that need Sockaddr Info etc., notably Forward Open).
    ExplicitRawResult send_explicit_raw(uint8_t service_code,
                                          std::span<const uint8_t> path_bytes,
                                          std::span<const uint8_t> service_data);

    /// Establish an I/O connection via Forward Open. The returned
    /// ScannerConnection owns its production thread until close() is called.
    std::unique_ptr<ScannerConnection> forward_open(const ForwardOpenConfig& config);

    /// Open a Class 3 connected-explicit messaging connection to the target.
    /// Subsequent send() / send_raw() calls on the returned handle travel
    /// over TCP via SendUnitData (encap 0x70) instead of SendRRData. Close
    /// the handle (or let it go out of scope) to issue the Forward Close.
    [[nodiscard]] std::unique_ptr<class ConnectedExplicit> open_explicit();

    /// Send Forward Close (used by ScannerConnection::close).
    void forward_close(uint16_t connection_serial,
                        uint16_t originator_vendor,
                        uint32_t originator_serial);

    /// Internal: send an MR request over an existing Class 3 connection via
    /// SendUnitData and return the inner CIP response. Used by
    /// ConnectedExplicit; not intended for direct use.
    cip::CipServiceResponse send_connected_mr(uint32_t oto_t_connection_id,
                                                uint16_t seq_count,
                                                uint8_t service_code,
                                                std::span<const uint8_t> path_bytes,
                                                std::span<const uint8_t> service_data);

    /// Route inbound UDP I/O messages to connections by their T->O ID.
    /// Called by ScannerConnection / SafetyScannerConnection during start.
    using UdpRouteHandler = std::function<void(messages::Message&)>;
    void register_udp_route(uint32_t tto_o_connection_id, UdpRouteHandler h);
    void unregister_udp_route(uint32_t tto_o_connection_id);

private:
    void on_udp_message_dispatch(std::unique_ptr<messages::Message> msg);
    std::vector<uint8_t> send_encapsulated(uint16_t command,
                                             std::span<const uint8_t> payload);
    void read_exact(uint8_t* dst, size_t n);
    uint32_t register_session();

    sock::socket_t socket_         = sock::invalid;
    uint32_t       session_handle_ = 0;
    IpEndpoint     local_endpoint_;
    IpEndpoint     remote_endpoint_;

    std::mutex                       io_mu_;
    std::unique_ptr<EipUdpTransport> udp_transport_;
    std::atomic<uint16_t>            next_conn_serial_{1};

    std::mutex                                        routes_mu_;
    std::unordered_map<uint32_t, UdpRouteHandler>     routes_;
};

} // namespace ethernetip::protocol
