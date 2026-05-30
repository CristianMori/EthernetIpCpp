#pragma once

#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/connections/connection_manager.hpp"
#include "ethernetip/connections/io_connection.hpp"
#include "ethernetip/device/assembly_object.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"
#include "ethernetip/protocol/eip_udp_transport.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>

namespace ethernetip::device {

/// Composition root for a complete EtherNet/IP device. Owns the CIP
/// dispatcher, assemblies, connection manager, TCP adapter, and UDP I/O
/// transport. Subclasses (e.g. SafetyDevice) override the virtual hooks to
/// inject safety framing on top of the standard I/O path.
class VirtualDevice {
public:
    VirtualDevice(cip::IdentityInfo identity, std::string bind_address,
                   std::string name = {});
    virtual ~VirtualDevice();

    VirtualDevice(const VirtualDevice&) = delete;
    VirtualDevice& operator=(const VirtualDevice&) = delete;

    [[nodiscard]] const std::string&        name()           const noexcept { return name_; }
    [[nodiscard]] const std::string&        bind_address()   const noexcept { return bind_address_; }
    [[nodiscard]] const cip::IdentityInfo&  identity()       const noexcept { return identity_; }
    [[nodiscard]] cip::CipDispatcher&       dispatcher()           noexcept { return dispatcher_; }
    [[nodiscard]] AssemblyObject&           assemblies()           noexcept { return assemblies_; }
    [[nodiscard]] connections::ConnectionManagerObject& connection_manager() noexcept {
        return connection_manager_;
    }
    [[nodiscard]] int tcp_port() const noexcept { return tcp_port_; }
    [[nodiscard]] int udp_port() const noexcept { return udp_port_; }
    [[nodiscard]] uint64_t tto_o_send_count() const noexcept { return tto_o_send_count_.load(); }

    /// Convenience wrapper around `assemblies().add_instance(...)`.
    AssemblyInstance& add_assembly(uint32_t instance_id, int data_size,
                                     std::optional<std::string> name = {});

    /// Start TCP listener (44818) and UDP transport (2222).
    void start(int tcp_port = protocol::EipAdapter::DefaultPort,
                int udp_port = protocol::EipUdpTransport::IoPort);

    /// Stop both transports and tear down all active production threads.
    void close();

protected:
    // ---- Virtual hooks for subclasses ----

    /// Called when a new connection is established and is about to start
    /// production. Default: starts the production thread for the T->O
    /// direction. Safety subclasses override to delay production until the
    /// first TCOO arrives.
    virtual void on_connection_ready(connections::IoConnection& conn);

    /// Build and send one T->O frame. Default produces a Class 1 frame
    /// (2-byte CIP seq + assembly bytes). Safety subclasses override to
    /// produce a CIP Safety frame.
    virtual void produce_io_data(connections::IoConnection& conn);

    /// Handle one incoming O->T frame. Default unwraps Class 1 framing and
    /// stores the bytes in the consumed assembly. Safety subclasses override
    /// for safety frame decoding + TCOO handling.
    virtual void handle_received_io_data(connections::IoConnection& conn,
                                           std::span<const uint8_t> data);

    /// Called when a connection's remote UDP endpoint is learned/updated
    /// from an incoming packet. Default: no-op. Safety subclasses use this
    /// to propagate the endpoint across partner connections.
    virtual void on_remote_endpoint_updated(connections::IoConnection& conn,
                                              const protocol::IpEndpoint& sender);

    // ---- Helpers for subclasses ----

    /// Send a pre-built I/O payload over UDP. Bumps the encapsulation
    /// sequence number and the device-wide T->O counter.
    void send_udp_io_data(connections::IoConnection& conn,
                           std::span<const uint8_t> data);

private:
    void on_connection_established(connections::IoConnection& conn);
    void on_udp_message(std::unique_ptr<protocol::messages::Message> msg);
    void on_connection_opened_from_adapter(const cip::CipServiceResponse& response,
                                              const protocol::IpEndpoint& plc_udp);

    void start_production_thread(connections::IoConnection& conn);
    void stop_production_threads();
    void watchdog_loop();

    cip::IdentityInfo  identity_;
    std::string        bind_address_;
    std::string        name_;

    cip::CipDispatcher                       dispatcher_;
    AssemblyObject                            assemblies_;
    connections::ConnectionManagerObject     connection_manager_;
    std::unique_ptr<protocol::IoEipAdapter>  adapter_;
    std::unique_ptr<protocol::EipUdpTransport> udp_transport_;

    int tcp_port_ = protocol::EipAdapter::DefaultPort;
    int udp_port_ = protocol::EipUdpTransport::IoPort;
    std::atomic<uint64_t> tto_o_send_count_{0};

    // Production threads, keyed by O->T connection ID.
    std::mutex production_mu_;
    std::unordered_map<uint32_t, std::thread> production_threads_;
    std::unordered_map<uint32_t, std::shared_ptr<std::atomic<bool>>> production_cancel_;

    // Watchdog thread checks every connection's last-received timestamp once
    // per ~50 ms and times it out if `connection_timeout_us` has elapsed.
    std::thread watchdog_thread_;
    std::atomic<bool> watchdog_running_{false};
};

} // namespace ethernetip::device
