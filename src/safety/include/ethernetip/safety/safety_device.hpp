#pragma once

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/connections/forward_open_request.hpp"
#include "ethernetip/connections/io_connection.hpp"
#include "ethernetip/connections/safety_handler.hpp"
#include "ethernetip/device/virtual_device.hpp"
#include "ethernetip/safety/safety_supervisor_object.hpp"
#include "ethernetip/safety/safety_types.hpp"
#include "ethernetip/safety/safety_validator_object.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace ethernetip::safety {

/// CIP Safety EtherNet/IP device. Extends VirtualDevice with safety frame
/// encoding/decoding, time coordination (TCOO), CRC seed computation, and
/// safety connection lifecycle. Implements ISafetyConnectionHandler so the
/// ConnectionManager defers FwdOpen validation + configuration to us.
class SafetyDevice : public device::VirtualDevice,
                      public connections::ISafetyConnectionHandler {
public:
    SafetyDevice(cip::IdentityInfo identity, std::string bind_address,
                  SafetyNetworkNumber snn, uint32_t node_address,
                  std::string name = {});
    ~SafetyDevice() override;

    /// Enable per-frame and per-TCOO trace logging to stderr. Off by default.
    /// Console writes hold a global lock — turn on only when actively
    /// debugging a stuck connection.
    static std::atomic<bool> enable_trace;

    /// Number of seconds at the start of each safety connection during which
    /// per-frame trace lines are emitted unconditionally. 0 disables. Useful
    /// for diagnosing the short 0.1-1 s failure windows at restart.
    static std::atomic<int> startup_trace_seconds;

    [[nodiscard]] SafetySupervisorObject& supervisor() noexcept { return *supervisor_; }
    [[nodiscard]] SafetyValidatorObject&  validator()  noexcept { return *validator_; }

    // ---- ISafetyConnectionHandler -----------------------------------------
    [[nodiscard]] uint16_t vendor_id()    const override { return identity().vendor_id; }
    [[nodiscard]] uint32_t serial_number() const override { return identity().serial_number; }
    [[nodiscard]] std::optional<uint16_t> validate_safety_open(
        std::span<const uint8_t> safety_segment,
        const connections::ForwardOpenRequest& fwd_open) override;
    void configure_safety_connection(connections::IoConnection& conn,
                                      const connections::ForwardOpenRequest& fwd_open) override;

protected:
    // ---- VirtualDevice overrides ------------------------------------------
    void on_connection_ready(connections::IoConnection& conn) override;
    void produce_io_data(connections::IoConnection& conn) override;
    void handle_received_io_data(connections::IoConnection& conn,
                                   std::span<const uint8_t> data) override;
    void on_remote_endpoint_updated(connections::IoConnection& conn,
                                      const protocol::IpEndpoint& sender) override;

private:
    void on_connection_removed(connections::IoConnection& conn);
    void send_time_coordination(connections::IoConnection& conn);

    std::unique_ptr<SafetySupervisorObject> supervisor_;
    std::unique_ptr<SafetyValidatorObject>  validator_;
};

} // namespace ethernetip::safety
