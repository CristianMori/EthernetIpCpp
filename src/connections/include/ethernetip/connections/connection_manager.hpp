#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/cip/cip_service.hpp"
#include "ethernetip/connections/forward_open_request.hpp"
#include "ethernetip/connections/io_connection.hpp"
#include "ethernetip/connections/safety_handler.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <unordered_map>
#include <vector>

namespace ethernetip::connections {

/// CIP Connection Manager Object (Class 0x06). Handles Forward Open (0x54),
/// Large Forward Open (0x5B), Forward Close (0x4E), and Unconnected Send
/// (0x52). Creates and tracks IoConnection instances.
class ConnectionManagerObject {
public:
    static constexpr uint32_t ClassCode               = 0x06;
    static constexpr uint8_t  ForwardOpenService      = 0x54;
    static constexpr uint8_t  ForwardCloseService     = 0x4E;
    static constexpr uint8_t  LargeForwardOpenService = 0x5B;
    static constexpr uint8_t  UnconnectedSendService  = 0x52;

    ConnectionManagerObject();

    /// CIP class object — register with a dispatcher for explicit-message routing.
    [[nodiscard]] cip::CipClass& cip_class() noexcept { return *cip_class_; }

    /// Transfer ownership of the CIP class to a dispatcher. The connection
    /// manager keeps a raw pointer to maintain the service handler closure.
    [[nodiscard]] std::unique_ptr<cip::CipClass> release_cip_class();

    /// Snapshot of currently active connections (lock-protected copy).
    [[nodiscard]] std::vector<IoConnection*> active_connections();

    /// Look up a connection by its O->T connection ID. Used by the UDP transport
    /// to route incoming I/O packets to the right connection.
    [[nodiscard]] IoConnection* find_by_oto_t_id(uint32_t connection_id);

    /// Remove a connection, mark it NonExistent, and fire on_connection_removed.
    void remove_connection(IoConnection& conn);

    /// Mark a connection as timed-out and remove it.
    void timeout_connection(IoConnection& conn);

    // ---- Hooks ----

    /// Set the safety handler. The pointed-to handler must outlive the manager.
    void set_safety_handler(ISafetyConnectionHandler* handler) noexcept {
        safety_handler_ = handler;
    }

    /// Validate that an assembly instance exists. Returns the assembly size in
    /// bytes, or -1 if the instance does not exist. Set by VirtualDevice.
    std::function<int(uint32_t)> validate_assembly;

    /// Dispatch an inner CIP request — used by Unconnected Send to route the
    /// unwrapped request. Set by VirtualDevice or LogixDispatcher.
    std::function<cip::CipServiceResponse(uint8_t, const cip::CipPath&,
                                            std::span<const uint8_t>)>
        dispatch_request;

    /// Fired when a new I/O connection is established via Forward Open.
    std::vector<std::function<void(IoConnection&)>> on_connection_established;

    /// Fired when a connection is closed (Forward Close) or timed out.
    std::vector<std::function<void(IoConnection&)>> on_connection_removed;

private:
    cip::CipServiceResponse handle_forward_open(cip::CipInstance&,
                                                  const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_large_forward_open(cip::CipInstance&,
                                                        const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_forward_close(cip::CipInstance&,
                                                   const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_unconnected_send(cip::CipInstance&,
                                                      const cip::CipServiceRequest&);

    cip::CipServiceResponse process_forward_open(const cip::CipServiceRequest& request,
                                                   bool is_large);

    static cip::CipServiceResponse forward_open_error(uint8_t service_code,
                                                       uint16_t extended_status);

    std::unique_ptr<cip::CipClass> cip_class_;
    cip::CipClass* cip_class_view_ = nullptr;   ///< raw view for handler closure

    std::mutex mu_;
    std::unordered_map<uint32_t, std::unique_ptr<IoConnection>> connections_;
    std::atomic<uint32_t> next_connection_id_{0};

    ISafetyConnectionHandler* safety_handler_ = nullptr;
};

} // namespace ethernetip::connections
