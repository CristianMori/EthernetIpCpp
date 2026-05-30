#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/cip/cip_service.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>

namespace ethernetip::cip {

/// Central CIP message dispatch interface. Both adapter (server) and
/// scanner (client) implementations consume this. An adapter implementation
/// handles incoming requests from a PLC; subclasses may also handle
/// unsolicited or unconnected messages.
class ICipDispatch {
public:
    virtual ~ICipDispatch() = default;
    virtual CipServiceResponse dispatch(uint8_t service_code,
                                          const CipPath& path,
                                          std::span<const uint8_t> data) = 0;
};

/// Default ICipDispatch implementation that routes requests through the CIP
/// object tree: path.class_id → CipClass → instance → service → handler.
/// When the path has no class_id (e.g. symbolic segment), forwards to
/// on_unhandled() which subclasses can override.
class CipDispatcher : public ICipDispatch {
public:
    /// Register a CIP class so it can receive dispatched requests. Ownership
    /// is transferred — the dispatcher manages the class's lifetime.
    void register_class(std::unique_ptr<CipClass> cls);

    /// Look up a registered class by class code. Returns nullptr if not registered.
    [[nodiscard]] CipClass* get_class(uint32_t class_code) const;

    [[nodiscard]] const std::unordered_map<uint32_t, std::unique_ptr<CipClass>>&
        registered_classes() const noexcept { return classes_; }

    CipServiceResponse dispatch(uint8_t service_code,
                                  const CipPath& path,
                                  std::span<const uint8_t> data) override;

protected:
    /// Called when a request cannot be resolved through the standard class /
    /// instance / service routing. Override in subclasses to provide custom
    /// routing (e.g. symbolic tag dispatch, logging echo servers).
    ///
    /// `default_status` is the CIP error code the dispatcher would have
    /// returned for this failure (PathDestinationUnknown, ObjectDoesNotExist,
    /// or ServiceNotSupported) — the default implementation returns it
    /// unchanged, so callers that don't override see no behavior change.
    virtual CipServiceResponse on_unhandled(uint8_t service_code,
                                              const CipPath& path,
                                              std::span<const uint8_t> data,
                                              uint8_t default_status = CipStatus::PathDestinationUnknown);

private:
    std::unordered_map<uint32_t, std::unique_ptr<CipClass>> classes_;
};

} // namespace ethernetip::cip
