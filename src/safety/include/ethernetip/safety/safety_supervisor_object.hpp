#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/safety/safety_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace ethernetip::safety {

/// Safety Supervisor device states.
enum class SafetySupervisorState : uint8_t {
    Idle        = 0,
    SelfTesting = 1,
    Executing   = 2,
    Abort       = 3,
    Exception   = 4,
    WaitForLock = 5,
};

/// Safety Supervisor device modes.
enum class SafetySupervisorMode : uint8_t {
    Idle          = 0,
    Configuration = 1,
    Run           = 2,
};

/// CIP Safety Supervisor Object (Class 0x39) — one per device. Holds overall
/// device safety state, SNN/TUNID/SCID, and the Safety_Reset (0x54),
/// Propose_TUNID (0x56), Apply_TUNID (0x57) services.
class SafetySupervisorObject {
public:
    static constexpr uint32_t ClassCode             = 0x39;
    static constexpr uint8_t  SafetyResetService    = 0x54;
    static constexpr uint8_t  ProposeTunidService   = 0x56;
    static constexpr uint8_t  ApplyTunidService     = 0x57;

    SafetySupervisorObject(SafetyNetworkNumber snn, uint32_t node_address);

    [[nodiscard]] cip::CipClass& cip_class() noexcept { return *cip_class_ptr_; }
    [[nodiscard]] std::unique_ptr<cip::CipClass> release_cip_class();

    [[nodiscard]] SafetySupervisorState state() const noexcept { return state_; }
    [[nodiscard]] SafetySupervisorMode  mode()  const noexcept { return mode_; }
    [[nodiscard]] const SafetyNetworkNumber& snn() const noexcept { return snn_; }
    [[nodiscard]] const UniqueNetworkId&     tunid() const noexcept { return tunid_; }
    [[nodiscard]] const SafetyConfigurationId& scid() const noexcept { return scid_; }
    [[nodiscard]] bool tunid_assigned() const noexcept { return tunid_assigned_; }

    /// Set the device SCID. Safety device updates this after a FwdOpen with
    /// a non-zero SCCRC stores the configuration.
    void set_scid(const SafetyConfigurationId& scid) noexcept { scid_ = scid; }

    /// Transition to Executing / Run (ready for safety connections).
    void start();
    /// Transition to Abort.
    void abort();
    /// Reset from Abort/Idle.
    void reset();

private:
    cip::CipServiceResponse handle_safety_reset(cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_propose_tunid(cip::CipInstance&, const cip::CipServiceRequest&);
    cip::CipServiceResponse handle_apply_tunid(cip::CipInstance&, const cip::CipServiceRequest&);

    void update_state_attribute();

    std::unique_ptr<cip::CipClass> cip_class_;
    /// Non-owning pointer captured before `release_cip_class()` hands ownership
    /// to the dispatcher; survives the move so update_state_attribute() and
    /// other late-bound paths can still touch class instances.
    cip::CipClass* cip_class_ptr_ = nullptr;
    SafetySupervisorState state_ = SafetySupervisorState::Idle;
    SafetySupervisorMode  mode_  = SafetySupervisorMode::Idle;
    SafetyNetworkNumber   snn_;
    UniqueNetworkId       tunid_;
    SafetyConfigurationId scid_;
    bool                  tunid_assigned_ = false;
    std::optional<UniqueNetworkId> proposed_tunid_;
};

} // namespace ethernetip::safety
