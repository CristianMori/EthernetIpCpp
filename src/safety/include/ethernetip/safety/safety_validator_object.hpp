#pragma once

#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/connections/io_connection.hpp"

#include <cstdint>
#include <memory>
#include <unordered_map>

namespace ethernetip::safety {

/// State of a Safety Validator instance.
enum class SafetyValidatorState : uint8_t {
    Idle      = 0,
    Executing = 1,
    Faulted   = 2,
};

/// Runtime state for a single safety connection's validator. Owned by
/// SafetyValidatorObject; the safety device holds a reference and updates
/// the counters as I/O frames pass through.
struct SafetyValidatorInstance {
    uint32_t instance_id = 0;
    cip::CipInstance* cip_instance = nullptr;
    connections::IoConnection* connection = nullptr;
    SafetyValidatorState state = SafetyValidatorState::Idle;

    // CRC seeds (mirrored from connection at FwdOpen time).
    uint8_t  pid_seed_s1 = 0;
    uint16_t pid_seed_s3 = 0;
    uint32_t pid_seed_s5 = 0;

    // Runtime counters — bumped per-frame by the safety device.
    uint16_t rollover_count = 0;
    uint16_t timestamp = 0;
    uint8_t  ping_count = 0;
    uint32_t packets_produced = 0;
    uint32_t packets_consumed = 0;
    uint32_t crc_errors = 0;

    /// Advance the 128µs timestamp; wraps at 0xFFFF and bumps rollover.
    void advance_timestamp(uint16_t increment) noexcept;
};

/// CIP Safety Validator Object (Class 0x3A). Holds one
/// SafetyValidatorInstance per active safety connection.
class SafetyValidatorObject {
public:
    static constexpr uint32_t ClassCode = 0x3A;

    SafetyValidatorObject();

    [[nodiscard]] cip::CipClass& cip_class() noexcept { return *cip_class_ptr_; }
    [[nodiscard]] std::unique_ptr<cip::CipClass> release_cip_class();

    /// Create a validator instance for a new safety connection.
    /// Returns a non-owning pointer to the runtime state (owned by this object).
    SafetyValidatorInstance* create_instance(connections::IoConnection& connection);

    /// Look up an existing instance by ID. Returns nullptr if not found.
    [[nodiscard]] SafetyValidatorInstance* get_instance(uint32_t instance_id);

private:
    std::unique_ptr<cip::CipClass> cip_class_;
    /// Non-owning pointer captured before `release_cip_class()` hands ownership
    /// to the dispatcher; survives the move so create_instance() can keep
    /// adding instances after registration.
    cip::CipClass* cip_class_ptr_ = nullptr;
    uint32_t next_instance_id_ = 0;
    std::unordered_map<uint32_t, std::unique_ptr<SafetyValidatorInstance>> instances_;
};

} // namespace ethernetip::safety
