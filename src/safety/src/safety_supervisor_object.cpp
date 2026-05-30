#include "ethernetip/safety/safety_supervisor_object.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/standard_services.hpp"

#include <cstring>

namespace ethernetip::safety {

using namespace ethernetip::cip;

SafetySupervisorObject::SafetySupervisorObject(SafetyNetworkNumber snn, uint32_t node_address)
    : snn_(snn), tunid_{snn, node_address} {

    cip_class_ = std::make_unique<CipClass>(ClassCode, "Safety Supervisor", uint16_t{1});
    cip_class_ptr_ = cip_class_.get();  // survives release_cip_class()
    cip_class_->add_standard_instance_services();

    CipInstance& inst = cip_class_->create_instance(1);

    // Attr 1: State (USINT).
    inst.add_attribute(CipAttribute::create_byte(
        1, CipDataType::Usint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        static_cast<uint8_t>(state_)));
    // Attr 2: Mode (USINT).
    inst.add_attribute(CipAttribute::create_byte(
        2, CipDataType::Usint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        static_cast<uint8_t>(mode_)));

    // Attr 3: Safety Network Number (6 bytes).
    {
        std::vector<uint8_t> snn_bytes(6);
        snn_.copy_to(snn_bytes);
        inst.add_attribute(std::make_unique<CipAttribute>(
            uint16_t{3}, CipDataType::Byte,
            AttributeAccess::GetSingle | AttributeAccess::GetAll,
            std::move(snn_bytes)));
    }

    // Attr 4: Configuration Lock (USINT, 0 = unlocked).
    inst.add_attribute(CipAttribute::create_byte(
        4, CipDataType::Usint,
        AttributeAccess::GetSingle | AttributeAccess::SetSingle | AttributeAccess::GetAll,
        uint8_t{0}));

    // Attr 6: Safety Configuration Identifier (10 bytes, zeros = unconfigured).
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{6}, CipDataType::Byte,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        std::vector<uint8_t>(SafetyConfigurationId::Size)));

    // Attr 25 (0x19): Configuration UNID (10 bytes, zeros = unowned).
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{25}, CipDataType::Byte,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        std::vector<uint8_t>(UniqueNetworkId::Size)));

    // Attr 27 (0x1B): Target UNID (10 bytes).
    {
        std::vector<uint8_t> tunid_bytes(UniqueNetworkId::Size);
        tunid_.copy_to(tunid_bytes);
        inst.add_attribute(std::make_unique<CipAttribute>(
            uint16_t{27}, CipDataType::Byte,
            AttributeAccess::GetSingle | AttributeAccess::GetAll,
            std::move(tunid_bytes)));
    }

    // Attr 28 (0x1C): Output Connection Point Owners — 0 entries.
    inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{28}, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        std::vector<uint8_t>{0x00, 0x00}));

    cip_class_->add_instance_service({
        SafetyResetService, "Safety_Reset",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_safety_reset(i, r);
        }});
    cip_class_->add_instance_service({
        ProposeTunidService, "Propose_TUNID",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_propose_tunid(i, r);
        }});
    cip_class_->add_instance_service({
        ApplyTunidService, "Apply_TUNID",
        [this](CipInstance& i, const CipServiceRequest& r) {
            return handle_apply_tunid(i, r);
        }});
}

std::unique_ptr<CipClass> SafetySupervisorObject::release_cip_class() {
    return std::move(cip_class_);
}

void SafetySupervisorObject::start() {
    state_ = SafetySupervisorState::Executing;
    mode_  = SafetySupervisorMode::Run;
    update_state_attribute();
}

void SafetySupervisorObject::abort() {
    state_ = SafetySupervisorState::Abort;
    update_state_attribute();
}

void SafetySupervisorObject::reset() {
    state_ = SafetySupervisorState::Idle;
    mode_  = SafetySupervisorMode::Idle;
    update_state_attribute();
}

void SafetySupervisorObject::update_state_attribute() {
    if (cip_class_ptr_ == nullptr) return;
    CipInstance* inst = cip_class_ptr_->get_instance(1);
    if (inst == nullptr) return;
    if (auto* a = inst->get_attribute(1)) {
        uint8_t v = static_cast<uint8_t>(state_);
        a->set_data(std::span<const uint8_t>(&v, 1));
    }
    if (auto* a = inst->get_attribute(2)) {
        uint8_t v = static_cast<uint8_t>(mode_);
        a->set_data(std::span<const uint8_t>(&v, 1));
    }
}

CipServiceResponse SafetySupervisorObject::handle_safety_reset(
        CipInstance& inst, const CipServiceRequest& request) {
    if (request.data.size() < 1) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::NotEnoughData));
    }
    uint8_t reset_type = request.data[0];
    switch (reset_type) {
        case 0:
        case 1:
            reset();
            return CipServiceResponse::success(request.service_code);
        case 2: {
            // Reset ownership: clear CFUNID, owner list, SCID, TUNID-assigned.
            if (auto* a25 = inst.get_attribute(25)) {
                a25->set_data(std::vector<uint8_t>(UniqueNetworkId::Size));
            }
            if (auto* a28 = inst.get_attribute(28)) {
                a28->set_data(std::vector<uint8_t>{0x00, 0x00});
            }
            scid_ = SafetyConfigurationId{};
            tunid_assigned_ = false;
            proposed_tunid_.reset();
            return CipServiceResponse::success(request.service_code);
        }
        default:
            return CipServiceResponse::error(request.service_code,
                CipStatus::error(CipStatus::InvalidParameter));
    }
}

CipServiceResponse SafetySupervisorObject::handle_propose_tunid(
        CipInstance&, const CipServiceRequest& request) {
    if (request.data.size() < static_cast<size_t>(UniqueNetworkId::Size)) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::NotEnoughData));
    }
    // All-0xFF means cancel pending proposal.
    bool all_ff = true;
    for (int i = 0; i < UniqueNetworkId::Size && all_ff; ++i) {
        if (request.data[i] != 0xFF) all_ff = false;
    }
    if (all_ff) {
        proposed_tunid_.reset();
        return CipServiceResponse::success(request.service_code);
    }
    proposed_tunid_ = UniqueNetworkId::parse(request.data.first(UniqueNetworkId::Size));
    return CipServiceResponse::success(request.service_code);
}

CipServiceResponse SafetySupervisorObject::handle_apply_tunid(
        CipInstance& inst, const CipServiceRequest& request) {
    if (request.data.size() < static_cast<size_t>(UniqueNetworkId::Size)) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::NotEnoughData));
    }
    if (!proposed_tunid_.has_value()) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(0x0C));  // Object state conflict — no pending proposal
    }
    auto applied = UniqueNetworkId::parse(request.data.first(UniqueNetworkId::Size));
    std::vector<uint8_t> prop_buf(UniqueNetworkId::Size);
    proposed_tunid_->copy_to(prop_buf);
    std::vector<uint8_t> apply_buf(UniqueNetworkId::Size);
    applied.copy_to(apply_buf);
    if (prop_buf != apply_buf) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::InvalidParameter));
    }

    tunid_ = applied;
    snn_   = applied.snn;
    tunid_assigned_ = true;
    proposed_tunid_.reset();

    std::vector<uint8_t> tunid_bytes(UniqueNetworkId::Size);
    tunid_.copy_to(tunid_bytes);
    if (auto* a27 = inst.get_attribute(27)) a27->set_data(tunid_bytes);

    std::vector<uint8_t> snn_bytes(6);
    snn_.copy_to(snn_bytes);
    if (auto* a3 = inst.get_attribute(3)) a3->set_data(snn_bytes);

    return CipServiceResponse::success(request.service_code);
}

} // namespace ethernetip::safety
