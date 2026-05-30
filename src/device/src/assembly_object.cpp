#include "ethernetip/device/assembly_object.hpp"

#include <algorithm>

namespace ethernetip::device {

using namespace ethernetip::cip;

// ---- AssemblyInstance ------------------------------------------------------

AssemblyInstance::AssemblyInstance(uint32_t instance_id, int data_size,
                                      std::optional<std::string> name)
    : instance_id_(instance_id), name_(std::move(name)), data_(data_size) {}

void AssemblyInstance::copy_data_to(std::span<uint8_t> dst) const {
    std::scoped_lock lock(write_mu_);
    size_t n = std::min(dst.size(), data_.size());
    if (n > 0) std::memcpy(dst.data(), data_.data(), n);
}

void AssemblyInstance::set_data(std::span<const uint8_t> source) {
    {
        std::scoped_lock lock(write_mu_);
        size_t n = std::min(source.size(), data_.size());
        if (n > 0) std::memcpy(data_.data(), source.data(), n);
    }
    fire_data_changed();
}

void AssemblyInstance::add_data_changed_handler(DataChangedHandler h) {
    handlers_.push_back(std::move(h));
}

void AssemblyInstance::fire_data_changed() {
    if (handlers_.empty()) return;
    // Snapshot so subscribers see a stable view without holding our lock.
    std::vector<uint8_t> snapshot;
    {
        std::scoped_lock lock(write_mu_);
        snapshot = data_;
    }
    for (auto& h : handlers_) h(instance_id_, snapshot);
}

// ---- AssemblyDataAttribute: subclass that backs the CIP attribute directly --
//
// Both reads (encode_to) and writes (set_data) go through the
// AssemblyInstance so the CIP attribute always reflects the live I/O buffer
// regardless of whether updates come from the CIP side or from application
// code calling AssemblyInstance::set_data / write<T>(...) directly.

namespace {
class AssemblyDataAttribute : public CipAttribute {
public:
    AssemblyDataAttribute(AssemblyInstance& asm_inst)
        : CipAttribute(AssemblyObject::DataAttributeId, CipDataType::Byte,
                       AttributeAccess::GetSingle | AttributeAccess::SetSingle | AttributeAccess::GetAll,
                       std::vector<uint8_t>(asm_inst.data_size())),
          assembly_(asm_inst) {}

    void set_data(std::span<const uint8_t> value) override {
        assembly_.set_data(value);
    }

    int encode_to(std::span<uint8_t> dst) const override {
        assembly_.copy_data_to(dst);
        return assembly_.data_size();
    }

private:
    AssemblyInstance& assembly_;
};
} // namespace

// ---- AssemblyObject --------------------------------------------------------

AssemblyObject::AssemblyObject() {
    cip_class_ = std::make_unique<CipClass>(ClassCode, "Assembly", uint16_t{2});
    cip_class_view_ = cip_class_.get();
    cip_class_->add_standard_instance_services();
}

std::unique_ptr<CipClass> AssemblyObject::release_cip_class() {
    return std::move(cip_class_);   // view pointer keeps working
}

AssemblyInstance& AssemblyObject::add_instance(uint32_t instance_id, int data_size,
                                                  std::optional<std::string> name) {
    auto asm_inst = std::make_unique<AssemblyInstance>(instance_id, data_size, std::move(name));
    CipInstance& cip_inst = cip_class_view_->create_instance(instance_id);

    // Attribute 1: number of members (UINT) = 0 for raw assemblies.
    cip_inst.add_attribute(CipAttribute::create_uint(
        1, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll, uint16_t{0}));
    // Attribute 2: member list (empty for raw).
    cip_inst.add_attribute(std::make_unique<CipAttribute>(
        uint16_t{2}, CipDataType::Uint,
        AttributeAccess::GetSingle, std::vector<uint8_t>{}));
    // Attribute 3: Data — backed by the AssemblyInstance buffer.
    cip_inst.add_attribute(std::make_unique<AssemblyDataAttribute>(*asm_inst));
    // Attribute 4: Size (UINT).
    cip_inst.add_attribute(CipAttribute::create_uint(
        4, CipDataType::Uint,
        AttributeAccess::GetSingle | AttributeAccess::GetAll,
        static_cast<uint16_t>(data_size)));

    cip_inst.set_user_data(asm_inst.get());
    AssemblyInstance& ref = *asm_inst;
    assemblies_[instance_id] = std::move(asm_inst);
    return ref;
}

AssemblyInstance* AssemblyObject::get_assembly(uint32_t instance_id) {
    auto it = assemblies_.find(instance_id);
    return it == assemblies_.end() ? nullptr : it->second.get();
}

} // namespace ethernetip::device
