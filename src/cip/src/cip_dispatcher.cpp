#include "ethernetip/cip/cip_dispatcher.hpp"

namespace ethernetip::cip {

void CipDispatcher::register_class(std::unique_ptr<CipClass> cls) {
    uint32_t code = cls->class_code();
    classes_[code] = std::move(cls);
}

CipClass* CipDispatcher::get_class(uint32_t class_code) const {
    auto it = classes_.find(class_code);
    return it == classes_.end() ? nullptr : it->second.get();
}

CipServiceResponse CipDispatcher::dispatch(uint8_t service_code,
                                             const CipPath& path,
                                             std::span<const uint8_t> data) {
    // No class in path — delegate to subclass for symbolic addressing.
    if (!path.class_id.has_value()) {
        return on_unhandled(service_code, path, data, CipStatus::PathDestinationUnknown);
    }

    auto it = classes_.find(*path.class_id);
    if (it == classes_.end()) {
        return on_unhandled(service_code, path, data, CipStatus::PathDestinationUnknown);
    }
    CipClass& cls = *it->second;

    uint32_t instance_id = path.instance_id.value_or(0);
    bool is_class_level = instance_id == 0;

    CipInstance* instance = cls.get_instance(instance_id);
    if (instance == nullptr) {
        return on_unhandled(service_code, path, data, CipStatus::ObjectDoesNotExist);
    }

    const auto* service = cls.get_service(service_code, is_class_level);
    if (service == nullptr) {
        return on_unhandled(service_code, path, data, CipStatus::ServiceNotSupported);
    }

    CipServiceRequest req{service_code, path, data};
    return service->handler(*instance, req);
}

CipServiceResponse CipDispatcher::on_unhandled(uint8_t service_code,
                                                 const CipPath& /*path*/,
                                                 std::span<const uint8_t> /*data*/,
                                                 uint8_t default_status) {
    return CipServiceResponse::error(service_code, CipStatus::error(default_status));
}

} // namespace ethernetip::cip
