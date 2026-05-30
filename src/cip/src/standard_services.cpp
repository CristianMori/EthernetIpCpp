#include "ethernetip/cip/standard_services.hpp"

#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/cip_instance.hpp"

namespace ethernetip::cip::standard_services {

CipServiceResponse handle_get_attribute_single(CipInstance& instance,
                                                const CipServiceRequest& request) {
    if (!request.path.attribute_id.has_value()) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::PathSegmentError));
    }
    auto* attr = instance.get_attribute(*request.path.attribute_id);
    if (attr == nullptr) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::AttributeNotSupported));
    }
    if (!has_flag(attr->access(), AttributeAccess::GetSingle)) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::AttributeNotSupported));
    }
    std::vector<uint8_t> payload(attr->data_length());
    attr->encode_to(payload);
    return CipServiceResponse::success(request.service_code, std::move(payload));
}

CipServiceResponse handle_set_attribute_single(CipInstance& instance,
                                                const CipServiceRequest& request) {
    if (!request.path.attribute_id.has_value()) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::PathSegmentError));
    }
    auto* attr = instance.get_attribute(*request.path.attribute_id);
    if (attr == nullptr) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::AttributeNotSupported));
    }
    if (!has_flag(attr->access(), AttributeAccess::SetSingle)) {
        return CipServiceResponse::error(request.service_code,
            CipStatus::error(CipStatus::AttributeNotSettable));
    }
    attr->set_data(request.data);
    return CipServiceResponse::success(request.service_code);
}

CipServiceResponse handle_get_attribute_all(CipInstance& instance,
                                             const CipServiceRequest& request) {
    // 4 KB initial buffer matches C# ArrayPool.Rent(4096). Resized down to
    // exactly the encoded size before returning, so no waste in the response.
    std::vector<uint8_t> buf(4096);
    int len = instance.encode_all_attributes(buf);
    buf.resize(len);
    return CipServiceResponse::success(request.service_code, std::move(buf));
}

} // namespace ethernetip::cip::standard_services
