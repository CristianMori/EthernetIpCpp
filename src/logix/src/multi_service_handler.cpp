#include "ethernetip/logix/multi_service_handler.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/cip/dispatch_depth.hpp"
#include "ethernetip/cip/mr_codec.hpp"

namespace ethernetip::logix::multi_service_handler {

using cip::CipServiceRequest;
using cip::CipServiceResponse;
using cip::CipStatus;
namespace ser = cip::serializer;
namespace depth = cip::dispatch_depth;

CipServiceResponse handle(cip::ICipDispatch& dispatch, const CipServiceRequest& request) {
    // Shared with Unconnected_Send and any other re-entrant service — a
    // UCS→MSP→UCS→... chain exhausts the C stack just as surely as a pure
    // MSP→MSP chain, so one counter covers the whole combined call chain.
    if (depth::exceeded()) {
        return CipServiceResponse::error(request.service_code,
                                          CipStatus::error(CipStatus::ServiceNotSupported));
    }
    depth::Guard depth_guard;

    if (request.data.size() < 2) {
        return CipServiceResponse::error(request.service_code, CipStatus::error(0x13));
    }
    uint16_t service_count = ser::read_uint(request.data);
    int header_size = 2 + service_count * 2;
    if (request.data.size() < static_cast<size_t>(header_size)) {
        return CipServiceResponse::error(request.service_code, CipStatus::error(0x13));
    }

    std::vector<uint16_t> offsets(service_count);
    for (uint16_t i = 0; i < service_count; ++i) {
        offsets[i] = ser::read_uint(request.data.subspan(2u + i * 2u));
    }

    // Validate the whole offset table before touching any sub-request. A
    // non-monotonic entry makes sub_end - sub_start wrap in the signed int
    // below; a trailing offset past request.data.size() lets subspan read
    // off the end. We also require offsets[i] >= table_end so a crafted
    // table cannot point sub-requests back into the offset array itself.
    const size_t data_size = request.data.size();
    const size_t table_end = 2u + static_cast<size_t>(service_count) * 2u;
    for (uint16_t i = 0; i < service_count; ++i) {
        if (offsets[i] < table_end || offsets[i] > data_size) {
            return CipServiceResponse::error(request.service_code, CipStatus::error(0x13));
        }
        if (i + 1 < service_count && offsets[i] > offsets[i + 1]) {
            return CipServiceResponse::error(request.service_code, CipStatus::error(0x13));
        }
    }

    // Encode each sub-response and stash the bytes.
    std::vector<std::vector<uint8_t>> responses(service_count);
    std::vector<uint8_t> encode_buf(520);
    for (uint16_t i = 0; i < service_count; ++i) {
        int sub_start = offsets[i];
        int sub_end   = (i + 1 < service_count)
            ? offsets[i + 1]
            : static_cast<int>(request.data.size());
        auto sub_data = request.data.subspan(sub_start, sub_end - sub_start);

        auto parsed = cip::mr_codec::try_parse_request(sub_data);
        CipServiceResponse sub_resp;
        if (!parsed.has_value()) {
            sub_resp = CipServiceResponse::error(0, CipStatus::error(0x13));
        } else {
            sub_resp = dispatch.dispatch(parsed->service_code, parsed->path, parsed->data);
        }
        int resp_len = sub_resp.encode(encode_buf);
        if (resp_len < 0) {
            // Sub-response is too large for the per-sub buffer. The depth cap
            // bounds recursion, but a nested MSP (or any oversized sub-reply)
            // can still exceed encode_buf's capacity — encoding it unchecked
            // would overflow the heap. Replace the oversized reply with a
            // size-error response for this sub-service and continue so the
            // remaining sub-services still get processed.
            uint8_t svc = static_cast<uint8_t>(sub_resp.service_code & 0x7F);
            sub_resp = CipServiceResponse::error(
                svc, CipStatus::error(CipStatus::TooMuchData));
            resp_len = sub_resp.encode(encode_buf);
        }
        responses[i].assign(encode_buf.begin(), encode_buf.begin() + resp_len);
    }

    int resp_header = 2 + service_count * 2;
    int total = resp_header;
    for (const auto& r : responses) total += static_cast<int>(r.size());

    std::vector<uint8_t> result(total);
    int offset = 0;
    ser::write_uint(result, service_count);
    offset += 2;

    int current = resp_header;
    for (uint16_t i = 0; i < service_count; ++i) {
        ser::write_uint(std::span<uint8_t>(result).subspan(offset),
                         static_cast<uint16_t>(current));
        offset  += 2;
        current += static_cast<int>(responses[i].size());
    }
    for (const auto& r : responses) {
        std::copy(r.begin(), r.end(), result.begin() + offset);
        offset += static_cast<int>(r.size());
    }
    return CipServiceResponse::success(request.service_code, std::move(result));
}

} // namespace ethernetip::logix::multi_service_handler
