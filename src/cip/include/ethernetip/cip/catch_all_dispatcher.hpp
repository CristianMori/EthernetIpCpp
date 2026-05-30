#pragma once

#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/cip_service.hpp"
#include "ethernetip/cip/cip_status.hpp"

#include <cstdint>
#include <functional>
#include <span>
#include <utility>
#include <vector>

namespace ethernetip::cip {

/// View of an incoming CIP request that didn't match any registered class.
/// Field pointers/spans are owned by the dispatcher for the duration of the
/// handler call.
struct CatchAllRequest {
    uint8_t                  service_code;
    const CipPath*           path;
    std::span<const uint8_t> data;
};

/// What a CatchAllDispatcher handler returns. Leave `data` empty to send a
/// reply with no payload; set `status` non-zero to indicate an error
/// (CipStatus::* codes). `status == 0` = Success.
struct CatchAllReply {
    std::vector<uint8_t> data;
    uint8_t              status = 0;
};

/// A CipDispatcher subclass that routes every otherwise-unmatched request
/// through a user-supplied handler. Useful for echo servers, sniffers, and
/// adapters that want a single fall-through hook without subclassing.
///
/// Classes registered via register_class() still go through the standard
/// class → instance → service routing; only requests that fall through to
/// on_unhandled hit the handler.
class CatchAllDispatcher : public CipDispatcher {
public:
    using Handler = std::function<CatchAllReply(const CatchAllRequest&)>;

    /// Install (or replace) the catch-all handler. With no handler set the
    /// dispatcher behaves like the base CipDispatcher and returns the
    /// would-have-been error status.
    void set_handler(Handler h) { handler_ = std::move(h); }

protected:
    CipServiceResponse on_unhandled(uint8_t service_code,
                                      const CipPath& path,
                                      std::span<const uint8_t> data,
                                      uint8_t default_status) override {
        if (!handler_) {
            return CipDispatcher::on_unhandled(service_code, path, data, default_status);
        }
        CatchAllRequest req{service_code, &path, data};
        CatchAllReply reply = handler_(req);
        if (reply.status != 0) {
            return CipServiceResponse::error(service_code, CipStatus::error(reply.status));
        }
        return CipServiceResponse::success(service_code, std::move(reply.data));
    }

private:
    Handler handler_;
};

} // namespace ethernetip::cip
