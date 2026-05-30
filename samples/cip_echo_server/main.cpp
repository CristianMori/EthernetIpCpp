// Catch-all CIP echo server.
//
// Listens on TCP 44818, handles RegisterSession, SendRRData (UCMM), and
// SendUnitData (Class 3 connected explicit). For each inbound CIP service
// request, prints the service code, the parsed EPATH (class / instance /
// attribute / element / symbolic), and the request data in hex — then
// returns a Success response with an empty payload.
//
// Useful for capturing whatever a Logix MSG instruction (or any other
// client) sends at us: pointing the MSG path at this host will show the
// exact bytes received on this console.
//
// Usage:  cip_echo_server [<bind>] [<tcp_port>]

#include "ethernetip/cip/catch_all_dispatcher.hpp"
#include "ethernetip/cip/cip_attribute.hpp"
#include "ethernetip/cip/cip_class.hpp"
#include "ethernetip/cip/cip_service.hpp"
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/connections/connection_manager.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

using namespace std::chrono_literals;

namespace {
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }
} // namespace

int main(int argc, char** argv) {
    std::string bind = (argc > 1) ? argv[1] : "0.0.0.0";
    int         port = (argc > 2) ? std::atoi(argv[2]) : 44818;
    int         reply_bytes = (argc > 3) ? std::atoi(argv[3]) : 0;

    ethernetip::cip::IdentityInfo identity;
    identity.vendor_id      = 0x0001;
    identity.device_type    = 0x000C;
    identity.product_code   = 0xCAFE;
    identity.major_revision = 1;
    identity.minor_revision = 0;
    identity.serial_number  = 0xC1500001;
    identity.product_name   = "EthernetIPCpp CIP Echo Server";
    identity.status         = 0x0000;

    ethernetip::cip::CatchAllDispatcher dispatcher;

    // Catch-all handler: logs the request, then optionally returns
    // `reply_bytes` bytes of incremental data (0, 1, 2, ..., reply_bytes-1)
    // so a Logix MSG with a Destination Tag receives a recognizable pattern.
    std::mutex log_mu;
    uint64_t   request_count = 0;
    dispatcher.set_handler(
        [&log_mu, &request_count, reply_bytes](const ethernetip::cip::CatchAllRequest& req)
            -> ethernetip::cip::CatchAllReply {
            std::scoped_lock lock(log_mu);
            ++request_count;
            const auto& path = *req.path;
            std::printf("[#%llu] svc=0x%02X  ",
                         static_cast<unsigned long long>(request_count), req.service_code);
            std::printf("class=");
            if (path.class_id) std::printf("0x%02X", *path.class_id); else std::printf("-");
            std::printf("  instance=");
            if (path.instance_id) std::printf("%u", *path.instance_id); else std::printf("-");
            std::printf("  attribute=");
            if (path.attribute_id) std::printf("%u", *path.attribute_id); else std::printf("-");
            std::printf("  element=");
            if (path.element_id) std::printf("%u", *path.element_id); else std::printf("-");
            std::printf("  conn_pt=");
            if (path.connection_point) std::printf("%u", *path.connection_point); else std::printf("-");
            std::printf("  symbol=");
            if (path.symbolic_name) std::printf("%s", path.symbolic_name->c_str()); else std::printf("-");
            std::printf("  data(%zu)=", req.data.size());
            for (size_t i = 0; i < req.data.size() && i < 64; ++i) {
                std::printf("%02X ", req.data[i]);
            }
            if (req.data.size() > 64) std::printf("...");
            std::printf("\n");
            std::fflush(stdout);

            ethernetip::cip::CatchAllReply reply;
            reply.data.resize(reply_bytes);
            for (int i = 0; i < reply_bytes; ++i) {
                reply.data[i] = static_cast<uint8_t>(i);
            }
            return reply;
        });

    // Identity Object (Class 0x01) — needed so RegisterSession / ListIdentity
    // see a real device. Single instance with the standard attribute set.
    {
        auto id_class = std::make_unique<ethernetip::cip::CipClass>(
            ethernetip::cip::IdentityInfo::ClassCode, "Identity", uint16_t{1});
        id_class->add_standard_instance_services();
        auto& inst = id_class->create_instance(1);
        using AA = ethernetip::cip::AttributeAccess;
        using DT = ethernetip::cip::CipDataType;
        inst.add_attribute(ethernetip::cip::CipAttribute::create_uint (1, DT::Uint,  AA::GetSingle | AA::GetAll, identity.vendor_id));
        inst.add_attribute(ethernetip::cip::CipAttribute::create_uint (2, DT::Uint,  AA::GetSingle | AA::GetAll, identity.device_type));
        inst.add_attribute(ethernetip::cip::CipAttribute::create_uint (3, DT::Uint,  AA::GetSingle | AA::GetAll, identity.product_code));
        inst.add_attribute(std::make_unique<ethernetip::cip::CipAttribute>(
            uint16_t{4}, DT::Usint, AA::GetSingle | AA::GetAll,
            std::vector<uint8_t>{identity.major_revision, identity.minor_revision}));
        inst.add_attribute(ethernetip::cip::CipAttribute::create_uint (5, DT::Word,  AA::GetSingle | AA::GetAll, identity.status));
        inst.add_attribute(ethernetip::cip::CipAttribute::create_udint(6, DT::Udint, AA::GetSingle | AA::GetAll, identity.serial_number));
        inst.add_attribute(ethernetip::cip::CipAttribute::create_short_string(
            7, AA::GetSingle | AA::GetAll, identity.product_name));
        dispatcher.register_class(std::move(id_class));
    }

    // Connection Manager (Class 0x06) — required so the PLC can send
    // Unconnected Send (svc 0x52) and Forward Open (svc 0x54). The CM's
    // Unconnected Send handler unwraps the inner CIP request and calls
    // back into our dispatcher; an inner request that doesn't match any
    // registered class lands in LoggingDispatcher::on_unhandled, which is
    // exactly where we want to see the PLC's MSG payload.
    auto conn_mgr = std::make_unique<ethernetip::connections::ConnectionManagerObject>();
    conn_mgr->dispatch_request =
        [&dispatcher](uint8_t svc, const ethernetip::cip::CipPath& p,
                       std::span<const uint8_t> d) {
            return dispatcher.dispatch(svc, p, d);
        };
    auto* conn_mgr_raw = conn_mgr.get();   // borrow before release moves the CipClass
    dispatcher.register_class(conn_mgr->release_cip_class());

    ethernetip::protocol::EipAdapter adapter(dispatcher, identity);

    // Translate OT_conn_id (in incoming SendUnitData) → TO_conn_id (for the
    // reply's ConnectedAddress item). Without this, Logix MSG ignores our
    // Class 3 explicit replies as "not for me" and times out with EXTERR 0x23.
    adapter.set_connection_id_lookup([conn_mgr_raw](uint32_t oto_t_id) -> uint32_t {
        auto* conn = conn_mgr_raw->find_by_oto_t_id(oto_t_id);
        return conn != nullptr ? conn->tto_o_connection_id : 0u;
    });

    adapter.listen(ethernetip::protocol::IpEndpoint{bind, static_cast<uint16_t>(port)});

    std::printf("=== CIP Echo Server ===\n"
                 "Listening on %s:%d\n"
                 "Reply payload: %d byte(s)%s\n"
                 "Every incoming CIP request will be printed below.\n"
                 "Ctrl+C to stop.\n\n",
                 bind.c_str(), port, reply_bytes,
                 reply_bytes > 0 ? " of incremental data (0,1,2,...)" : " (empty)");

#ifndef _WIN32
    std::signal(SIGTERM, on_signal);
#endif
    std::signal(SIGINT, on_signal);

    while (!g_stop.load()) std::this_thread::sleep_for(200ms);

    std::printf("\nStopping ...\n");
    adapter.stop();
    return 0;
}
