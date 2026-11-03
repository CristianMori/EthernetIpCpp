#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/connections/connection_manager.hpp"

#include <gtest/gtest.h>

using namespace ethernetip::connections;
using namespace ethernetip::cip;
namespace ser = ethernetip::cip::serializer;

namespace {

std::vector<uint8_t> make_fwd_open_data() {
    // Path uses the assembly shortcut so the parser populates consumed/produced
    // and validate_assembly is actually invoked:
    //   20 04 24 05 2C 64 2C 66 -> class 4, config inst 5, OT cp 100, TO cp 102
    std::vector<uint8_t> data(44);
    data[0] = 0x05;
    data[1] = 0x9C;
    ser::write_udint(std::span<uint8_t>(data).subspan(2), 0u);
    ser::write_udint(std::span<uint8_t>(data).subspan(6), 0x10001234u);
    ser::write_uint (std::span<uint8_t>(data).subspan(10), uint16_t{0x4321});
    ser::write_uint (std::span<uint8_t>(data).subspan(12), uint16_t{0x0001});
    ser::write_udint(std::span<uint8_t>(data).subspan(14), 0xC0FFEE42u);
    data[18] = 1;
    ser::write_udint(std::span<uint8_t>(data).subspan(22), 20000u);
    ser::write_uint (std::span<uint8_t>(data).subspan(26), uint16_t{0x4007});
    ser::write_udint(std::span<uint8_t>(data).subspan(28), 20000u);
    ser::write_uint (std::span<uint8_t>(data).subspan(32), uint16_t{0x4007});
    data[34] = 0xA1;
    data[35] = 0x04;       // path size = 4 words = 8 bytes
    data[36] = 0x20; data[37] = 0x04; data[38] = 0x24; data[39] = 0x05;
    data[40] = 0x2C; data[41] = 0x64; data[42] = 0x2C; data[43] = 0x66;
    return data;
}

} // namespace

TEST(ConnectionManagerTest, ForwardOpenSucceeds) {
    ConnectionManagerObject mgr;
    mgr.validate_assembly = [](uint32_t) { return 16; };   // always say "exists, 16B"

    int established_count = 0;
    mgr.on_connection_established.push_back([&](IoConnection&) { ++established_count; });

    auto svc_data = make_fwd_open_data();
    auto resp = mgr.cip_class().get_instance_service(ConnectionManagerObject::ForwardOpenService)
                  ->handler(*mgr.cip_class().get_instance(1),
                            CipServiceRequest{ConnectionManagerObject::ForwardOpenService,
                                                CipPath{}, svc_data});
    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(1, established_count);
    EXPECT_EQ(26u, resp.data.size());        // 26-byte non-safety response

    auto conns = mgr.active_connections();
    ASSERT_EQ(1u, conns.size());
    EXPECT_EQ(0x4321, conns[0]->connection_serial_number);
    EXPECT_EQ(0xC0FFEE42u, conns[0]->originator_serial_number);
}

TEST(ConnectionManagerTest, DuplicateTriadRejected) {
    ConnectionManagerObject mgr;
    mgr.validate_assembly = [](uint32_t) { return 16; };
    auto svc_data = make_fwd_open_data();
    const auto* svc = mgr.cip_class().get_instance_service(ConnectionManagerObject::ForwardOpenService);
    auto& inst = *mgr.cip_class().get_instance(1);

    auto resp1 = svc->handler(inst, CipServiceRequest{0x54, CipPath{}, svc_data});
    EXPECT_TRUE(resp1.status.is_success());

    auto resp2 = svc->handler(inst, CipServiceRequest{0x54, CipPath{}, svc_data});
    EXPECT_FALSE(resp2.status.is_success());
    ASSERT_EQ(1u, resp2.status.additional_status.size());
    EXPECT_EQ(0x0100, resp2.status.additional_status[0]);   // Connection in use
}

TEST(ConnectionManagerTest, ForwardCloseRemovesConnection) {
    ConnectionManagerObject mgr;
    mgr.validate_assembly = [](uint32_t) { return 16; };
    auto svc_data = make_fwd_open_data();
    const auto* open_svc  = mgr.cip_class().get_instance_service(0x54);
    const auto* close_svc = mgr.cip_class().get_instance_service(0x4E);
    auto& inst = *mgr.cip_class().get_instance(1);

    auto open_resp = open_svc->handler(inst, CipServiceRequest{0x54, CipPath{}, svc_data});
    ASSERT_TRUE(open_resp.status.is_success());

    int removed = 0;
    mgr.on_connection_removed.push_back([&](IoConnection&) { ++removed; });

    // Forward Close payload: priority(1) + timeout(1) + conn_serial(2) + vendor(2) + serial(4) + pad(2)
    std::vector<uint8_t> close_data(12);
    close_data[0] = 0x05; close_data[1] = 0x9C;
    ser::write_uint (std::span<uint8_t>(close_data).subspan(2), uint16_t{0x4321});
    ser::write_uint (std::span<uint8_t>(close_data).subspan(4), uint16_t{0x0001});
    ser::write_udint(std::span<uint8_t>(close_data).subspan(6), 0xC0FFEE42u);

    auto close_resp = close_svc->handler(inst, CipServiceRequest{0x4E, CipPath{}, close_data});
    EXPECT_TRUE(close_resp.status.is_success());
    EXPECT_EQ(1, removed);
    EXPECT_TRUE(mgr.active_connections().empty());
}

TEST(ConnectionManagerTest, UnconnectedSendDepthCapped) {
    // A hostile client nests Unconnected_Send inside Unconnected_Send to
    // blow the C stack through the dispatch call chain. Without a depth
    // cap this crashes the process. With the cap, the server returns the
    // nested dispatch's cap-exceeded error (service not supported) and
    // the stack stays bounded.
    ConnectionManagerObject mgr;

    // dispatch_request routes UCS back into the handler, so a nested UCS
    // MR re-enters handle_unconnected_send exactly as it would through
    // the real dispatcher in VirtualDevice.
    const auto* ucs_svc = mgr.cip_class().get_instance_service(
                                ConnectionManagerObject::UnconnectedSendService);
    ASSERT_NE(nullptr, ucs_svc);
    auto& ucs_inst = *mgr.cip_class().get_instance(1);

    mgr.dispatch_request = [&](uint8_t service_code, const CipPath&,
                                 std::span<const uint8_t> data) -> CipServiceResponse {
        if (service_code == ConnectionManagerObject::UnconnectedSendService) {
            std::vector<uint8_t> buf(data.begin(), data.end());
            return ucs_svc->handler(
                ucs_inst,
                CipServiceRequest{ConnectionManagerObject::UnconnectedSendService,
                                    CipPath{}, buf});
        }
        // Innermost echo — succeed cleanly so the only possible failure
        // route is the depth cap.
        return CipServiceResponse::success(service_code, {});
    };

    // MR of service 0x52 at class 6 instance 1, carrying `data` payload.
    auto make_ucs_mr = [](const std::vector<uint8_t>& data) {
        std::vector<uint8_t> mr;
        mr.push_back(0x52);                       // service
        mr.push_back(0x02);                       // path size words
        mr.insert(mr.end(), {0x20, 0x06, 0x24, 0x01});  // class 6 inst 1
        mr.insert(mr.end(), data.begin(), data.end());
        return mr;
    };
    // UCS data payload: priority/time_tick + timeout_ticks + msg_len + embedded_mr.
    auto make_ucs_data = [](const std::vector<uint8_t>& embedded_mr) {
        std::vector<uint8_t> d;
        d.push_back(0x05);
        d.push_back(0x9C);
        uint16_t len = static_cast<uint16_t>(embedded_mr.size());
        d.push_back(static_cast<uint8_t>(len & 0xFF));
        d.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        d.insert(d.end(), embedded_mr.begin(), embedded_mr.end());
        return d;
    };

    // Innermost MR: Get_Attribute_Single on class 1 inst 1 attr 1 — never
    // actually reached because the dispatch lambda intercepts UCS; even if
    // it were, the lambda returns success for anything non-UCS.
    std::vector<uint8_t> innermost_mr = {0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01};

    // Build a 10-level-deep UCS chain, inside out.
    std::vector<uint8_t> data = make_ucs_data(innermost_mr);
    for (int i = 1; i < 10; ++i) {
        data = make_ucs_data(make_ucs_mr(data));
    }

    auto resp = ucs_svc->handler(
        ucs_inst,
        CipServiceRequest{ConnectionManagerObject::UnconnectedSendService,
                            CipPath{}, data});

    // Depth cap must have fired — the top-level handler returns the nested
    // dispatch's error unchanged, which is Service Not Supported (0x08).
    EXPECT_FALSE(resp.status.is_success());
    EXPECT_EQ(CipStatus::ServiceNotSupported, resp.status.general_status);
}

TEST(ConnectionManagerTest, RejectsMissingAssembly) {
    ConnectionManagerObject mgr;
    mgr.validate_assembly = [](uint32_t) { return -1; };  // none exist
    auto svc_data = make_fwd_open_data();
    auto resp = mgr.cip_class().get_instance_service(0x54)
                  ->handler(*mgr.cip_class().get_instance(1),
                              CipServiceRequest{0x54, CipPath{}, svc_data});
    EXPECT_FALSE(resp.status.is_success());
    ASSERT_EQ(1u, resp.status.additional_status.size());
    EXPECT_EQ(0x0116, resp.status.additional_status[0]);
}
