#include "ethernetip/cip/cip_path.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <array>
#include <cstring>
#include <gtest/gtest.h>

using namespace ethernetip::logix;
namespace ldt = logix_data_types;
namespace ser = ethernetip::cip::serializer;

// Build a CipPath for an ANSI Extended Symbolic name (single segment).
static ethernetip::cip::CipPath make_symbolic_path(std::string_view name) {
    ethernetip::cip::CipPath p;
    p.symbolic_name = std::string(name);
    return p;
}

TEST(LogixDispatcherTest, SymbolicReadRoundTrip) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counter", ldt::Dint);
    tag.write<int32_t>(0, 0xABCD1234);

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);  // element_count
    auto resp = disp.dispatch(tag_services::ReadTag, make_symbolic_path("counter"), req);
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(6u, resp.data.size());
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(0xABCD1234u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(LogixDispatcherTest, SymbolicWriteRoundTrip) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("setpoint", ldt::Dint);

    std::array<uint8_t, 8> req{};
    ser::write_uint(req, ldt::Dint);
    ser::write_uint(std::span<uint8_t>(req).subspan(2), 1);
    ser::write_udint(std::span<uint8_t>(req).subspan(4), 0xFEEDFACE);
    auto resp = disp.dispatch(tag_services::WriteTag, make_symbolic_path("setpoint"), req);
    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(static_cast<int32_t>(0xFEEDFACE), tag.read<int32_t>(0));
}

TEST(LogixDispatcherTest, UnknownSymbolReturnsPathDestinationUnknown) {
    LogixDispatcher disp;
    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = disp.dispatch(tag_services::ReadTag, make_symbolic_path("doesnotexist"), req);
    EXPECT_EQ(0x05, resp.status.general_status);
}

TEST(LogixDispatcherTest, SymbolObjectInstanceReadByInstanceId) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("temperature", ldt::Real);
    float f = 72.5f;
    std::array<uint8_t, 4> buf{};
    std::memcpy(buf.data(), &f, 4);
    tag.set_data(buf);

    ethernetip::cip::CipPath p;
    p.class_id = SymbolObject::ClassCode;
    p.instance_id = tag.instance_id();

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);
    auto resp = disp.dispatch(tag_services::ReadTag, p, req);
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(6u, resp.data.size());
    EXPECT_EQ(ldt::Real, ser::read_uint(resp.data));
    float got = 0;
    std::memcpy(&got, resp.data.data() + 2, 4);
    EXPECT_FLOAT_EQ(72.5f, got);
}

TEST(LogixDispatcherTest, MessageRouterMultipleServicePacket) {
    LogixDispatcher disp;
    auto& a = disp.tags().add_tag("a", ldt::Dint);
    auto& b = disp.tags().add_tag("b", ldt::Dint);
    a.write<int32_t>(0, 11);
    b.write<int32_t>(0, 22);

    // Build two sub-requests using the MR codec format: svc + path_words + path + data
    auto build_read_req = [](std::string_view name) {
        // EPATH = ANSI symbolic segment (0x91 + len + chars + pad)
        size_t n = name.size();
        size_t pad = (n % 2 == 0) ? 0 : 1;
        std::vector<uint8_t> path;
        path.push_back(0x91);
        path.push_back(static_cast<uint8_t>(n));
        for (char c : name) path.push_back(static_cast<uint8_t>(c));
        for (size_t i = 0; i < pad; ++i) path.push_back(0);

        std::vector<uint8_t> req;
        req.push_back(tag_services::ReadTag);
        req.push_back(static_cast<uint8_t>(path.size() / 2));
        req.insert(req.end(), path.begin(), path.end());
        // element_count = 1
        req.push_back(0x01); req.push_back(0x00);
        return req;
    };

    auto sub_a = build_read_req("a");
    auto sub_b = build_read_req("b");

    // Aggregate: count(2) + offsets[2] + sub_a + sub_b
    uint16_t count = 2;
    uint16_t off_a = static_cast<uint16_t>(2 + 4);
    uint16_t off_b = static_cast<uint16_t>(off_a + sub_a.size());
    std::vector<uint8_t> data(6);
    ser::write_uint(data, count);
    ser::write_uint(std::span<uint8_t>(data).subspan(2), off_a);
    ser::write_uint(std::span<uint8_t>(data).subspan(4), off_b);
    data.insert(data.end(), sub_a.begin(), sub_a.end());
    data.insert(data.end(), sub_b.begin(), sub_b.end());

    ethernetip::cip::CipPath p;
    p.class_id = 0x02;          // Message Router
    p.instance_id = 1;

    auto resp = disp.dispatch(0x0A, p, data);
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_GE(resp.data.size(), 6u);
    uint16_t got_count = ser::read_uint(resp.data);
    EXPECT_EQ(2u, got_count);

    // Decode each sub-response: read offsets, then check each starts with reply
    // service (0xCC) and contains the expected value.
    uint16_t r_off_a = ser::read_uint(std::span<const uint8_t>(resp.data).subspan(2));
    uint16_t r_off_b = ser::read_uint(std::span<const uint8_t>(resp.data).subspan(4));
    ASSERT_LT(r_off_a + 9u, resp.data.size());
    ASSERT_LT(r_off_b + 9u, resp.data.size());
    EXPECT_EQ(0xCC, resp.data[r_off_a]);
    EXPECT_EQ(0xCC, resp.data[r_off_b]);
    // After reply(1)+reserved(1)+status(1)+addl_size(1)+tag_type(2) = +6
    uint32_t va = ser::read_udint(std::span<const uint8_t>(resp.data).subspan(r_off_a + 6));
    uint32_t vb = ser::read_udint(std::span<const uint8_t>(resp.data).subspan(r_off_b + 6));
    EXPECT_EQ(11u, va);
    EXPECT_EQ(22u, vb);
}
