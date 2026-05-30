#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/connections/forward_open_request.hpp"

#include <array>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::connections;
namespace ser = ethernetip::cip::serializer;

namespace {
// Build a minimal Forward Open request: 36-byte fixed header + 4-byte path.
std::vector<uint8_t> make_basic_request() {
    std::vector<uint8_t> data(40);
    data[0] = 0x05;          // priority_time_tick
    data[1] = 0x9C;          // timeout_ticks
    ser::write_udint(std::span<uint8_t>(data).subspan(2), 0u);              // OT id
    ser::write_udint(std::span<uint8_t>(data).subspan(6), 0x10001234u);     // TO id
    ser::write_uint (std::span<uint8_t>(data).subspan(10), uint16_t{0x4321}); // conn serial
    ser::write_uint (std::span<uint8_t>(data).subspan(12), uint16_t{0x0001}); // vendor
    ser::write_udint(std::span<uint8_t>(data).subspan(14), 0xC0FFEE42u);     // origin serial
    data[18] = 1;            // timeout multiplier
    // 19-21 reserved
    ser::write_udint(std::span<uint8_t>(data).subspan(22), 20000u);          // OT RPI
    ser::write_uint (std::span<uint8_t>(data).subspan(26), uint16_t{0x4205}); // OT params (P2P, fixed, size 5)
    ser::write_udint(std::span<uint8_t>(data).subspan(28), 20000u);          // TO RPI
    ser::write_uint (std::span<uint8_t>(data).subspan(32), uint16_t{0x4207}); // TO params (P2P, fixed, size 7)
    data[34] = 0xA1;          // transport_class_trigger (class 1, server)
    data[35] = 0x02;          // path size = 2 words
    // 4 bytes of path: class 0x04, instance 1
    data[36] = 0x20; data[37] = 0x04; data[38] = 0x24; data[39] = 0x01;
    return data;
}
} // namespace

TEST(ForwardOpenParseTest, BasicFieldsRoundTrip) {
    auto data = make_basic_request();
    auto req = ForwardOpenRequest::parse(data);
    EXPECT_EQ(0x05, req.priority_time_tick);
    EXPECT_EQ(0x9C, req.timeout_ticks);
    EXPECT_EQ(0x10001234u, req.tto_o_connection_id);
    EXPECT_EQ(0x4321, req.connection_serial_number);
    EXPECT_EQ(0x0001, req.originator_vendor_id);
    EXPECT_EQ(0xC0FFEE42u, req.originator_serial_number);
    EXPECT_EQ(1, req.connection_timeout_multiplier);
    EXPECT_EQ(20000u, req.oto_t_rpi);
    EXPECT_EQ(20000u, req.tto_o_rpi);
    EXPECT_FALSE(req.is_large_forward_open);
    EXPECT_EQ(TransportClass::Class1, req.transport_class());
    EXPECT_EQ(2, req.connection_path_size_words);
    ASSERT_EQ(4u, req.connection_path.size());
}

TEST(ForwardOpenParseTest, RawServiceDataMirrorsWire) {
    auto data = make_basic_request();
    auto req = ForwardOpenRequest::parse(data);
    EXPECT_EQ(data, req.raw_service_data);
}

TEST(ForwardOpenParseTest, RejectsTruncated) {
    std::vector<uint8_t> tiny(10);
    EXPECT_THROW(
        { [[maybe_unused]] auto _ = ForwardOpenRequest::parse(tiny); },
        std::invalid_argument);
}

TEST(NetworkConnectionParamsTest, Parse16Decodes) {
    // 0x4007 = P2P (bits 14-13=10), fixed (bit 9=0), size 7
    auto p = NetworkConnectionParams::parse_16(0x4007);
    EXPECT_FALSE(p.redundant_owner);
    EXPECT_EQ(2u, p.connection_type);
    EXPECT_FALSE(p.is_variable);
    EXPECT_EQ(7u, p.connection_size);
    EXPECT_FALSE(p.is_null());
}

TEST(NetworkConnectionParamsTest, Parse16VariableBitSet) {
    // 0x4207 = same but is_variable bit set
    auto p = NetworkConnectionParams::parse_16(0x4207);
    EXPECT_TRUE(p.is_variable);
}

TEST(NetworkConnectionParamsTest, Parse32WideSize) {
    // 16-bit size 0xFFFF, P2P, fixed.
    uint32_t raw = 0x4000FFFFu;
    auto p = NetworkConnectionParams::parse_32(raw);
    EXPECT_EQ(2u, p.connection_type);
    EXPECT_EQ(0xFFFF, p.connection_size);
}
