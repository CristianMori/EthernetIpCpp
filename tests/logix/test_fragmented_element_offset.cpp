// Regression tests for an asymmetry in SymbolObject's instance handlers:
// Read_Tag / Write_Tag honored request.path.element_id, but
// Read_Tag_Fragmented (0x52) and Write_Tag_Fragmented (0x53) did not — a
// client sending Class 0x6B + Instance N + Element i + 0x52 read from
// byte 0 of the tag instead of element i. The symbolic/walker path was
// always correct; this covers the instance-ID + element path that
// TagClient uses after a browse call.
//
// Pulled from PR #1 exploration (@SRCthird). Mirrors
// tests/EthernetIPSharp.Logix.Tests/FragmentedElementOffsetTests.cs.

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/symbol_object.hpp"
#include "ethernetip/logix/tag.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <array>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

using namespace ethernetip::logix;
namespace ldt = logix_data_types;
namespace ser = ethernetip::cip::serializer;

namespace {

std::vector<uint8_t> fragmented_read_body(uint16_t element_count,
                                           uint32_t byte_offset_in_elements) {
    std::vector<uint8_t> buf(6);
    ser::write_uint(buf, element_count);
    ser::write_udint(std::span<uint8_t>(buf).subspan(2), byte_offset_in_elements);
    return buf;
}

std::vector<uint8_t> fragmented_write_body(uint16_t tag_type,
                                            uint16_t element_count,
                                            uint32_t byte_offset_in_elements,
                                            std::span<const uint8_t> payload) {
    std::vector<uint8_t> buf(8 + payload.size());
    ser::write_uint(buf, tag_type);
    ser::write_uint(std::span<uint8_t>(buf).subspan(2), element_count);
    ser::write_udint(std::span<uint8_t>(buf).subspan(4), byte_offset_in_elements);
    std::memcpy(buf.data() + 8, payload.data(), payload.size());
    return buf;
}

} // namespace

TEST(FragmentedElementOffsetTest, SymbolObject_FragmentedRead_HonorsElementSegment) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);
    for (int i = 0; i < 10; ++i) tag.write<int32_t>(i * 4, 100 + i);

    ethernetip::cip::CipPath p;
    p.class_id    = SymbolObject::ClassCode;
    p.instance_id = tag.instance_id();
    p.element_id  = 5u;

    auto req  = fragmented_read_body(/*element_count=*/1, /*byte_offset=*/0);
    auto resp = disp.dispatch(tag_services::ReadTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success())
        << "general_status=0x" << std::hex
        << static_cast<unsigned>(resp.status.general_status);
    ASSERT_GE(resp.data.size(), 6u);
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(105u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(FragmentedElementOffsetTest, SymbolObject_FragmentedRead_NoElementSegment_ReadsFromByteZero) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);
    for (int i = 0; i < 10; ++i) tag.write<int32_t>(i * 4, 100 + i);

    ethernetip::cip::CipPath p;
    p.class_id    = SymbolObject::ClassCode;
    p.instance_id = tag.instance_id();

    auto req  = fragmented_read_body(/*element_count=*/1, /*byte_offset=*/0);
    auto resp = disp.dispatch(tag_services::ReadTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success());
    EXPECT_EQ(100u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(FragmentedElementOffsetTest, SymbolObject_FragmentedWrite_HonorsElementSegment) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);

    ethernetip::cip::CipPath p;
    p.class_id    = SymbolObject::ClassCode;
    p.instance_id = tag.instance_id();
    p.element_id  = 7u;

    std::array<uint8_t, 4> payload{};
    int32_t v = 7777;
    std::memcpy(payload.data(), &v, 4);
    auto req  = fragmented_write_body(ldt::Dint, /*element_count=*/1,
                                       /*byte_offset=*/0, payload);
    auto resp = disp.dispatch(tag_services::WriteTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success())
        << "general_status=0x" << std::hex
        << static_cast<unsigned>(resp.status.general_status);
    EXPECT_EQ(7777, tag.read<int32_t>(7 * 4));
    EXPECT_EQ(0,    tag.read<int32_t>(6 * 4));
    EXPECT_EQ(0,    tag.read<int32_t>(8 * 4));
}

// The symbolic-name dispatch path in LogixDispatcher::on_unhandled resolves
// path.element_id into an element offset and hands it to dispatch_tag_service.
// Fragmented services (0x52 / 0x53) used to drop that offset on the floor,
// so a fragmented read of MyArray[N] via a bare symbolic-name path read
// from element 0 instead of element N.
TEST(FragmentedElementOffsetTest, SymbolicNamePath_FragmentedRead_HonorsElementId) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);
    for (int i = 0; i < 10; ++i) tag.write<int32_t>(i * 4, 500 + i);

    ethernetip::cip::CipPath p;
    p.symbolic_name = std::string("counts");
    p.element_id    = 5u;

    auto req  = fragmented_read_body(/*element_count=*/1, /*byte_offset=*/0);
    auto resp = disp.dispatch(tag_services::ReadTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success())
        << "general_status=0x" << std::hex
        << static_cast<unsigned>(resp.status.general_status);
    ASSERT_GE(resp.data.size(), 6u);
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(505u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(FragmentedElementOffsetTest, SymbolicNamePath_FragmentedWrite_HonorsElementId) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);

    ethernetip::cip::CipPath p;
    p.symbolic_name = std::string("counts");
    p.element_id    = 7u;

    std::array<uint8_t, 4> payload{};
    int32_t v = 9999;
    std::memcpy(payload.data(), &v, 4);
    auto req  = fragmented_write_body(ldt::Dint, /*element_count=*/1,
                                       /*byte_offset=*/0, payload);
    auto resp = disp.dispatch(tag_services::WriteTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success())
        << "general_status=0x" << std::hex
        << static_cast<unsigned>(resp.status.general_status);
    EXPECT_EQ(9999, tag.read<int32_t>(7 * 4));
    EXPECT_EQ(0,    tag.read<int32_t>(6 * 4));
    EXPECT_EQ(0,    tag.read<int32_t>(8 * 4));
}

// Ordered-segments (walker) path in LogixDispatcher::dispatch_via_walker:
// the switch's default arm (fragmented services 0x52 / 0x53) used to call
// dispatch_tag_service with element_offset=0, dropping the walker-resolved
// offset. A fragmented read of counts[5] routed through
// [SymbolicPathSegment("counts"), ElementPathSegment{5}] therefore read from
// element 0. Mirrors the symbolic-name fix in commit 5960596.
TEST(FragmentedElementOffsetTest, WalkerPath_FragmentedRead_HonorsElementId) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);
    for (int i = 0; i < 10; ++i) tag.write<int32_t>(i * 4, 500 + i);

    ethernetip::cip::CipPath p;
    p.segments.push_back(ethernetip::cip::SymbolicPathSegment{"counts"});
    p.segments.push_back(ethernetip::cip::ElementPathSegment{5});

    auto req  = fragmented_read_body(/*element_count=*/1, /*byte_offset=*/0);
    auto resp = disp.dispatch(tag_services::ReadTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success())
        << "general_status=0x" << std::hex
        << static_cast<unsigned>(resp.status.general_status);
    ASSERT_GE(resp.data.size(), 6u);
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(505u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(FragmentedElementOffsetTest, WalkerPath_FragmentedWrite_HonorsElementId) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);

    ethernetip::cip::CipPath p;
    p.segments.push_back(ethernetip::cip::SymbolicPathSegment{"counts"});
    p.segments.push_back(ethernetip::cip::ElementPathSegment{7});

    std::array<uint8_t, 4> payload{};
    int32_t v = 9999;
    std::memcpy(payload.data(), &v, 4);
    auto req  = fragmented_write_body(ldt::Dint, /*element_count=*/1,
                                       /*byte_offset=*/0, payload);
    auto resp = disp.dispatch(tag_services::WriteTagFragmented, p, req);

    ASSERT_TRUE(resp.status.is_success())
        << "general_status=0x" << std::hex
        << static_cast<unsigned>(resp.status.general_status);
    EXPECT_EQ(9999, tag.read<int32_t>(7 * 4));
    EXPECT_EQ(0,    tag.read<int32_t>(0 * 4));
    EXPECT_EQ(0,    tag.read<int32_t>(8 * 4));
}

TEST(FragmentedElementOffsetTest, SymbolObject_FragmentedRead_ParityWithAtomicReadTag) {
    LogixDispatcher disp;
    auto& tag = disp.tags().add_tag("counts", ldt::Dint, /*element_count=*/10);
    for (int i = 0; i < 10; ++i) tag.write<int32_t>(i * 4, 1000 + i);

    ethernetip::cip::CipPath p;
    p.class_id    = SymbolObject::ClassCode;
    p.instance_id = tag.instance_id();
    p.element_id  = 3u;

    std::array<uint8_t, 2> atomic_req{};
    ser::write_uint(atomic_req, 1);
    auto atomic_resp = disp.dispatch(tag_services::ReadTag, p, atomic_req);
    ASSERT_TRUE(atomic_resp.status.is_success());
    uint32_t atomic_value =
        ser::read_udint(std::span<const uint8_t>(atomic_resp.data).subspan(2));

    auto frag_req  = fragmented_read_body(/*element_count=*/1, /*byte_offset=*/0);
    auto frag_resp = disp.dispatch(tag_services::ReadTagFragmented, p, frag_req);
    ASSERT_TRUE(frag_resp.status.is_success());
    uint32_t frag_value =
        ser::read_udint(std::span<const uint8_t>(frag_resp.data).subspan(2));

    EXPECT_EQ(1003u, atomic_value);
    EXPECT_EQ(atomic_value, frag_value);
}
