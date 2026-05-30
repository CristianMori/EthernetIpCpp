#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag.hpp"
#include "ethernetip/logix/tag_services.hpp"

#include <array>
#include <cstring>
#include <gtest/gtest.h>

using namespace ethernetip::logix;
namespace ldt = logix_data_types;
namespace ser = ethernetip::cip::serializer;

TEST(TagServicesTest, ReadTagReturnsTypeAndData) {
    Tag t(1, "rate", ldt::make_atomic_symbol_type(ldt::Dint, 0), ldt::Dint, 4, 1);
    t.write<int32_t>(0, 0x12345678);

    std::array<uint8_t, 2> req{};
    ser::write_uint(req, 1);  // element_count = 1
    auto resp = tag_services::handle_read_tag(t, tag_services::ReadTag, req);
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(6u, resp.data.size());
    EXPECT_EQ(ldt::Dint, ser::read_uint(resp.data));
    EXPECT_EQ(0x12345678u, ser::read_udint(std::span<const uint8_t>(resp.data).subspan(2)));
}

TEST(TagServicesTest, WriteTagUpdatesBufferAndRejectsTypeMismatch) {
    Tag t(1, "rate", ldt::make_atomic_symbol_type(ldt::Dint, 0), ldt::Dint, 4, 1);

    std::array<uint8_t, 8> good{};
    ser::write_uint(good, ldt::Dint);
    ser::write_uint(std::span<uint8_t>(good).subspan(2), 1);
    ser::write_udint(std::span<uint8_t>(good).subspan(4), 0xCAFEBABE);
    auto ok = tag_services::handle_write_tag(t, tag_services::WriteTag, good);
    EXPECT_TRUE(ok.status.is_success());
    EXPECT_EQ(static_cast<int32_t>(0xCAFEBABE), t.read<int32_t>(0));

    std::array<uint8_t, 8> bad = good;
    ser::write_uint(bad, ldt::Int);  // wrong type
    auto err = tag_services::handle_write_tag(t, tag_services::WriteTag, bad);
    EXPECT_FALSE(err.status.is_success());
    EXPECT_EQ(0xFF, err.status.general_status);
    ASSERT_EQ(1u, err.status.additional_status.size());
    EXPECT_EQ(0x2107u, err.status.additional_status[0]);
}

TEST(TagServicesTest, ReadFragmentedReturnsMoreFlagWhenChunked) {
    // 200-element DINT array → 800 bytes, exceeds MaxReplyData (480-2)
    Tag t(1, "big", ldt::make_atomic_symbol_type(ldt::Dint, 1), ldt::Dint, 4, 200);

    std::array<uint8_t, 6> req{};
    ser::write_uint(req, 200);
    ser::write_udint(std::span<uint8_t>(req).subspan(2), 0u);

    auto resp = tag_services::handle_read_tag_fragmented(t, tag_services::ReadTagFragmented, req);
    EXPECT_EQ(0xD2, resp.service_code);
    EXPECT_EQ(0x06, resp.status.general_status);  // "more data"
    EXPECT_EQ(static_cast<size_t>(tag_services::MaxReplyData), resp.data.size());
}

TEST(TagServicesTest, ReadModifyWriteAppliesOrAndMask) {
    Tag t(1, "flags", ldt::make_atomic_symbol_type(ldt::Dword, 0), ldt::Dword, 4, 1);
    t.write<uint32_t>(0, 0xF0F0F0F0u);

    // mask_size=4, OR=0x0F0F0F0F, AND=0xFFFFFFFF → result = 0xFFFFFFFF
    std::array<uint8_t, 10> req{};
    ser::write_uint(req, 4);
    ser::write_udint(std::span<uint8_t>(req).subspan(2), 0x0F0F0F0Fu);
    ser::write_udint(std::span<uint8_t>(req).subspan(6), 0xFFFFFFFFu);

    auto resp = tag_services::handle_read_modify_write(t, tag_services::ReadModifyWrite, req);
    EXPECT_TRUE(resp.status.is_success());
    EXPECT_EQ(0xFFFFFFFFu, t.read<uint32_t>(0));
}
