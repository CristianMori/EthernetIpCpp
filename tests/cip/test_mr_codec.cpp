#include "ethernetip/cip/mr_codec.hpp"

#include <array>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::cip;

TEST(MrCodecTest, EncodeRequestBasic) {
    // Service 0x0E (Get_Attribute_Single), path = 20 04 24 01 30 01 (assembly/1/attr 1)
    std::array<uint8_t, 6> path{0x20, 0x04, 0x24, 0x01, 0x30, 0x01};
    std::array<uint8_t, 32> buf{};
    int n = mr_codec::encode_request(buf, 0x0E, path, std::span<const uint8_t>());
    EXPECT_EQ(8, n);
    EXPECT_EQ(0x0E, buf[0]);
    EXPECT_EQ(0x03, buf[1]);     // 3 words = 6 bytes of path
    EXPECT_EQ(0x20, buf[2]);
}

TEST(MrCodecTest, ParseRequestRoundTrip) {
    std::array<uint8_t, 4> path{0x20, 0x04, 0x24, 0x01};
    std::array<uint8_t, 3> data{0xAA, 0xBB, 0xCC};
    std::array<uint8_t, 16> buf{};
    int n = mr_codec::encode_request(buf, 0x10, path, data);
    EXPECT_EQ(9, n);

    auto req = mr_codec::try_parse_request(std::span<const uint8_t>(buf).first(n));
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(0x10, req->service_code);
    EXPECT_EQ(0x04u, req->path.class_id.value_or(0));
    EXPECT_EQ(1u, req->path.instance_id.value_or(0));
    ASSERT_EQ(3u, req->data.size());
    EXPECT_EQ(0xAA, req->data[0]);
    EXPECT_EQ(0xCC, req->data[2]);
}

TEST(MrCodecTest, ParseResponseWithAdditionalStatus) {
    // reply=0x90, reserved=0, general=0x01, add_size=2, add[0]=0x0203, add[1]=0xDEAD, data=0x42
    std::array<uint8_t, 9> buf{
        0x90, 0x00, 0x01, 0x02,
        0x03, 0x02, 0xAD, 0xDE,
        0x42,
    };
    auto resp = mr_codec::try_parse_response(buf);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(0x90, resp->reply_service);
    EXPECT_EQ(0x01, resp->status.general_status);
    ASSERT_EQ(2u, resp->status.additional_status.size());
    EXPECT_EQ(0x0203, resp->status.additional_status[0]);
    EXPECT_EQ(0xDEAD, resp->status.additional_status[1]);
    ASSERT_EQ(1u, resp->data.size());
    EXPECT_EQ(0x42, resp->data[0]);
}

TEST(MrCodecTest, ParseTruncatedReturnsNullopt) {
    std::array<uint8_t, 1> buf{0};
    EXPECT_FALSE(mr_codec::try_parse_request(buf).has_value());
    EXPECT_FALSE(mr_codec::try_parse_response(buf).has_value());
}
