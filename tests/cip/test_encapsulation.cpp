#include "ethernetip/cip/encapsulation.hpp"

#include <array>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace ethernetip::cip;

TEST(EncapsulationHeaderTest, RoundTrip) {
    EncapsulationHeader src;
    src.command        = EncapsulationCommand::SendRRData;
    src.length         = 42;
    src.session_handle = 0x12345678;
    src.status         = EncapsulationStatus::Success;
    src.sender_context = 0x0102030405060708ull;
    src.options        = 0;

    std::array<uint8_t, EncapsulationHeader::Size> buf{};
    int n = src.write_to(buf);
    EXPECT_EQ(EncapsulationHeader::Size, n);

    auto rt = EncapsulationHeader::parse(buf);
    EXPECT_EQ(src.command, rt.command);
    EXPECT_EQ(src.length, rt.length);
    EXPECT_EQ(src.session_handle, rt.session_handle);
    EXPECT_EQ(src.status, rt.status);
    EXPECT_EQ(src.sender_context, rt.sender_context);
    EXPECT_EQ(src.options, rt.options);
}

TEST(EncapsulationHeaderTest, RejectsTruncated) {
    std::array<uint8_t, 10> buf{};
    EXPECT_THROW(
        { [[maybe_unused]] auto _ = EncapsulationHeader::parse(buf); },
        std::invalid_argument);
}

TEST(EncapsulationHeaderTest, LittleEndianLayout) {
    EncapsulationHeader h{
        .command = EncapsulationCommand::RegisterSession,
        .length = 0x0034,
        .session_handle = 0xCAFEBABE,
        .status = EncapsulationStatus::Success,
        .sender_context = 0,
        .options = 0,
    };
    std::array<uint8_t, EncapsulationHeader::Size> buf{};
    h.write_to(buf);

    // Command 0x0065 LE
    EXPECT_EQ(0x65, buf[0]); EXPECT_EQ(0x00, buf[1]);
    // Length 0x0034 LE
    EXPECT_EQ(0x34, buf[2]); EXPECT_EQ(0x00, buf[3]);
    // Session handle 0xCAFEBABE LE
    EXPECT_EQ(0xBE, buf[4]); EXPECT_EQ(0xBA, buf[5]);
    EXPECT_EQ(0xFE, buf[6]); EXPECT_EQ(0xCA, buf[7]);
}
