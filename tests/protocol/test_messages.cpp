#include "ethernetip/cip/encapsulation.hpp"
#include "ethernetip/protocol/messages.hpp"

#include <array>
#include <gtest/gtest.h>
#include <vector>

using namespace ethernetip::protocol;
using ethernetip::cip::EncapsulationCommand;
using ethernetip::cip::EncapsulationHeader;
using ethernetip::cip::EncapsulationStatus;

namespace {
IpEndpoint loopback() { return {"127.0.0.1", 44818}; }
} // namespace

TEST(MessagesTest, NopWritesHeaderOnly) {
    messages::NopMessage msg;
    msg.sender_context = 0x0102030405060708ull;
    std::array<uint8_t, EncapsulationHeader::Size> buf{};
    msg.write_to(buf);
    auto hdr = EncapsulationHeader::parse(buf);
    EXPECT_EQ(EncapsulationCommand::Nop, hdr.command);
    EXPECT_EQ(0u, hdr.length);
    EXPECT_EQ(0x0102030405060708ull, hdr.sender_context);
}

TEST(MessagesTest, RegisterSessionRoundTrip) {
    messages::RegisterSessionMessage msg;
    msg.session_handle = 0x12345678;
    msg.sender_context = 0xCAFEBABE;
    msg.protocol_version = 1;
    msg.options_flags = 0;
    std::vector<uint8_t> buf(msg.wire_size());
    msg.write_to(buf);

    int consumed = 0;
    auto parsed = messages::try_parse_encapsulation(buf, loopback(), consumed);
    ASSERT_NE(nullptr, parsed);
    EXPECT_EQ(static_cast<int>(buf.size()), consumed);
    ASSERT_EQ(messages::MessageKind::RegisterSession, parsed->kind);
    auto& rs = static_cast<messages::RegisterSessionMessage&>(*parsed);
    EXPECT_EQ(0x12345678u, rs.session_handle);
    EXPECT_EQ(0xCAFEBABEull, rs.sender_context);
    EXPECT_EQ(1, rs.protocol_version);
}

TEST(MessagesTest, SendRRDataRoundTrip) {
    messages::SendRRDataMessage msg;
    msg.session_handle = 0xAA;
    msg.cip_data = {0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07};   // GAS Identity attr 7
    std::vector<uint8_t> buf(msg.wire_size());
    msg.write_to(buf);

    int consumed = 0;
    auto parsed = messages::try_parse_encapsulation(buf, loopback(), consumed);
    ASSERT_NE(nullptr, parsed);
    EXPECT_EQ(static_cast<int>(buf.size()), consumed);
    ASSERT_EQ(messages::MessageKind::SendRRData, parsed->kind);
    auto& rr = static_cast<messages::SendRRDataMessage&>(*parsed);
    EXPECT_EQ(0xAAu, rr.session_handle);
    EXPECT_EQ(msg.cip_data, rr.cip_data);
}

TEST(MessagesTest, CpfConnectedDataParseAndWrite) {
    std::vector<uint8_t> payload{0x42, 0x43, 0x44};
    std::vector<uint8_t> buf(messages::CpfConnectedDataMessage::CpfOverhead + payload.size());
    messages::CpfConnectedDataMessage::write_wire(buf, /*conn_id=*/0xCAFEBABE,
                                                     /*encap_seq=*/0x42,
                                                     payload);
    auto parsed = messages::CpfConnectedDataMessage::try_parse(buf, loopback());
    ASSERT_NE(nullptr, parsed);
    EXPECT_EQ(0xCAFEBABEu, parsed->connection_id);
    EXPECT_EQ(0x42u, parsed->encap_sequence_number);
    EXPECT_EQ(payload, parsed->payload);
}

TEST(MessagesTest, PartialBufferReturnsNullptr) {
    messages::RegisterSessionMessage msg;
    std::vector<uint8_t> buf(msg.wire_size());
    msg.write_to(buf);

    int consumed = 0;
    // Half-size buffer — should signal "need more bytes".
    std::span<const uint8_t> partial(buf.data(), buf.size() / 2);
    auto parsed = messages::try_parse_encapsulation(partial, loopback(), consumed);
    EXPECT_EQ(nullptr, parsed);
    EXPECT_EQ(0, consumed);
}
