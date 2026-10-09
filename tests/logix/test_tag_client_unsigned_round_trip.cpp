// End-to-end loopback round-trip for the CIP §C-6.1 unsigned + bit-string
// atomic type family. Spins up a LogixDispatcher-backed EipAdapter on an
// ephemeral TCP port in a background thread, connects a TagClient, writes
// with each unsigned C++ scalar type parameter, reads it back, and
// verifies the full value survives the client -> wire -> server -> wire
// -> client loop.
//
// Covers the gap left by the in-process test_unsigned_and_bitstring_types
// unit tests: those proved the server side; this proves TagClient's
// guess_tag_type<T> path agrees with the server-side type check over the
// wire.

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/tag_client.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

using namespace ethernetip::logix;
using namespace std::chrono_literals;
namespace ldt = ethernetip::logix::logix_data_types;

namespace {

// Grab a free TCP port by binding ephemeral, reading it, closing. There's a
// race between close() and the LogixHost server's bind — accepted here
// because the tests re-run quickly and ports rarely collide on a loopback
// loopback test machine.
uint16_t grab_free_port() {
    ethernetip::protocol::sock::ensure_initialized();
    auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    socklen_t len = sizeof(addr);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    uint16_t port = ntohs(addr.sin_port);
    ethernetip::protocol::sock::close(s);
    return port;
}

// Composition helper. Returns (dispatcher, adapter, listener-thread) all
// kept alive for the lifetime of the test.
struct TestServer {
    std::shared_ptr<TagDatabase>                       tags;
    std::unique_ptr<LogixDispatcher>                   dispatcher;
    std::unique_ptr<ethernetip::protocol::EipAdapter>  adapter;
    std::thread                                        thread;
    uint16_t                                           port;

    void start(uint16_t p) {
        port = p;
        ethernetip::cip::IdentityInfo id;
        id.vendor_id = 42;
        id.device_type = 0x0E;
        id.product_code = 1;
        id.major_revision = 1;
        id.minor_revision = 0;
        id.serial_number = 0xC0DE;
        id.product_name = "UnsignedRoundTripTarget";

        tags = std::make_shared<TagDatabase>();
        tags->add_tag("u8",   ldt::Usint);
        tags->add_tag("u16",  ldt::Uint);
        tags->add_tag("u32",  ldt::Udint);
        tags->add_tag("u64",  ldt::Ulint);
        tags->add_tag("b8",   ldt::Byte);
        tags->add_tag("w16",  ldt::Word);
        tags->add_tag("dw32", ldt::Dword);
        tags->add_tag("lw64", ldt::Lword);

        dispatcher = std::make_unique<LogixDispatcher>(tags, id);
        adapter    = std::make_unique<ethernetip::protocol::EipAdapter>(*dispatcher, id);
        thread     = std::thread([this]() {
            adapter->listen(ethernetip::protocol::IpEndpoint{"127.0.0.1", port});
        });
        // Give the listener a moment to bind. 50ms is plenty on loopback.
        std::this_thread::sleep_for(50ms);
    }

    ~TestServer() {
        if (adapter) adapter->stop();
        if (thread.joinable()) thread.join();
    }
};

} // namespace

TEST(TagClientUnsignedRoundTrip, Usint_FullRange) {
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();
    c.write<uint8_t>("u8", 0xFF);
    EXPECT_EQ(c.read<uint8_t>("u8"), 0xFF);
}

TEST(TagClientUnsignedRoundTrip, Uint_FullRange) {
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();
    c.write<uint16_t>("u16", 0xFFFF);
    EXPECT_EQ(c.read<uint16_t>("u16"), 0xFFFF);
}

TEST(TagClientUnsignedRoundTrip, Udint_FullRange) {
    // The specific EscaFlow crash case — now full-range round-trip over
    // real TCP.
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();
    c.write<uint32_t>("u32", 0xFFFF'FFFFu);
    EXPECT_EQ(c.read<uint32_t>("u32"), 0xFFFF'FFFFu);
}

TEST(TagClientUnsignedRoundTrip, Ulint_FullRange) {
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();
    c.write<uint64_t>("u64", 0xFFFF'FFFF'FFFF'FFFFull);
    EXPECT_EQ(c.read<uint64_t>("u64"), 0xFFFF'FFFF'FFFF'FFFFull);
}

TEST(TagClientUnsignedRoundTrip, BitString_ViaWriteRaw) {
    // C++ scalar types collapse uint8_t -> USINT (via guess_tag_type<T>),
    // so BYTE/WORD/DWORD/LWORD tags need the explicit tag_type raw path.
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();

    {
        uint8_t v = 0xAB;
        c.write_raw("b8", ldt::Byte, 1, std::span<const uint8_t>(&v, 1));
        auto resp = c.read_tag_raw("b8", 1);
        ASSERT_EQ(resp.size(), 3u);
        EXPECT_EQ(resp[2], 0xAB);
    }
    {
        uint16_t v = 0xBEEF;
        std::vector<uint8_t> bytes(sizeof(v));
        std::memcpy(bytes.data(), &v, sizeof(v));
        c.write_raw("w16", ldt::Word, 1, bytes);
        auto resp = c.read_tag_raw("w16", 1);
        ASSERT_EQ(resp.size(), 4u);
        uint16_t got;
        std::memcpy(&got, resp.data() + 2, 2);
        EXPECT_EQ(got, 0xBEEF);
    }
    {
        uint32_t v = 0xDEAD'BEEFu;
        std::vector<uint8_t> bytes(sizeof(v));
        std::memcpy(bytes.data(), &v, sizeof(v));
        c.write_raw("dw32", ldt::Dword, 1, bytes);
        auto resp = c.read_tag_raw("dw32", 1);
        uint32_t got;
        std::memcpy(&got, resp.data() + 2, 4);
        EXPECT_EQ(got, 0xDEAD'BEEFu);
    }
    {
        uint64_t v = 0xFEED'FACE'CAFE'BABEull;
        std::vector<uint8_t> bytes(sizeof(v));
        std::memcpy(bytes.data(), &v, sizeof(v));
        c.write_raw("lw64", ldt::Lword, 1, bytes);
        auto resp = c.read_tag_raw("lw64", 1);
        uint64_t got;
        std::memcpy(&got, resp.data() + 2, 8);
        EXPECT_EQ(got, 0xFEED'FACE'CAFE'BABEull);
    }
}

TEST(TagClientUnsignedRoundTrip, AllUnsignedTypes_RoundTripInOneSession) {
    // Reuse one TCP session across every type to catch state-machine
    // / connection-handle bugs that only show up on sequential writes
    // against tags of different widths.
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();

    c.write<uint8_t>  ("u8",  0xAB);
    c.write<uint16_t> ("u16", 0xBEEF);
    c.write<uint32_t> ("u32", 0xDEAD'BEEFu);
    c.write<uint64_t> ("u64", 0xFEED'FACE'CAFE'BABEull);

    EXPECT_EQ(c.read<uint8_t>  ("u8"),  0xAB);
    EXPECT_EQ(c.read<uint16_t> ("u16"), 0xBEEF);
    EXPECT_EQ(c.read<uint32_t> ("u32"), 0xDEAD'BEEFu);
    EXPECT_EQ(c.read<uint64_t> ("u64"), 0xFEED'FACE'CAFE'BABEull);
}

TEST(TagClientUnsignedRoundTrip, SignedWriteAgainstUnsignedTag_RejectedByServer) {
    // The negative half of the round-trip proof. int8_t -> Sint via
    // guess_tag_type; writing to a USINT-registered tag must fail the
    // server-side tag_type check (status 0xFF ext 0x2107). This is what
    // proves the GuessTagType fix is what makes the valid writes work
    // (not accidental server tolerance).
    TestServer srv;
    srv.start(grab_free_port());

    TagClient c("127.0.0.1", srv.port);
    c.connect();
    EXPECT_THROW(c.write<int8_t>("u8", 1), std::exception);
}
