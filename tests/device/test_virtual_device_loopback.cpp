#include "ethernetip/cip/encapsulation.hpp"
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/device/virtual_device.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace ethernetip::device;
using namespace ethernetip::protocol;
using namespace std::chrono_literals;

namespace {
// Tiny synchronous TCP helper for the test — opens a connection, sends an
// EncapsulationHeader, reads the reply.
sock::socket_t connect_tcp(const std::string& host, uint16_t port) {
    sock::ensure_initialized();
    auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    sock::to_sockaddr({host, port}, addr);
    ::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    return s;
}

bool wait_for(std::function<bool()> pred, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}
} // namespace

TEST(VirtualDeviceLoopbackTest, RespondsToListIdentity) {
    ethernetip::cip::IdentityInfo identity;
    identity.vendor_id    = 0x0001;
    identity.device_type  = 0x000C;
    identity.product_code = 0x0042;
    identity.serial_number = 0xC0FFEE42;
    identity.product_name = "EthernetIPCpp Test Device";

    // Pick a high port unlikely to clash with anything on the dev box.
    constexpr uint16_t kTcpPort = 0x9991;
    constexpr uint16_t kUdpPort = 0xA991;

    VirtualDevice dev(identity, "127.0.0.1", "Test");
    dev.add_assembly(100, 8, "Input");
    dev.add_assembly(101, 8, "Output");
    dev.start(kTcpPort, kUdpPort);

    // Build a ListIdentity request and send it.
    ethernetip::cip::EncapsulationHeader hdr;
    hdr.command = ethernetip::cip::EncapsulationCommand::ListIdentity;
    hdr.sender_context = 0x0102030405060708ull;
    std::vector<uint8_t> req(ethernetip::cip::EncapsulationHeader::Size);
    hdr.write_to(req);

    auto s = connect_tcp("127.0.0.1", kTcpPort);
    ASSERT_NE(sock::invalid, s);
    int sent = ::send(s, reinterpret_cast<const char*>(req.data()),
                       static_cast<int>(req.size()), 0);
    EXPECT_EQ(static_cast<int>(req.size()), sent);

    std::vector<uint8_t> reply(2048);
    int got = ::recv(s, reinterpret_cast<char*>(reply.data()),
                      static_cast<int>(reply.size()), 0);
    ASSERT_GT(got, ethernetip::cip::EncapsulationHeader::Size);
    auto resp = ethernetip::cip::EncapsulationHeader::parse(reply);
    EXPECT_EQ(ethernetip::cip::EncapsulationCommand::ListIdentity, resp.command);
    EXPECT_EQ(ethernetip::cip::EncapsulationStatus::Success, resp.status);
    EXPECT_EQ(0x0102030405060708ull, resp.sender_context);
    EXPECT_GT(resp.length, 0);

    sock::close(s);
    dev.close();
}

TEST(VirtualDeviceLoopbackTest, ExposesAssembliesByInstanceId) {
    ethernetip::cip::IdentityInfo identity;
    VirtualDevice dev(identity, "127.0.0.1");
    auto& a = dev.add_assembly(200, 16);
    auto& b = dev.add_assembly(201, 32);
    EXPECT_EQ(&a, dev.assemblies().get_assembly(200));
    EXPECT_EQ(&b, dev.assemblies().get_assembly(201));
    EXPECT_EQ(16, a.data_size());
    EXPECT_EQ(32, b.data_size());
}
