#include "ethernetip/protocol/socket_compat.hpp"
#include "ethernetip/protocol/tcp_socket.hpp"
#include "ethernetip/protocol/udp_socket.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace ethernetip::protocol;
using namespace std::chrono_literals;

namespace {
// Spin a short condition with timeout. Returns true if `pred()` became true.
template <class Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

// Best-effort: open a raw TCP socket and connect synchronously, mirroring
// what an EipScanner would do. Used to drive our TcpSocket listener in tests
// without depending on the scanner-side implementation (not yet ported).
sock::socket_t connect_tcp(const IpEndpoint& target) {
    sock::ensure_initialized();
    auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    sock::to_sockaddr(target, addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == sock::sockerr) {
        sock::close(s);
        return sock::invalid;
    }
    return s;
}
} // namespace

TEST(TcpSocketTest, AcceptsClientAndExchangesBytes) {
    TcpSocket server;
    std::atomic<int> bytes_received{0};
    std::shared_ptr<TcpSocketConnection> server_side;
    std::mutex mu;
    server.set_on_accept([&](std::shared_ptr<TcpSocketConnection> c) {
        {
            std::scoped_lock lock(mu);
            server_side = c;
        }
        c->set_on_bytes(
            [&](TcpSocketConnection& self, std::span<const uint8_t> data) {
                bytes_received += static_cast<int>(data.size());
                self.send(data);  // echo
            });
    });
    server.start({"127.0.0.1", 0});           // ephemeral port
    ASSERT_NE(0, server.actual_port());

    auto client = connect_tcp({"127.0.0.1", server.actual_port()});
    ASSERT_NE(sock::invalid, client);

    // Wait for the accept callback to fire.
    EXPECT_TRUE(wait_for([&] {
        std::scoped_lock lock(mu);
        return server_side != nullptr;
    }, 1s));

    // Write a packet from client, expect to receive it back (server echoes).
    const char* probe = "hello-eip";
    int n = ::send(client, probe, static_cast<int>(std::strlen(probe)), 0);
    EXPECT_EQ(static_cast<int>(std::strlen(probe)), n);

    char recv_buf[64] = {0};
    n = ::recv(client, recv_buf, sizeof(recv_buf), 0);
    EXPECT_EQ(static_cast<int>(std::strlen(probe)), n);
    EXPECT_STREQ(probe, recv_buf);

    EXPECT_TRUE(wait_for([&] { return bytes_received.load() == static_cast<int>(std::strlen(probe)); }, 1s));

    sock::close(client);
    server.stop();
}

TEST(UdpSocketTest, ReceiveAndSendRoundTrip) {
    UdpSocket receiver;
    std::atomic<int> packets{0};
    std::vector<uint8_t> last;
    IpEndpoint last_from;
    std::mutex mu;
    receiver.set_on_packet(
        [&](std::span<const uint8_t> data, const IpEndpoint& from) {
            std::scoped_lock lock(mu);
            last.assign(data.begin(), data.end());
            last_from = from;
            ++packets;
        });
    receiver.start({"127.0.0.1", 0});
    uint16_t port = receiver.actual_port();
    ASSERT_NE(0, port);

    // Send from a separate sender socket bound to ephemeral port.
    UdpSocket sender;
    sender.start({"127.0.0.1", 0});
    std::vector<uint8_t> probe{1, 2, 3, 4, 5};
    sender.send({"127.0.0.1", port}, probe);

    EXPECT_TRUE(wait_for([&] { return packets.load() > 0; }, 1s));
    {
        std::scoped_lock lock(mu);
        EXPECT_EQ(probe, last);
        EXPECT_EQ("127.0.0.1", last_from.host);
    }

    sender.stop();
    receiver.stop();
}
