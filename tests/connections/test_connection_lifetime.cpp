// Regression tests for the IoConnection lifetime cluster — shared_ptr
// storage, weak_ptr-pinned production, single-lock FwdClose pop, and
// atomic hot counters.

#include "ethernetip/cip/cip_dispatcher.hpp"
#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/connections/connection_manager.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

using namespace ethernetip::connections;
using namespace ethernetip::cip;
namespace ser = ethernetip::cip::serializer;

namespace {

// Build a Forward Open MR payload identical in shape to the shared
// helper in test_connection_manager.cpp, parameterized by the
// connection serial so two triads can coexist in one test.
std::vector<uint8_t> make_fwd_open_data(uint16_t connection_serial,
                                          uint32_t originator_serial) {
    std::vector<uint8_t> data(44);
    data[0] = 0x05;
    data[1] = 0x9C;
    ser::write_udint(std::span<uint8_t>(data).subspan(2), 0u);
    ser::write_udint(std::span<uint8_t>(data).subspan(6), 0x10001234u);
    ser::write_uint (std::span<uint8_t>(data).subspan(10), connection_serial);
    ser::write_uint (std::span<uint8_t>(data).subspan(12), uint16_t{0x0001});
    ser::write_udint(std::span<uint8_t>(data).subspan(14), originator_serial);
    data[18] = 1;
    ser::write_udint(std::span<uint8_t>(data).subspan(22), 20000u);
    ser::write_uint (std::span<uint8_t>(data).subspan(26), uint16_t{0x4007});
    ser::write_udint(std::span<uint8_t>(data).subspan(28), 20000u);
    ser::write_uint (std::span<uint8_t>(data).subspan(32), uint16_t{0x4007});
    data[34] = 0xA1;
    data[35] = 0x04;
    data[36] = 0x20; data[37] = 0x04; data[38] = 0x24; data[39] = 0x05;
    data[40] = 0x2C; data[41] = 0x64; data[42] = 0x2C; data[43] = 0x66;
    return data;
}

std::vector<uint8_t> make_fwd_close_data(uint16_t connection_serial,
                                           uint32_t originator_serial) {
    std::vector<uint8_t> data(10);
    data[0] = 0x05; data[1] = 0x9C;
    ser::write_uint (std::span<uint8_t>(data).subspan(2), connection_serial);
    ser::write_uint (std::span<uint8_t>(data).subspan(4), uint16_t{0x0001});
    ser::write_udint(std::span<uint8_t>(data).subspan(6), originator_serial);
    return data;
}

} // namespace

// F1: a producer-style loop that holds a weak_ptr to the IoConnection
// must observe a Forward Close by failing to lock() the weak_ptr, not
// by dereferencing a destroyed object.
TEST(ConnectionLifetimeTest, FwdCloseDuringActiveProductionExitsCleanly) {
    ConnectionManagerObject mgr;
    mgr.validate_assembly = [](uint32_t) { return 16; };

    auto open_svc  = mgr.cip_class().get_instance_service(0x54);
    auto close_svc = mgr.cip_class().get_instance_service(0x4E);
    auto& inst = *mgr.cip_class().get_instance(1);

    auto open_resp = open_svc->handler(
        inst, CipServiceRequest{0x54, CipPath{}, make_fwd_open_data(0x4321, 0xC0FFEE42u)});
    ASSERT_TRUE(open_resp.status.is_success());

    uint32_t oto_t_id = ser::read_udint(open_resp.data);
    auto conn_sp = mgr.find_by_oto_t_id(oto_t_id);
    ASSERT_TRUE(conn_sp);

    // Stand-in for VirtualDevice::start_production_thread: capture a
    // weak_ptr and exit cleanly when the manager drops its reference.
    std::weak_ptr<IoConnection> weak = conn_sp;
    std::atomic<bool> cancel{false};
    std::atomic<int>  iters{0};
    std::thread producer([&] {
        while (!cancel.load()) {
            auto locked = weak.lock();
            if (!locked) break;
            if (locked->state.load() != ConnectionState::Established) break;
            iters.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    });

    // Let the producer run for a bit, then drop our local pin and send
    // a Forward Close. The producer's weak_ptr.lock() must return null
    // once the manager drops its shared_ptr too.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    conn_sp.reset();

    auto close_resp = close_svc->handler(
        inst, CipServiceRequest{0x4E, CipPath{}, make_fwd_close_data(0x4321, 0xC0FFEE42u)});
    EXPECT_TRUE(close_resp.status.is_success());

    producer.join();  // must return; no infinite loop, no UAF
    EXPECT_GT(iters.load(), 0);
    EXPECT_TRUE(mgr.active_connections().empty());
}

// F2: two threads sending Forward Closes for the same triad must not
// double-callback; the lock-and-pop puts exactly one through.
TEST(ConnectionLifetimeTest, ConcurrentFwdCloseIsSingleShot) {
    ConnectionManagerObject mgr;
    mgr.validate_assembly = [](uint32_t) { return 16; };

    auto open_svc  = mgr.cip_class().get_instance_service(0x54);
    auto close_svc = mgr.cip_class().get_instance_service(0x4E);
    auto& inst = *mgr.cip_class().get_instance(1);

    auto open_resp = open_svc->handler(
        inst, CipServiceRequest{0x54, CipPath{}, make_fwd_open_data(0x4321, 0xC0FFEE42u)});
    ASSERT_TRUE(open_resp.status.is_success());

    std::atomic<int> removed{0};
    mgr.on_connection_removed.push_back([&](IoConnection&) { removed.fetch_add(1); });

    std::atomic<int> successes{0};
    auto close_payload = make_fwd_close_data(0x4321, 0xC0FFEE42u);
    auto run_close = [&] {
        auto r = close_svc->handler(inst, CipServiceRequest{0x4E, CipPath{}, close_payload});
        if (r.status.is_success()) successes.fetch_add(1);
    };
    std::thread t1(run_close);
    std::thread t2(run_close);
    t1.join();
    t2.join();

    // Exactly one Forward Close should have succeeded (the other sees
    // "no such connection"), and the removed callback must fire once.
    EXPECT_EQ(1, successes.load());
    EXPECT_EQ(1, removed.load());
    EXPECT_TRUE(mgr.active_connections().empty());
}

// F4: two threads bumping safety_rollover_count race-free — the final
// value is exactly the sum of their fetch_add contributions.
TEST(ConnectionLifetimeTest, AtomicRolloverCounterIsRaceFree) {
    IoConnection conn;
    conn.safety_rollover_count.store(0);

    constexpr int kPerThread = 50'000;
    std::thread a([&] {
        for (int i = 0; i < kPerThread; ++i) conn.safety_rollover_count.fetch_add(1);
    });
    std::thread b([&] {
        for (int i = 0; i < kPerThread; ++i) conn.safety_rollover_count.fetch_add(1);
    });
    a.join();
    b.join();

    EXPECT_EQ(static_cast<uint16_t>(2 * kPerThread),
              conn.safety_rollover_count.load());
}
