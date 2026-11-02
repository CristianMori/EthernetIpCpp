// Our TagClient against our server — the symmetric check to the pycomm3
// round-trip.
//
// pycomm3 verifies that OUR server speaks the Rockwell wire dialect
// correctly. This test verifies that OUR client speaks the same dialect —
// reads back exactly what the server stored (as proven by the pycomm3
// test against the same server with the same seed values).
//
// Shares the same tag landscape as the pycomm3 host so the matrix is
// identical: every atomic covered by the Python own-client test, 1-D
// array, bit of atomic, BOOL array, multi-dim array, SHORT_STRING, Logix
// STRING UDT, user UDT whole-struct and member access, Timer/AOI UDTs,
// program-scoped tags, and batch read.

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/tag_client.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace ethernetip::logix;
using namespace std::chrono_literals;
namespace ldt = ethernetip::logix::logix_data_types;

namespace {

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

// Composition helper. Mirrors the pycomm3 host's seed data so our client
// hits the identical matrix. Exposes template refs so the test can read
// their actual instance IDs (we don't hardcode 257/258 — they depend on
// the TagDatabase allocation order and could shift under us).
struct TestServer {
    std::shared_ptr<TagDatabase>                       tags;
    std::unique_ptr<LogixDispatcher>                   dispatcher;
    std::unique_ptr<ethernetip::protocol::EipAdapter>  adapter;
    std::thread                                        thread;
    uint16_t                                           port = 0;
    uint16_t                                           string_tpl_id = 0;
    uint16_t                                           motor_tpl_id = 0;

    void start(uint16_t p) {
        port = p;
        ethernetip::cip::IdentityInfo id;
        id.vendor_id      = 1;
        id.device_type    = 0x0E;
        id.product_code   = 65;
        id.major_revision = 20;
        id.minor_revision = 11;
        id.serial_number  = 0x12345678u;
        id.product_name   = "OwnClientRoundTripTarget";

        tags = std::make_shared<TagDatabase>();

        // --- Atomics (names + initial values match Python own-client test) --
        {
            auto& t = tags->add_tag("TestDint", ldt::Dint);
            int32_t v = -1'000'000;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            t.set_data(b);
        }
        {
            auto& t = tags->add_tag("TestReal", ldt::Real);
            float v = 3.14f;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            t.set_data(b);
        }
        {
            auto& t = tags->add_tag("TestUdint", ldt::Udint);
            uint32_t v = 0xDEADBEEFu;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            t.set_data(b);
        }
        {
            auto& t = tags->add_tag("TestLint", ldt::Lint);
            int64_t v = -1;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            t.set_data(b);
        }
        tags->add_tag("TestShortString", ldt::ShortString);

        // 1-D array of atomics: DINT[10] seeded 100..109.
        {
            auto& arr = tags->add_tag("DintArr", ldt::Dint, 10);
            std::vector<uint8_t> b(10 * 4);
            for (int i = 0; i < 10; ++i) {
                int32_t v = 100 + i;
                std::memcpy(b.data() + i * 4, &v, 4);
            }
            arr.set_data(b);
        }

        // Bit of atomic — alternating pattern (not asserted in this test
        // directly, but kept for parity with the matrix landscape).
        {
            auto& t = tags->add_tag("FlagsDint", ldt::Dint);
            uint32_t v = 0b1010'1010'1010'1010u;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            t.set_data(b);
        }

        // BOOL[32] (DWORD-packed) — kept for landscape parity.
        tags->add_tag("Flags32", ldt::Bool, 32);

        // Multi-dim DINT[2,3], row-major values 10*r+c.
        {
            auto& mat = tags->add_tag_dims("Matrix", ldt::Dint, {2, 3});
            std::vector<uint8_t> b(2 * 3 * 4);
            for (int r = 0; r < 2; ++r) {
                for (int c = 0; c < 3; ++c) {
                    int32_t v = 10 * r + c;
                    std::memcpy(b.data() + (r * 3 + c) * 4, &v, 4);
                }
            }
            mat.set_data(b);
        }

        // Logix STRING UDT (LEN:DINT + DATA:SINT[82], 88 bytes).
        auto& string_tpl = tags->add_template("STRING", {
            TemplateMember{"LEN",  ldt::Dint, 0},
            TemplateMember{"DATA", ldt::Sint, 82},
        });
        string_tpl_id = string_tpl.instance_id();
        {
            auto& greet = tags->add_tag("Greeting", string_tpl);
            std::vector<uint8_t> buf(string_tpl.structure_size(), 0);
            const char hello[] = "Hello client";
            int32_t strlen = static_cast<int32_t>(sizeof(hello) - 1);
            std::memcpy(buf.data(), &strlen, 4);
            std::memcpy(buf.data() + 4, hello, sizeof(hello) - 1);
            greet.set_data(buf);
        }

        // User UDT: Motor { Speed:REAL, Fault:BOOL, RunCount:DINT }.
        auto& motor_tpl = tags->add_template("Motor", {
            TemplateMember{"Speed",    ldt::Real, 0},
            TemplateMember{"Fault",    ldt::Bool, 0},
            TemplateMember{"RunCount", ldt::Dint, 0},
        });
        motor_tpl_id = motor_tpl.instance_id();
        {
            auto& motor_a = tags->add_tag("MotorA", motor_tpl);
            std::vector<uint8_t> buf(motor_tpl.structure_size(), 0);
            float speed = 3.14f;
            int32_t run = 42;
            for (const auto& m : motor_tpl.members()) {
                if      (m.name == "Speed")    std::memcpy(buf.data() + m.offset, &speed, 4);
                else if (m.name == "Fault")    buf[m.offset] = 1;  // bit 0 True
                else if (m.name == "RunCount") std::memcpy(buf.data() + m.offset, &run, 4);
            }
            motor_a.set_data(buf);
        }
        tags->add_tag("MotorArr", motor_tpl, 3);

        // TIMER- and AOI-shape UDTs.
        auto& timer_tpl = tags->add_template("TIMER", {
            TemplateMember{"EN",  ldt::Bool, 0},
            TemplateMember{"TT",  ldt::Bool, 0},
            TemplateMember{"DN",  ldt::Bool, 0},
            TemplateMember{"PRE", ldt::Dint, 0},
            TemplateMember{"ACC", ldt::Dint, 0},
        });
        {
            auto& my_timer = tags->add_tag("MyTimer", timer_tpl);
            std::vector<uint8_t> buf(timer_tpl.structure_size(), 0);
            buf[0] = 1;  // EN bit 0 True
            int32_t pre = 1000;
            int32_t acc = 250;
            for (const auto& m : timer_tpl.members()) {
                if      (m.name == "PRE") std::memcpy(buf.data() + m.offset, &pre, 4);
                else if (m.name == "ACC") std::memcpy(buf.data() + m.offset, &acc, 4);
            }
            my_timer.set_data(buf);
        }

        auto& aoi_tpl = tags->add_template("MixerAOI", {
            TemplateMember{"Enable",   ldt::Bool, 0},
            TemplateMember{"Setpoint", ldt::Real, 0},
            TemplateMember{"Done",     ldt::Bool, 0},
            TemplateMember{"Steps",    ldt::Dint, 0},
        });
        {
            auto& my_aoi = tags->add_tag("MyAOI", aoi_tpl);
            std::vector<uint8_t> buf(aoi_tpl.structure_size(), 0);
            float setpoint = 42.5f;
            int32_t steps = 7;
            for (const auto& m : aoi_tpl.members()) {
                if      (m.name == "Enable")   buf[m.offset] = 1;
                else if (m.name == "Setpoint") std::memcpy(buf.data() + m.offset, &setpoint, 4);
                else if (m.name == "Done")     buf[m.offset] = 0;
                else if (m.name == "Steps")    std::memcpy(buf.data() + m.offset, &steps, 4);
            }
            my_aoi.set_data(buf);
        }

        // Program-scoped tags.
        tags->register_program("MainProgram");
        {
            auto& p_dint = tags->add_program_tag("MainProgram", "LocalDint", ldt::Dint);
            int32_t v = 42;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            p_dint.set_data(b);
        }
        {
            auto& p_real = tags->add_program_tag("MainProgram", "LocalReal", ldt::Real);
            float v = 3.14f;
            std::vector<uint8_t> b(sizeof(v));
            std::memcpy(b.data(), &v, sizeof(v));
            p_real.set_data(b);
        }
        {
            auto& p_motor = tags->add_program_struct_tag("MainProgram", "LocalMotor", motor_tpl);
            std::vector<uint8_t> buf(motor_tpl.structure_size(), 0);
            float speed = 2.5f;
            int32_t run = 99;
            for (const auto& m : motor_tpl.members()) {
                if      (m.name == "Speed")    std::memcpy(buf.data() + m.offset, &speed, 4);
                else if (m.name == "Fault")    buf[m.offset] = 1;
                else if (m.name == "RunCount") std::memcpy(buf.data() + m.offset, &run, 4);
            }
            p_motor.set_data(buf);
        }

        dispatcher = std::make_unique<LogixDispatcher>(tags, id);
        adapter    = std::make_unique<ethernetip::protocol::EipAdapter>(*dispatcher, id);
        thread     = std::thread([this]() {
            adapter->listen(ethernetip::protocol::IpEndpoint{"127.0.0.1", port});
        });
        std::this_thread::sleep_for(100ms);
    }

    ~TestServer() {
        if (adapter) adapter->stop();
        if (thread.joinable()) thread.join();
    }
};

template <class Fn>
void run_block(const char* label, std::vector<std::string>& failures, Fn&& fn) {
    try {
        fn();
    } catch (const std::exception& ex) {
        std::ostringstream os;
        os << label << ": " << ex.what();
        failures.push_back(os.str());
    } catch (...) {
        std::ostringstream os;
        os << label << ": (unknown exception)";
        failures.push_back(os.str());
    }
}

} // namespace

// Each sub-matrix guarded by its own try block, mirroring the Python
// test's `failures.append(...)` collection pattern: don't let the first
// assertion failure hide the rest.
TEST(TagClientFullMatrix, Roundtrip) {
    TestServer srv;
    srv.start(grab_free_port());

    std::vector<std::string> failures;

    TagClient c("127.0.0.1", srv.port);
    c.connect();

    // --- Atomics ----------------------------------------------------------
    run_block("TestDint",  failures, [&]{
        ASSERT_EQ(c.read<int32_t>("TestDint"), -1'000'000);
        c.write<int32_t>("TestDint", 2'000'000'000);
        ASSERT_EQ(c.read<int32_t>("TestDint"), 2'000'000'000);
    });
    run_block("TestReal",  failures, [&]{
        ASSERT_NEAR(c.read<float>("TestReal"), 3.14f, 1e-5f);
        c.write<float>("TestReal", -2.71828f);
        ASSERT_NEAR(c.read<float>("TestReal"), -2.71828f, 1e-4f);
    });
    run_block("TestUdint", failures, [&]{
        ASSERT_EQ(c.read<uint32_t>("TestUdint"), 0xDEADBEEFu);
        c.write<uint32_t>("TestUdint", 0xFFFF'FFFFu);
        ASSERT_EQ(c.read<uint32_t>("TestUdint"), 0xFFFF'FFFFu);
    });
    run_block("TestLint",  failures, [&]{
        ASSERT_EQ(c.read<int64_t>("TestLint"), int64_t{-1});
        int64_t big = 0x7FFF'FFFF'FFFF'FFFFLL;
        c.write<int64_t>("TestLint", big);
        ASSERT_EQ(c.read<int64_t>("TestLint"), big);
    });

    // --- 1-D array indexed ------------------------------------------------
    run_block("DintArr[5]", failures, [&]{
        ASSERT_EQ(c.read<int32_t>("DintArr[5]"), 105);
        c.write<int32_t>("DintArr[5]", 999);
        ASSERT_EQ(c.read<int32_t>("DintArr[5]"), 999);
    });

    // --- Multi-dim array --------------------------------------------------
    run_block("Matrix", failures, [&]{
        ASSERT_EQ(c.read<int32_t>("Matrix[1,2]"), 12);
        c.write<int32_t>("Matrix[0,1]", 777);
        ASSERT_EQ(c.read<int32_t>("Matrix[0,1]"), 777);
    });

    // --- Logix STRING UDT -------------------------------------------------
    run_block("Greeting", failures, [&]{
        ASSERT_EQ(c.read_string("Greeting"), "Hello client");
        // Discover the STRING template's structure handle before writing
        // (the client requires it, mirroring Studio 5000's behaviour).
        auto info = c.read_template(srv.string_tpl_id);
        c.write_string("Greeting", "written back", info.structure_handle);
        ASSERT_EQ(c.read_string("Greeting"), "written back");
    });

    // --- UDT whole-struct read -------------------------------------------
    run_block("MotorA read_struct_bytes", failures, [&]{
        auto info = c.read_template(srv.motor_tpl_id);
        auto bytes = c.read_struct_bytes("MotorA");
        // Just confirm the server returned at least structure_size bytes;
        // Python's read_struct asserts `is not None`, we assert non-empty.
        ASSERT_FALSE(bytes.empty());
        ASSERT_GE(bytes.size(), static_cast<size_t>(info.structure_size));
    });

    // --- UDT member access (via generic read path) -----------------------
    run_block("MotorA members", failures, [&]{
        ASSERT_NEAR(c.read<float>("MotorA.Speed"), 3.14f, 1e-5f);
        ASSERT_EQ  (c.read<int32_t>("MotorA.RunCount"), 42);
        c.write<float>("MotorA.Speed", -1.5f);
        ASSERT_NEAR(c.read<float>("MotorA.Speed"), -1.5f, 1e-4f);
    });

    run_block("MotorArr[1].Speed", failures, [&]{
        c.write<float>("MotorArr[1].Speed", 7.77f);
        ASSERT_NEAR(c.read<float>("MotorArr[1].Speed"), 7.77f, 1e-4f);
    });

    // --- Timer / AOI (just UDTs) -----------------------------------------
    run_block("Timer/AOI", failures, [&]{
        ASSERT_EQ(c.read<int32_t>("MyTimer.PRE"), 1000);
        ASSERT_EQ(c.read<int32_t>("MyTimer.ACC"), 250);
        c.write<int32_t>("MyTimer.PRE", 2000);
        ASSERT_EQ(c.read<int32_t>("MyTimer.PRE"), 2000);

        ASSERT_NEAR(c.read<float>("MyAOI.Setpoint"), 42.5f, 1e-5f);
        c.write<float>("MyAOI.Setpoint", 99.9f);
        ASSERT_NEAR(c.read<float>("MyAOI.Setpoint"), 99.9f, 1e-4f);
        ASSERT_EQ(c.read<int32_t>("MyAOI.Steps"), 7);
    });

    // --- Program-scoped tags ---------------------------------------------
    run_block("Program:MainProgram.LocalDint", failures, [&]{
        ASSERT_EQ(c.read<int32_t>("Program:MainProgram.LocalDint"), 42);
        c.write<int32_t>("Program:MainProgram.LocalDint", 100);
        ASSERT_EQ(c.read<int32_t>("Program:MainProgram.LocalDint"), 100);
    });
    run_block("Program:MainProgram.LocalReal", failures, [&]{
        ASSERT_NEAR(c.read<float>("Program:MainProgram.LocalReal"), 3.14f, 1e-5f);
    });
    run_block("Program:MainProgram.LocalMotor", failures, [&]{
        ASSERT_NEAR(c.read<float>  ("Program:MainProgram.LocalMotor.Speed"), 2.5f, 1e-5f);
        ASSERT_EQ  (c.read<int32_t>("Program:MainProgram.LocalMotor.RunCount"), 99);
        c.write<float>("Program:MainProgram.LocalMotor.Speed", 5.5f);
        ASSERT_NEAR(c.read<float>("Program:MainProgram.LocalMotor.Speed"), 5.5f, 1e-4f);
    });

    // --- Batch read (multi-service) --------------------------------------
    run_block("batch read", failures, [&]{
        auto got = c.read_multiple({"DintArr[0]", "DintArr[1]", "DintArr[2]"});
        ASSERT_EQ(got.size(), 3u);
    });

    c.disconnect();

    if (!failures.empty()) {
        std::ostringstream os;
        os << "TagClient round-trip failures:\n";
        for (const auto& f : failures) os << "  * " << f << "\n";
        FAIL() << os.str();
    }
}
