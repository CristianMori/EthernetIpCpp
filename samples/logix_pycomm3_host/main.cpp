// EthernetIPCpp Logix pycomm3 Host — Logix 5000 simulator seeded with one
// tag per atomic CIP type (plus SHORT_STRING). Target for the pycomm3
// round-trip test under tests/pycomm3/.
//
// Mirrors _spawn_server() in the Python port's
// tests/pycomm3/test_pycomm3_roundtrip.py so the two implementations
// expose identical tag catalogs on the wire.

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
namespace ldt = ethernetip::logix::logix_data_types;

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

template <class T>
void seed_scalar(ethernetip::logix::Tag& tag, T value) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::vector<uint8_t> bytes(sizeof(T));
    std::memcpy(bytes.data(), &value, sizeof(T));
    tag.set_data(bytes);
}

void seed_bytes(ethernetip::logix::Tag& tag, uint64_t value, int n_bytes) {
    std::vector<uint8_t> bytes(static_cast<size_t>(n_bytes));
    for (int i = 0; i < n_bytes; ++i) {
        bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
    tag.set_data(bytes);
}

int parse_port(int argc, char** argv, int fallback) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            return std::atoi(argv[i + 1]);
        }
        // Positional fallback: last plain integer wins.
        if (!arg.empty() && (std::isdigit(static_cast<unsigned char>(arg[0])) ||
                             (arg[0] == '-' && arg.size() > 1 &&
                              std::isdigit(static_cast<unsigned char>(arg[1]))))) {
            fallback = std::atoi(arg.c_str());
        }
    }
    return fallback;
}

std::string parse_bind(int argc, char** argv, const std::string& fallback) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--bind" && i + 1 < argc) {
            return argv[i + 1];
        }
    }
    return fallback;
}

} // namespace

int main(int argc, char** argv) {
    std::string bind = parse_bind(argc, argv, "127.0.0.1");
    int         port = parse_port(argc, argv, 44818);

    ethernetip::cip::IdentityInfo identity;
    identity.vendor_id      = 1;
    identity.device_type    = 0x000E;      // PLC
    identity.product_code   = 65;
    identity.major_revision = 20;
    identity.minor_revision = 11;
    identity.serial_number  = 0x12345678;
    identity.product_name   = "PyCommRoundTripTarget";

    auto tags = std::make_shared<ethernetip::logix::TagDatabase>();

    // Atomic numeric types — names + initial values match
    // tests/pycomm3/test_pycomm3_roundtrip.py TYPES in the Python port.
    seed_scalar<uint8_t >(tags->add_tag("TestBool",  ldt::Bool),  1);         // True
    seed_scalar<int8_t  >(tags->add_tag("TestSint",  ldt::Sint),  -5);
    seed_scalar<int16_t >(tags->add_tag("TestInt",   ldt::Int),   -1234);
    seed_scalar<int32_t >(tags->add_tag("TestDint",  ldt::Dint),  -1'000'000);
    seed_scalar<int64_t >(tags->add_tag("TestLint",  ldt::Lint),  int64_t{-1});
    seed_scalar<uint8_t >(tags->add_tag("TestUsint", ldt::Usint), 42);
    seed_scalar<uint16_t>(tags->add_tag("TestUint",  ldt::Uint),  uint16_t{0xBEEF});
    seed_scalar<uint32_t>(tags->add_tag("TestUdint", ldt::Udint), uint32_t{0xDEADBEEFu});
    seed_scalar<uint64_t>(tags->add_tag("TestUlint", ldt::Ulint), uint64_t{1'234'567'890'123ULL});
    seed_scalar<float   >(tags->add_tag("TestReal",  ldt::Real),  3.14f);
    seed_scalar<double  >(tags->add_tag("TestLreal", ldt::Lreal), 3.141592653589793);

    // Bit-string family — stored as raw little-endian integer bytes.
    seed_bytes(tags->add_tag("TestByte",  ldt::Byte),  0xABULL,                1);
    seed_bytes(tags->add_tag("TestWord",  ldt::Word),  0x1234ULL,              2);
    seed_bytes(tags->add_tag("TestDword", ldt::Dword), 0xDEADBEEFULL,          4);
    seed_bytes(tags->add_tag("TestLword", ldt::Lword), 0x123456789ABCDEF0ULL,  8);

    // SHORT_STRING — pycomm3 writes a variable-length [len][chars] payload,
    // which tag_services.cpp accepts since commit a89cb55.
    tags->add_tag("TestShortString", ldt::ShortString);

    // ---- Yellow-row coverage ------------------------------------------------
    // Mirrors the sibling Python port's test_pycomm3_roundtrip._spawn_server
    // extension. Names and seed values must match verbatim.
    using ethernetip::logix::TemplateMember;

    // Row 17-20: 1-D array of atomics (DINT[10]) seeded 100..109.
    {
        auto& arr = tags->add_tag("DintArr", ldt::Dint, 10);
        std::vector<uint8_t> bytes(10 * 4);
        for (int i = 0; i < 10; ++i) {
            int32_t v = 100 + i;
            std::memcpy(bytes.data() + i * 4, &v, 4);
        }
        arr.set_data(bytes);
    }

    // Row 21: bit of atomic (DINT with alternating bit pattern).
    seed_scalar<uint32_t>(tags->add_tag("FlagsDint", ldt::Dint),
                           uint32_t{0b1010'1010'1010'1010});

    // Row 22: BOOL[32] (DWORD-packed).
    tags->add_tag("Flags32", ldt::Bool, 32);

    // Row 23: multi-dim DINT[2,3], row-major values 10*r+c.
    {
        auto& mat = tags->add_tag_dims("Matrix", ldt::Dint, {2, 3});
        std::vector<uint8_t> bytes(2 * 3 * 4);
        for (int r = 0; r < 2; ++r) {
            for (int c = 0; c < 3; ++c) {
                int32_t v = 10 * r + c;
                std::memcpy(bytes.data() + (r * 3 + c) * 4, &v, 4);
            }
        }
        mat.set_data(bytes);
    }

    // Row 24-25: Logix STRING UDT (LEN:DINT + DATA:SINT[82], 88 bytes).
    auto& string_tpl = tags->add_template("STRING", {
        TemplateMember{"LEN",  ldt::Dint, 0},
        TemplateMember{"DATA", ldt::Sint, 82},
    });
    {
        auto& greet = tags->add_tag("Greeting", string_tpl);
        std::vector<uint8_t> buf(string_tpl.structure_size(), 0);
        const char hello[] = "Hello pycomm3";
        int32_t len = static_cast<int32_t>(sizeof(hello) - 1);
        std::memcpy(buf.data(), &len, 4);
        std::memcpy(buf.data() + 4, hello, sizeof(hello) - 1);
        greet.set_data(buf);
    }
    tags->add_tag("GreetingArr", string_tpl, 3);

    // Row 26-29, 31: User UDT Motor { Speed:REAL, Fault:BOOL, RunCount:DINT }.
    auto& motor_tpl = tags->add_template("Motor", {
        TemplateMember{"Speed",    ldt::Real, 0},
        TemplateMember{"Fault",    ldt::Bool, 0},
        TemplateMember{"RunCount", ldt::Dint, 0},
    });
    {
        auto& motor_a = tags->add_tag("MotorA", motor_tpl);
        std::vector<uint8_t> buf(motor_tpl.structure_size(), 0);
        float speed = 3.14f;
        std::memcpy(buf.data() + 0, &speed, 4);
        buf[4] = 1;  // Fault bit 0 of host SINT at offset 4
        int32_t run_count = 42;
        std::memcpy(buf.data() + 8, &run_count, 4);
        motor_a.set_data(buf);
    }
    tags->add_tag("MotorArr", motor_tpl, 3);

    // TIMER / COUNTER / CONTROL / AOI-backing proof: all four are "just UDTs"
    // from pycomm3's perspective -- same access pattern as Motor.*, same
    // Template Object plumbing.  Register a Logix-shape TIMER (EN, TT, DN,
    // PRE, ACC) and an AOI-shape UDT and seed them so the test can prove
    // MyTimer.PRE / MyTimer.EN / MyAOI.Enable all round-trip.
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
        buf[0] = 1;                                   // EN bit 0 = True
        int32_t pre = 1000;
        int32_t acc = 250;
        // Locate PRE and ACC by name, in case alignment padding changes.
        for (const auto& m : timer_tpl.members()) {
            if (m.name == "PRE") std::memcpy(buf.data() + m.offset, &pre, 4);
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
            if (m.name == "Enable")        buf[m.offset] = 1;  // bit 0 True
            else if (m.name == "Setpoint") std::memcpy(buf.data() + m.offset, &setpoint, 4);
            else if (m.name == "Done")     buf[m.offset] = 0;  // bit 0 False
            else if (m.name == "Steps")    std::memcpy(buf.data() + m.offset, &steps, 4);
        }
        my_aoi.set_data(buf);
    }

    // Program-scoped tags: pycomm3 enumerates them under the "Program:<name>."
    // prefix and reads/writes them via that prefix. Register a program,
    // a scalar inside it, and a UDT inside it with the same Motor shape so
    // we exercise member access too. Names and seed values mirror the
    // sibling Python port's fixture.
    tags->register_program("MainProgram");
    {
        auto& p_dint = tags->add_program_tag("MainProgram", "LocalDint", ldt::Dint);
        int32_t v = 42;
        std::vector<uint8_t> bytes(sizeof(v));
        std::memcpy(bytes.data(), &v, sizeof(v));
        p_dint.set_data(bytes);
    }
    {
        auto& p_real = tags->add_program_tag("MainProgram", "LocalReal", ldt::Real);
        float v = 3.14f;
        std::vector<uint8_t> bytes(sizeof(v));
        std::memcpy(bytes.data(), &v, sizeof(v));
        p_real.set_data(bytes);
    }
    {
        auto& p_motor = tags->add_program_struct_tag("MainProgram", "LocalMotor", motor_tpl);
        std::vector<uint8_t> buf(motor_tpl.structure_size(), 0);
        float speed = 2.5f;
        int32_t run_count = 99;
        for (const auto& m : motor_tpl.members()) {
            if      (m.name == "Speed")    std::memcpy(buf.data() + m.offset, &speed, 4);
            else if (m.name == "Fault")    buf[m.offset] = 1;  // bit 0 True
            else if (m.name == "RunCount") std::memcpy(buf.data() + m.offset, &run_count, 4);
        }
        p_motor.set_data(buf);
    }
    // -------------------------------------------------------------------------

    ethernetip::logix::LogixDispatcher dispatcher(tags, identity);
    ethernetip::protocol::EipAdapter   adapter(dispatcher, identity);
    adapter.listen(ethernetip::protocol::IpEndpoint{bind, static_cast<uint16_t>(port)});

    std::printf("=== EthernetIPCpp Logix pycomm3 Host ===\n"
                 "Bind:     %s:%d\n"
                 "Identity: Vendor=0x%04X Type=0x%04X Serial=0x%08X Name=\"%s\"\n"
                 "Tags: 15 atomics + TestShortString\n"
                 "Ready. Ctrl+C to stop.\n",
                 bind.c_str(), port,
                 identity.vendor_id, identity.device_type, identity.serial_number,
                 identity.product_name.c_str());
    std::fflush(stdout);

#ifndef _WIN32
    std::signal(SIGTERM, on_signal);
#endif
    std::signal(SIGINT, on_signal);

    while (!g_stop.load()) {
        std::this_thread::sleep_for(100ms);
    }

    std::printf("Stopping...\n");
    adapter.stop();
    return 0;
}
