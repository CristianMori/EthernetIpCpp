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
