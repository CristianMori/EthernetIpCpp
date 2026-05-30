// EthernetIPCpp Echo Module — mirrors examples/echo_module.py in the Python port.
//
// Listens on TCP 44818 / UDP 2222, accepts a Class 1 connection from a
// PLC's Generic Ethernet Module, and exchanges cyclic I/O data:
//
//   Input  (assembly 100, 500 bytes / 125 DINTs) — pre-filled with a ramp
//                                                  1..125; DINT[0] is updated
//                                                  every tick with the counter.
//   Output (assembly 102, 496 bytes / 124 DINTs) — overwritten by PLC each scan.
//   Config (assembly 105, 10 bytes)              — present so Forward Open
//                                                  resolves the path.

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/device/virtual_device.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

using namespace std::chrono_literals;

namespace {
std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }
} // namespace

int main(int argc, char** argv) {
    std::string bind = (argc > 1) ? argv[1] : "0.0.0.0";
    int tcp_port     = (argc > 2) ? std::atoi(argv[2]) : 44818;
    int udp_port     = (argc > 3) ? std::atoi(argv[3]) : 2222;

    ethernetip::cip::IdentityInfo identity;
    identity.vendor_id     = 0x0001;
    identity.device_type   = 0x000C;
    identity.product_code  = 0x0001;
    identity.major_revision = 1;
    identity.minor_revision = 0;
    identity.serial_number = 0xC0FFEE42;
    identity.product_name  = "EthernetIPCpp Echo Module";

    ethernetip::device::VirtualDevice device(identity, bind, "EchoModule");
    auto& produced = device.add_assembly(100, 500, "T->O Input (125 DINTs)");
    auto& consumed = device.add_assembly(102, 496, "O->T Output (124 DINTs)");
    auto& config   = device.add_assembly(105, 10, "Configuration");

    // Pre-fill the input assembly with a ramp 1..125 so the PLC sees something
    // recognizable on its first scan.
    for (int i = 0; i < 125; ++i) {
        produced.write<int32_t>(i * 4, i + 1);
    }

    // Count O->T packets seen, in case the data-changed handler is convenient
    // for the user to see traffic.
    std::atomic<uint64_t> oto_t_packets{0};
    consumed.add_data_changed_handler(
        [&](uint32_t, std::span<const uint8_t>) { ++oto_t_packets; });

    std::printf("=== EthernetIPCpp Echo Module ===\n"
                 "Bind address: %s\n"
                 "TCP port:     %d\n"
                 "UDP port:     %d\n\n"
                 "Identity: Vendor=0x%04X Serial=0x%08X Name=\"%s\"\n"
                 "Assemblies: in=100 (500B), out=102 (496B), config=105 (10B)\n"
                 "Ready. Ctrl+C to stop.\n\n",
                 bind.c_str(), tcp_port, udp_port,
                 identity.vendor_id, identity.serial_number, identity.product_name.c_str());

    device.start(tcp_port, udp_port);

#ifndef _WIN32
    std::signal(SIGTERM, on_signal);
#endif
    std::signal(SIGINT, on_signal);

    int tick = 0;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(200ms);
        ++tick;
        // Bump Input[0] every tick so the PLC sees a counter.
        produced.write<int32_t>(0, tick);
        int32_t out0   = consumed.read<int32_t>(0);
        int32_t out45  = consumed.read<int32_t>(45 * 4);
        int32_t out120 = consumed.read<int32_t>(120 * 4);
        uint8_t cfg5   = config.read<uint8_t>(5);
        size_t conns = device.connection_manager().active_connections().size();
        std::printf("\r[tick %6d] Out[0]=%10d Out[45]=%10d Out[120]=%10d  "
                     "Cfg[5]=0x%02X  In[0]=%10d  Conns=%zu  "
                     "O->T rx=%llu T->O tx=%llu    ",
                     tick, out0, out45, out120, cfg5, tick, conns,
                     static_cast<unsigned long long>(oto_t_packets.load()),
                     static_cast<unsigned long long>(device.tto_o_send_count()));
        std::fflush(stdout);
        if (tick % 25 == 0) std::printf("\n");
    }

    std::printf("\n\nStopping...\n");
    device.close();
    return 0;
}
