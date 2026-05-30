// EthernetIPCpp Logix Host — minimal Logix 5000 simulator for PLC tag-message
// testing. Mirrors EthernetIPSharp/tests/LogixHost/Program.cs.
//
// Wraps LogixDispatcher (Symbol/Template/Message Router/Connection Manager/
// Identity) behind EipAdapter on TCP 44818. No I/O (Class 1) connections —
// just unconnected / Class 3 explicit messaging for tag reads/writes.

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
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
} // namespace

int main(int argc, char** argv) {
    std::string bind = (argc > 1) ? argv[1] : "0.0.0.0";
    int tcp_port     = (argc > 2) ? std::atoi(argv[2]) : 44818;

    ethernetip::cip::IdentityInfo identity;
    identity.vendor_id      = 0x0001;
    identity.device_type    = 0x000E;       // PLC
    identity.product_code   = 55;
    identity.major_revision = 32;
    identity.minor_revision = 11;
    identity.serial_number  = 0xDEAD;
    identity.product_name   = "EthernetIPCpp Logix";

    auto tags = std::make_shared<ethernetip::logix::TagDatabase>();
    auto& rate = tags->add_tag("rate",        ldt::Dint);
    auto& temp = tags->add_tag("temperature", ldt::Real);
    auto& cnts = tags->add_tag("counts",      ldt::Int, /*element_count=*/10);

    rate.write<int32_t>(0, 534);
    float t0 = 72.5f;
    std::vector<uint8_t> tbytes(4);
    std::memcpy(tbytes.data(), &t0, 4);
    temp.set_data(tbytes);

    ethernetip::logix::LogixDispatcher dispatcher(tags, identity);

    ethernetip::protocol::EipAdapter adapter(dispatcher, identity);
    adapter.listen(ethernetip::protocol::IpEndpoint{bind, static_cast<uint16_t>(tcp_port)});

    std::printf("=== EthernetIPCpp Logix Host ===\n"
                 "Bind:     %s:%d\n"
                 "Identity: Vendor=0x%04X Type=0x%04X Serial=0x%08X Name=\"%s\"\n"
                 "Tags: rate(DINT)=534, temperature(REAL)=72.5, counts(INT[10])\n"
                 "Ready. Ctrl+C to stop.\n\n",
                 bind.c_str(), tcp_port,
                 identity.vendor_id, identity.device_type, identity.serial_number,
                 identity.product_name.c_str());

#ifndef _WIN32
    std::signal(SIGTERM, on_signal);
#endif
    std::signal(SIGINT, on_signal);

    int tick = 0;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(500ms);
        ++tick;
        int32_t r = rate.read<int32_t>(0);
        float   t = temp.read<float>(0);
        int16_t c0 = cnts.read<int16_t>(0);
        int16_t c5 = cnts.read<int16_t>(5 * 2);
        std::printf("\r[tick %5d] rate=%d  temperature=%.3f  counts[0]=%d  counts[5]=%d   ",
                     tick, r, t, c0, c5);
        std::fflush(stdout);
        if (tick % 20 == 0) std::printf("\n");
    }

    std::printf("\n\nStopping...\n");
    adapter.stop();
    return 0;
}
