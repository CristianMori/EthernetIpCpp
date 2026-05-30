// Minimal scanner smoke test — connects to a Generic Ethernet Module adapter
// (samples/echo_module on loopback), opens an I/O connection, sends a few
// O->T cycles, prints the T->O bytes the adapter is pre-loading, then closes.
//
// usage: scanner_smoke [host]
//   default host = 127.0.0.1

#include "ethernetip/protocol/eip_scanner.hpp"
#include "ethernetip/protocol/forward_open_config.hpp"
#include "ethernetip/protocol/scanner_connection.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using ethernetip::protocol::EipScanner;
using ethernetip::protocol::ForwardOpenConfig;

int main(int argc, char** argv) {
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";

    EipScanner scanner;
    try {
        std::printf("Connecting to %s:44818 ...\n", host.c_str());
        scanner.connect(host);
        std::printf("  session = 0x%08X\n", scanner.session_handle());

        ForwardOpenConfig cfg;
        cfg.config_assembly   = 105;
        cfg.consumed_assembly = 102;   // O->T
        cfg.produced_assembly = 100;   // T->O
        cfg.consumed_size     = 496;   // bytes (echo_module Output)
        cfg.produced_size     = 500;   // bytes (echo_module Input)
        cfg.rpi               = 100000; // 100 ms
        cfg.transport_class   = 1;
        cfg.timeout_multiplier = 2;

        std::atomic<int> rx_count{0};
        std::printf("Forward Open ...\n");
        auto conn = scanner.forward_open(cfg);
        std::printf("  open. target UDP = %s:%u\n",
                     conn->target_endpoint().host.c_str(),
                     static_cast<unsigned>(conn->target_endpoint().port));
        conn->set_data_received_handler([&](std::span<const uint8_t>) { ++rx_count; });

        // Run for 2 seconds.
        std::this_thread::sleep_for(2s);

        auto produced = conn->get_produced_data();
        std::printf("After 2s: tx=%llu rx=%llu  first 8 produced bytes:",
                     static_cast<unsigned long long>(conn->send_count()),
                     static_cast<unsigned long long>(conn->receive_count()));
        for (int i = 0; i < 8 && i < static_cast<int>(produced.size()); ++i) {
            std::printf(" %02X", produced[i]);
        }
        std::printf("\n");

        conn->close();
        scanner.disconnect();
        std::printf("Done.\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
