// CIP Safety scanner driving a 1734-IB8S safety input module across a
// 1734-ENT backplane. Mirrors EthernetIPSharp/tests/SafetyScannerTest.
//
// Defaults match a real captured session:
//   target 192.168.1.76, slot 1, Extended safety format
//   spoofs ControlLogix originator identity (vendor 0x0001, serial 0x012FE10E)
//   hard-coded OUNID / TUNID / SCID captured from the real config download
//
// Usage:  safety_scanner_1734 [<target_ip> [<slot>]]

#include "ethernetip/protocol/eip_scanner.hpp"
#include "ethernetip/protocol/eip_udp_transport.hpp"
#include "ethernetip/protocol/ip_endpoint.hpp"
#include "ethernetip/safety/safety_forward_open_builder.hpp"
#include "ethernetip/safety/safety_scanner_connection.hpp"
#include "ethernetip/safety/safety_types.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using namespace ethernetip;

namespace {
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

// Encode the assembly class + instance for the application path. Logix uses
// 16-bit logical instance encoding for instance > 0xFF.
std::vector<uint8_t> assembly_instance(uint32_t instance) {
    if (instance <= 0xFF) {
        return {0x20, 0x04, 0x24, static_cast<uint8_t>(instance)};
    }
    return {0x20, 0x04,
              0x25, 0x00,
              static_cast<uint8_t>(instance & 0xFF),
              static_cast<uint8_t>(instance >> 8)};
}

void append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}
} // namespace

int main(int argc, char** argv) {
    std::string target_ip = (argc > 1) ? argv[1] : "192.168.1.76";
    uint8_t     slot      = (argc > 2) ? static_cast<uint8_t>(std::atoi(argv[2])) : 1;
    auto format = safety::SafetyFormat::Extended;

    std::printf("=== CIP Safety Scanner -> 1734 ===\n");
    std::printf("Target: %s, Backplane Slot: %u\n\n", target_ip.c_str(), slot);

    // ---- Spoofed PLC originator identity ----
    uint16_t orig_vendor = 0x0001;
    uint32_t orig_serial = 0x012FE10E;

    // Originator UNID (PLC identity from captured session)
    safety::SafetyNetworkNumber our_snn(
        std::array<uint8_t, 6>{0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D});
    safety::UniqueNetworkId our_ounid{our_snn, 0xC0A80160u};  // 192.168.1.96

    // Target UNID (1734-IB8S at slot 1)
    safety::SafetyNetworkNumber target_snn(
        std::array<uint8_t, 6>{0xB8, 0x0D, 0xED, 0x00, 0x8E, 0x4D});
    safety::UniqueNetworkId target_tunid{target_snn, 0x00000001u};

    // Safety Configuration ID (SCCRC + SCTS) from capture.
    safety::SafetyConfigurationId scid{};
    scid.sccrc = 0x781B988Eu;
    scid.scts  = safety::SafetyNetworkNumber(
        std::array<uint8_t, 6>{0xB6, 0x0D, 0xED, 0x00, 0x8E, 0x4D});

    // Backplane route: port 1 link address = slot.
    std::vector<uint8_t> route_prefix{0x01, slot};

    // Electronic key for 1734-IB8S (vendor=Rockwell, devType=0x0023 Safety Discrete I/O,
    // product=0x0010, rev 2.2 with compat bit).
    std::vector<uint8_t> electronic_key{
        0x34, 0x04,
        0x01, 0x00,
        0x23, 0x00,
        0x10, 0x00,
        0x82,
        0x02,
    };

    // Server app path: ekey + class+inst pairs for config / O->T-consumed / T->O-produced.
    std::vector<uint8_t> server_app_path = electronic_key;
    append(server_app_path, assembly_instance(0x0360));
    append(server_app_path, assembly_instance(0x0234));
    append(server_app_path, assembly_instance(0x00C7));

    // Client app path.
    std::vector<uint8_t> client_app_path = electronic_key;
    append(client_app_path, assembly_instance(0x0360));
    append(client_app_path, assembly_instance(0x00C7));
    append(client_app_path, assembly_instance(0x0244));

    // ---- SafetyForwardOpenConfigs ----
    safety::SafetyForwardOpenConfig server_config{};
    server_config.config_assembly                  = 0x0360;
    server_config.consumed_assembly                = 0x0234;
    server_config.produced_assembly                = 0x00C7;
    server_config.consumed_data_size               = 1;
    server_config.produced_data_size               = 1;
    server_config.oto_t_rpi                        = 20000;    // 20 ms
    server_config.tto_o_rpi                        = 380000;   // 380 ms
    server_config.oto_t_connection_size            = 7;        // wire size for 1B Extended
    server_config.tto_o_connection_size            = 6;        // TCOO = 6 bytes
    server_config.format                            = format;
    server_config.tunid                             = target_tunid;
    server_config.ounid                             = our_ounid;
    server_config.scid                              = scid;
    server_config.ping_interval_multiplier          = 19;
    server_config.time_coord_msg_min_multiplier     = 0;
    server_config.network_time_expectation_multiplier = 625;   // 80 ms
    server_config.timeout_multiplier                = 2;
    server_config.max_fault_number                  = 2;
    server_config.initial_timestamp                 = 0xFFFF;
    server_config.initial_rollover_value            = 0xFFFF;
    server_config.connection_timeout_multiplier     = 1;
    server_config.priority_time_tick                = 0x05;
    server_config.timeout_ticks                     = 156;

    safety::SafetyForwardOpenConfig client_config{};
    client_config.config_assembly                  = 0x0360;
    client_config.consumed_assembly                = 0x00C7;
    client_config.produced_assembly                = 0x0244;
    client_config.consumed_data_size               = 1;
    client_config.produced_data_size               = 1;
    client_config.oto_t_rpi                        = 1000000;  // 1000 ms
    client_config.tto_o_rpi                        = 10000;    // 10 ms
    client_config.oto_t_connection_size            = 6;
    client_config.tto_o_connection_size            = 7;
    client_config.format                            = format;
    client_config.tunid                             = target_tunid;
    client_config.ounid                             = our_ounid;
    client_config.scid                              = scid;
    client_config.ping_interval_multiplier          = 100;
    client_config.time_coord_msg_min_multiplier     = 0;
    client_config.network_time_expectation_multiplier = 313;   // ~40 ms
    client_config.timeout_multiplier                = 2;
    client_config.max_fault_number                  = 2;
    client_config.initial_timestamp                 = 0xFFFF;
    client_config.initial_rollover_value            = 0xFFFF;
    client_config.connection_timeout_multiplier     = 1;
    client_config.priority_time_tick                = 0x05;
    client_config.timeout_ticks                     = 156;

    // ---- Connect TCP + bring up UDP transport on standard I/O port ----
    protocol::EipScanner scanner;
    std::printf("Connecting to %s:44818 ...", target_ip.c_str());
    std::fflush(stdout);
    try {
        scanner.connect(target_ip);
        std::printf(" OK (session 0x%08X)\n", scanner.session_handle());
    } catch (const std::exception& e) {
        std::printf("\nFAIL: %s\n", e.what());
        return 1;
    }

    // UDP transport bound to UDP/2222 — passed to SafetyScannerConnection,
    // which installs its own connection-id dispatch handler on it.
    protocol::EipUdpTransport udp;
    udp.start(protocol::IpEndpoint{"0.0.0.0", protocol::EipUdpTransport::IoPort});

    // ---- Open safety connection ----
    std::unique_ptr<safety::SafetyScannerConnection> conn;
    try {
        std::printf("Opening safety connection pair ...\n");
        conn = safety::SafetyScannerConnection::open(
            scanner, udp, server_config, client_config,
            orig_vendor, orig_serial,
            route_prefix, server_app_path, client_app_path);
    } catch (const std::exception& e) {
        std::printf("FAIL: %s\n", e.what());
        scanner.disconnect();
        udp.stop();
        return 1;
    }

    conn->set_log_handler([](const std::string& m) {
        std::printf("[SAFETY] %s\n", m.c_str());
    });
    conn->set_data_received_handler([](std::span<const uint8_t> data) {
        std::printf("[DATA] ");
        for (uint8_t b : data) std::printf("%02X ", b);
        std::printf("\n");
    });

    // Safe-state output: single zero byte.
    std::array<uint8_t, 1> safe_state{0x00};
    conn->set_output_data(safe_state);

    std::printf("Running. Ctrl+C to stop.\n\n");
#ifndef _WIN32
    std::signal(SIGTERM, on_signal);
#endif
    std::signal(SIGINT, on_signal);

    int tick = 0;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(1s);
        ++tick;
        std::printf("[tick %d] tx=%llu rx=%llu\n",
                     tick,
                     static_cast<unsigned long long>(conn->tx_count()),
                     static_cast<unsigned long long>(conn->rx_count()));
    }

    std::printf("\nClosing ...\n");
    conn->close();
    scanner.disconnect();
    udp.stop();
    std::printf("Done.\n");
    return 0;
}
