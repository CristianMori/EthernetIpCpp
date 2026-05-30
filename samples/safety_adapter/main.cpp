// EthernetIPCpp Safety Adapter — mirrors the Python examples/safety_adapter.py.
//
// Listens on TCP 44818 / UDP 2222, accepts safety FwdOpens from a Logix PLC,
// and runs the producer/consumer state machine: CRC encode/decode, TCOO with
// CTCV slew, ping-change detection, originator-rollover tracking.
//
// Default profile targets your bench ControlLogix at 192.168.1.96 (we bind
// 192.168.1.84 with SNN 4D8D_00B4_12C9, node 0xC0A80154). Use --profile=test2
// for a generic synthetic-scanner setup, or override individual flags.

#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/safety/safety_device.hpp"
#include "ethernetip/safety/safety_types.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using namespace ethernetip;

namespace {
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

// Argument helpers: scan argv for "--key=value" and return the value or default.
std::string get_arg(int argc, char** argv, std::string_view key, std::string_view fallback) {
    std::string prefix = "--";
    prefix += key;
    prefix += '=';
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        if (a.size() > prefix.size()
            && std::memcmp(a.data(), prefix.data(), prefix.size()) == 0) {
            return std::string(a.substr(prefix.size()));
        }
    }
    return std::string(fallback);
}

uint32_t parse_hex_or_dec(const std::string& s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return static_cast<uint32_t>(std::strtoul(s.c_str() + 2, nullptr, 16));
    }
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 10));
}

// "4D8D_00B4_12C9" -> { 0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D }
std::array<uint8_t, 6> parse_snn(const std::string& s) {
    std::string hex;
    hex.reserve(12);
    for (char c : s) if (c != '_' && c != '-' && c != ' ') hex += c;
    if (hex.size() != 12) throw std::invalid_argument("SNN needs 12 hex chars");
    std::array<uint8_t, 6> out{};
    for (size_t i = 0; i < 6; ++i) {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        out[5 - i] = static_cast<uint8_t>(std::strtoul(byte_str, nullptr, 16));
    }
    return out;
}

std::string format_snn(const std::array<uint8_t, 6>& b) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02X%02X_%02X%02X_%02X%02X",
                   b[5], b[4], b[3], b[2], b[1], b[0]);
    return buf;
}

void log_line(const char* tag, const char* fmt, ...) {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    char ts[16];
    std::strftime(ts, sizeof(ts), "%H:%M:%S", &tm_buf);
    std::fprintf(stderr, "[%s] %s ", ts, tag);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}
} // namespace

int main(int argc, char** argv) {
    std::string profile = get_arg(argc, argv, "profile", "plc");

    // ---- Profile defaults ----
    uint16_t default_vendor;
    std::array<uint8_t, 6> default_snn;
    uint32_t default_node;
    std::string default_bind;
    uint32_t default_asm1, default_asm2, default_asm_cfg;

    if (profile == "plc") {
        // Bench ControlLogix at 192.168.1.96; adapter on 192.168.1.84.
        default_vendor   = 1;                                      // Rockwell
        default_snn      = {0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D};   // SNN 4D8D_00B4_12C9
        default_node     = 0xC0A80154u;                            // 192.168.1.84 packed BE
        default_bind     = "192.168.1.84";
        default_asm1     = 1;
        default_asm2     = 199;
        default_asm_cfg  = 199;
    } else {
        // Synthetic test scanner (e.g. an emulator on 192.168.204.0/24).
        default_vendor   = 12;
        default_snn      = {0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D};   // SNN 4D90_0101_A35C
        default_node     = 0xC0A8CC01u;                            // 192.168.204.1 packed BE
        default_bind     = "192.168.204.1";
        default_asm1     = 1;
        default_asm2     = 2;
        default_asm_cfg  = 197;
    }

    // ---- CLI overrides ----
    uint16_t vendor_id   = static_cast<uint16_t>(parse_hex_or_dec(
        get_arg(argc, argv, "vendor", std::to_string(default_vendor))));
    uint32_t serial      = parse_hex_or_dec(
        get_arg(argc, argv, "serial", "0xC0FFEE42"));
    std::string product  = get_arg(argc, argv, "product", "EthernetIPCpp Safety Module");
    std::array<uint8_t, 6> snn_bytes = parse_snn(
        get_arg(argc, argv, "snn", format_snn(default_snn)));
    uint32_t node_addr   = parse_hex_or_dec(get_arg(argc, argv, "node",
        std::to_string(default_node)));    // accepts decimal or 0x...
    std::string bind     = get_arg(argc, argv, "bind", default_bind);
    uint32_t asm1        = parse_hex_or_dec(get_arg(argc, argv, "asm-data1",   std::to_string(default_asm1)));
    uint32_t asm2        = parse_hex_or_dec(get_arg(argc, argv, "asm-data2",   std::to_string(default_asm2)));
    uint32_t asm_cfg     = parse_hex_or_dec(get_arg(argc, argv, "asm-config",  std::to_string(default_asm_cfg)));
    int startup_trace_s  = static_cast<int>(parse_hex_or_dec(
        get_arg(argc, argv, "startup-trace", "0")));

    if (get_arg(argc, argv, "trace", "0") != "0") {
        safety::SafetyDevice::enable_trace.store(true);
    }
    safety::SafetyDevice::startup_trace_seconds.store(startup_trace_s);

    cip::IdentityInfo identity;
    identity.vendor_id     = vendor_id;
    identity.device_type   = 0;
    identity.product_code  = 26;
    identity.major_revision = 1;
    identity.minor_revision = 1;
    identity.serial_number = serial;
    identity.product_name  = product;

    log_line("==", "EthernetIPCpp Safety Adapter (%s)", profile.c_str());
    log_line("==", "Bind=%s Node=0x%08X", bind.c_str(), node_addr);
    log_line("==", "Identity: Vendor=0x%04X Serial=0x%08X Name=\"%s\"",
              vendor_id, serial, product.c_str());
    log_line("==", "SNN: %s", format_snn(snn_bytes).c_str());
    log_line("==", "Assemblies: data1=%u data2=%u config=%u", asm1, asm2, asm_cfg);

    safety::SafetyDevice device(identity, bind,
                                  safety::SafetyNetworkNumber(snn_bytes),
                                  node_addr, "SafeTest");

    auto& safety1 = device.add_assembly(asm1, 1, "Safety Data 1");
    device.add_assembly(asm2, 1, "Safety Data 2");
    // Logix safety configs often map asm_cfg onto one of the data instances.
    // Skip the redundant registration when it would replace an existing one.
    if (asm_cfg != asm1 && asm_cfg != asm2) {
        device.add_assembly(asm_cfg, 0, "Configuration");
    }
    safety1.write<uint8_t>(0, 0x42);   // give the consumer something non-zero

    // Connection lifecycle hooks for visibility.
    int conn_count = 0;
    device.connection_manager().on_connection_established.push_back(
        [&](connections::IoConnection& c) {
            ++conn_count;
            log_line("[CONN]", "#%d open  serial=0x%04X class=%s safety=%d "
                                "OT-asm=%u(%uB@%.1fms) TO-asm=%u(%uB@%.1fms)",
                      conn_count, c.connection_serial_number,
                      (c.transport_class == connections::TransportClass::Class0 ? "C0" :
                       c.transport_class == connections::TransportClass::Class1 ? "C1" : "C6"),
                      c.is_safety,
                      c.consumed_assembly_instance, c.oto_t_size, c.oto_t_rpi / 1000.0,
                      c.produced_assembly_instance, c.tto_o_size, c.tto_o_rpi / 1000.0);
            if (c.is_safety) {
                log_line("[CONN]", "      fmt=%u S1=0x%02X S3=0x%04X",
                          c.safety_format, c.safety_pid_seed_s1, c.safety_pid_seed_s3);
            }
        });
    device.connection_manager().on_connection_removed.push_back(
        [](connections::IoConnection& c) {
            log_line("[CONN]", "close serial=0x%04X state=%d",
                      c.connection_serial_number, static_cast<int>(c.state));
        });

    device.start();
    std::signal(SIGINT, on_signal);
#ifndef _WIN32
    std::signal(SIGTERM, on_signal);
#endif

    log_line("==", "Ready. Ctrl+C to stop.");

    int tick = 0;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(500ms);
        ++tick;
        uint8_t d = safety1.read<uint8_t>(0);
        size_t conns = device.connection_manager().active_connections().size();
        std::fprintf(stderr, "\r[%lld] Data=0x%02X Conns=%zu T->O=%llu    ",
                      static_cast<long long>(tick), d, conns,
                      static_cast<unsigned long long>(device.tto_o_send_count()));
        std::fflush(stderr);
        if (tick % 10 == 0) std::fputc('\n', stderr);
    }
    std::fputc('\n', stderr);
    log_line("==", "Stopping...");
    device.close();
    return 0;
}
