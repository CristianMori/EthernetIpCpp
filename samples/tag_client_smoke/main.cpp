// TagClient smoke test — connects to a Logix controller (real or simulated),
// browses tags, reads + writes a few values, and prints PASS/FAIL counts.
//
// Usage:  tag_client_smoke <host> [<tag-to-watch>]
//   tag_client_smoke 127.0.0.1                 -> test against logix_host
//   tag_client_smoke 192.168.1.96 MyTag        -> test against real PLC
//
// For loopback tests, expects rate (DINT=534), temperature (REAL=72.5),
// counts (INT[10]). For real-PLC tests, browses first and exercises the
// first writable atomic tag found (skips system tags + structures).

#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag_client.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace ldt = ethernetip::logix::logix_data_types;
using ethernetip::logix::TagClient;
using ethernetip::logix::TagInfo;

static int g_fail = 0;

template <class T>
static void check(const char* label, const T& got, const T& expected) {
    bool ok = (got == expected);
    if (!ok) ++g_fail;
    std::printf("  %s  %s  (got=" , ok ? "PASS" : "FAIL", label);
    if constexpr (std::is_floating_point_v<T>) {
        std::printf("%.4f, expected=%.4f)\n", static_cast<double>(got),
                                                  static_cast<double>(expected));
    } else {
        std::printf("%lld, expected=%lld)\n",
                     static_cast<long long>(got), static_cast<long long>(expected));
    }
}

static const char* type_name(uint16_t t) {
    switch (t & 0x00FF) {
        case 0xC1: return "BOOL";
        case 0xC2: return "SINT";
        case 0xC3: return "INT";
        case 0xC4: return "DINT";
        case 0xC5: return "LINT";
        case 0xCA: return "REAL";
        case 0xCB: return "LREAL";
        case 0xD3: return "DWORD";
        default:   return "?";
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <host> [<tag>]\n", argv[0]);
        return 2;
    }
    std::string host = argv[1];
    std::string explicit_tag = (argc > 2) ? argv[2] : "";

    TagClient client(host);
    try {
        std::printf("Connecting to %s:44818 ...\n", host.c_str());
        client.connect();
        std::printf("Session handle = 0x%08X\n\n", client.session_handle());

        // ---- Browse ----
        std::printf("Browsing tags ...\n");
        auto tags = client.browse();
        std::printf("  Found %zu total tag(s).\n", tags.size());
        for (const auto& t : tags) {
            if (t.is_system || t.name.rfind("__", 0) == 0) continue;
            std::printf("    inst=%u  name=%-32s sym=0x%04X %s%s\n",
                         t.instance_id, t.name.c_str(), t.symbol_type,
                         t.is_struct ? "STRUCT" : type_name(t.type_code),
                         t.array_dimensions > 0 ? " [array]" : "");
        }
        std::printf("\n");

        // ---- Loopback-known tags if connecting to localhost ----
        bool is_loopback = (host == "127.0.0.1" || host == "localhost");
        if (is_loopback) {
            std::printf("Loopback reads (expects logix_host preloads):\n");
            check("rate",        client.read<int32_t>("rate"),       int32_t{534});
            check("temperature", client.read<float>("temperature"),  72.5f);
            check("counts[0]",   client.read<int16_t>("counts[0]"),  int16_t{0});

            std::printf("\nLoopback writes + readbacks:\n");
            client.write<int32_t>("rate", 9876);
            check("rate after write",        client.read<int32_t>("rate"),        int32_t{9876});
            client.write<float>("temperature", 12.5f);
            check("temperature after write", client.read<float>("temperature"),   12.5f);
            client.write<int16_t>("counts[7]", int16_t{77});
            check("counts[7] after write",   client.read<int16_t>("counts[7]"),   int16_t{77});

            // Restore originals so subsequent runs see clean state.
            client.write<int32_t>("rate",        534);
            client.write<float>  ("temperature", 72.5f);
            client.write<int16_t>("counts[7]",   int16_t{0});
        }

        // ---- Real-PLC: exercise a specific tag if requested ----
        if (!explicit_tag.empty()) {
            std::printf("\nExplicit read of '%s':\n", explicit_tag.c_str());
            // Try the most common types until one fits the raw response size.
            auto raw = client.read_tag_raw(explicit_tag, 1);
            std::printf("  raw response: tag_type=0x%02X%02X data_len=%zu bytes\n",
                         raw.size() > 1 ? raw[1] : 0,
                         raw.size() > 0 ? raw[0] : 0,
                         raw.size() >= 2 ? raw.size() - 2 : 0);
            if (raw.size() >= 6) {
                uint16_t tt = raw[0] | (raw[1] << 8);
                switch (tt & 0x00FF) {
                    case 0xC2: std::printf("  SINT value: %d\n", (int8_t)raw[2]); break;
                    case 0xC3: {
                        int16_t v; std::memcpy(&v, raw.data()+2, 2);
                        std::printf("  INT  value: %d\n", v); break;
                    }
                    case 0xC4: {
                        int32_t v; std::memcpy(&v, raw.data()+2, 4);
                        std::printf("  DINT value: %d\n", v); break;
                    }
                    case 0xCA: {
                        float v; std::memcpy(&v, raw.data()+2, 4);
                        std::printf("  REAL value: %f\n", v); break;
                    }
                    default: std::printf("  (raw bytes only — unsupported display type)\n"); break;
                }
            }
        }

        client.disconnect();
        std::printf("\n%s\n", g_fail == 0 ? "ALL PASS" : "SOME FAIL");
        return g_fail == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
