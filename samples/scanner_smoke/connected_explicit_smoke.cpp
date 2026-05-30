// Connected-explicit smoke test. Exercises both UCMM (send_explicit) and
// Class 3 connected explicit (open_explicit + send) round-trips against an
// adapter that supports both — typically samples/echo_module or
// samples/cip_echo_server.
//
//   usage: connected_explicit_smoke [host] [port]
//
// Tests, in order:
//   1. UCMM GetAttributeSingle on Identity attr 7 — verifies UCMM path
//   2. Class 3 Forward Open
//   3. Class 3 GetAttributeSingle on Identity attr 7
//   4. Class 3 catch-all custom message (svc 0xCD class 0xDE inst 2 attr 156)
//      with a 7-DINT payload — verifies the unhandled-service path and
//      that the response payload is returned correctly.

#include "ethernetip/cip/cip_service.hpp"
#include "ethernetip/protocol/connected_explicit.hpp"
#include "ethernetip/protocol/eip_scanner.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

using ethernetip::protocol::EipScanner;

static std::string identity_name(std::span<const uint8_t> data) {
    if (data.empty()) return "<empty>";
    uint8_t name_len = data[0];
    return std::string(reinterpret_cast<const char*>(data.data() + 1),
                         std::min<size_t>(name_len, data.size() - 1));
}

int main(int argc, char** argv) {
    std::string host = (argc > 1) ? argv[1]              : "127.0.0.1";
    int         port = (argc > 2) ? std::atoi(argv[2])   : 44818;

    EipScanner scanner;
    try {
        std::printf("Connecting to %s:%d ...\n", host.c_str(), port);
        scanner.connect(host, port);
        std::printf("  session = 0x%08X\n", scanner.session_handle());

        // ---- 1. UCMM ----
        std::printf("\n[UCMM] GetAttributeSingle(class=1, inst=1, attr=7) ...\n");
        std::array<uint8_t, 6> id_path{0x20, 0x01, 0x24, 0x01, 0x30, 0x07};
        auto ucmm = scanner.send_explicit(0x0E, id_path, {});
        std::printf("  status=0x%02X  data=%zu bytes  ProductName=\"%s\"\n",
                     ucmm.status.general_status, ucmm.data.size(),
                     identity_name(ucmm.data).c_str());

        // ---- 2/3. Class 3 ----
        std::printf("\n[Class3] Opening connection ...\n");
        auto conn = scanner.open_explicit();
        std::printf("  open\n");

        auto c3_id = conn->send(0x0E, /*class=*/0x01, /*inst=*/1, /*attr=*/7);
        std::printf("  GetAttributeSingle(class=1, inst=1, attr=7): status=0x%02X "
                     "data=%zu bytes  ProductName=\"%s\"\n",
                     c3_id.status.general_status, c3_id.data.size(),
                     identity_name(c3_id.data).c_str());

        // ---- 4. Class 3 catch-all custom message ----
        std::printf("\n[Class3] Custom svc=0xCD class=0xDE inst=2 attr=156 with 28-byte payload ...\n");
        std::array<uint8_t, 28> payload{};
        for (int i = 0; i < 7; ++i) {
            uint32_t v = 1000u + i;  // 7 DINTs: 1000, 1001, ..., 1006
            std::memcpy(payload.data() + i * 4, &v, 4);
        }
        auto c3_echo = conn->send(0xCD, /*class=*/0xDE, /*inst=*/2, /*attr=*/156, payload);
        std::printf("  status=0x%02X  reply data(%zu)=",
                     c3_echo.status.general_status, c3_echo.data.size());
        for (auto b : c3_echo.data) std::printf("%02X ", b);
        std::printf("\n");

        conn->close();
        scanner.disconnect();
        std::printf("\nDone.\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
