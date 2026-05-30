// Read multiple known atomics from the real PLC in one round-trip.
// usage: plc_multi_read <host>

#include "ethernetip/logix/tag_client.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>

using ethernetip::logix::TagClient;

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <host>\n", argv[0]); return 2; }
    TagClient client(argv[1]);
    try {
        client.connect();
        auto res = client.read_multiple({"StopMolues", "StopComm", "CommStopped"});
        std::printf("read_multiple returned %zu entries\n", res.size());
        for (const auto& [name, bytes] : res) {
            std::printf("  %s: %zu bytes  tag_type=0x%02X%02X\n",
                         name.c_str(), bytes.size(),
                         bytes.size() > 1 ? bytes[1] : 0,
                         bytes.size() > 0 ? bytes[0] : 0);
            if (bytes.size() >= 3) {
                if ((bytes[0] & 0xFF) == 0xC4 && bytes.size() >= 6) {  // DINT
                    int32_t v; std::memcpy(&v, bytes.data() + 2, 4);
                    std::printf("    DINT value: %d\n", v);
                } else if ((bytes[0] & 0xFF) == 0xC1) {                // BOOL
                    std::printf("    BOOL value: %d\n", static_cast<int>(bytes[2]));
                }
            }
        }
        client.disconnect();
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
