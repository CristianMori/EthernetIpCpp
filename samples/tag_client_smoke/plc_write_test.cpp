// One-shot write/read/restore test for a single DINT tag on the real PLC.
// Reads original, writes sentinel, reads back, restores original.
//
// usage: plc_write_test <host> <dint-tag-name> [<sentinel>]
//   default sentinel = 12345

#include "ethernetip/logix/tag_client.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

using ethernetip::logix::TagClient;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <host> <dint-tag> [<sentinel>]\n", argv[0]);
        return 2;
    }
    std::string host = argv[1];
    std::string tag  = argv[2];
    int32_t sentinel = (argc > 3) ? std::atoi(argv[3]) : 12345;

    TagClient client(host);
    try {
        std::printf("Connecting to %s ...\n", host.c_str());
        client.connect();

        int32_t original = client.read<int32_t>(tag);
        std::printf("  initial  %s = %d\n", tag.c_str(), original);

        std::printf("  writing  %s = %d (sentinel) ...\n", tag.c_str(), sentinel);
        client.write<int32_t>(tag, sentinel);

        int32_t readback = client.read<int32_t>(tag);
        std::printf("  readback %s = %d  (expected %d) -> %s\n",
                     tag.c_str(), readback, sentinel,
                     readback == sentinel ? "PASS" : "FAIL");

        std::printf("  restoring %s = %d ...\n", tag.c_str(), original);
        client.write<int32_t>(tag, original);

        int32_t final = client.read<int32_t>(tag);
        std::printf("  final    %s = %d  (expected %d) -> %s\n",
                     tag.c_str(), final, original,
                     final == original ? "PASS" : "FAIL");

        client.disconnect();
        bool ok = readback == sentinel && final == original;
        std::printf("\n%s\n", ok ? "ALL PASS" : "SOME FAIL");
        return ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
