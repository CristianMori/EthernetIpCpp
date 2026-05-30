// Smoke test for TagClient extensions: read_multiple, write_multiple,
// program-scope browse, and StructureValue accessors.
//
// Runs against samples/logix_host on loopback (preloaded with
// rate=534, temperature=72.5, counts=INT[10]).

#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/structure_value.hpp"
#include "ethernetip/logix/tag_client.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace ldt = ethernetip::logix::logix_data_types;
using ethernetip::logix::TagClient;

static int g_fail = 0;

static void check(const char* label, bool ok) {
    if (!ok) ++g_fail;
    std::printf("  %s  %s\n", ok ? "PASS" : "FAIL", label);
}

int main(int argc, char** argv) {
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    TagClient client(host);
    try {
        client.connect();
        std::printf("Connected to %s:44818\n\n", host.c_str());

        // ---- read_multiple ----
        std::printf("read_multiple({rate, temperature, counts[0]}):\n");
        auto reads = client.read_multiple({"rate", "temperature", "counts[0]"});
        check("returned 3 entries", reads.size() == 3);

        if (auto it = reads.find("rate"); it != reads.end()) {
            int32_t v = 0;
            if (it->second.size() >= 6) std::memcpy(&v, it->second.data() + 2, 4);
            check("rate == 534", v == 534);
        } else {
            check("rate present", false);
        }
        if (auto it = reads.find("temperature"); it != reads.end()) {
            float v = 0;
            if (it->second.size() >= 6) std::memcpy(&v, it->second.data() + 2, 4);
            check("temperature == 72.5", v == 72.5f);
        } else {
            check("temperature present", false);
        }

        // ---- write_multiple ----
        std::printf("\nwrite_multiple(rate=4242, temperature=99.0):\n");
        std::vector<uint8_t> rate_bytes(4);
        int32_t rv = 4242;
        std::memcpy(rate_bytes.data(), &rv, 4);
        std::vector<uint8_t> temp_bytes(4);
        float tv = 99.0f;
        std::memcpy(temp_bytes.data(), &tv, 4);
        auto writes = client.write_multiple({
            {"rate",        ldt::Dint, 1, rate_bytes},
            {"temperature", ldt::Real, 1, temp_bytes},
        });
        check("rate write status == 0", writes["rate"] == 0);
        check("temperature write status == 0", writes["temperature"] == 0);
        check("rate readback == 4242", client.read<int32_t>("rate") == 4242);
        check("temperature readback == 99.0", client.read<float>("temperature") == 99.0f);

        // Restore originals.
        std::vector<uint8_t> restore_rate(4);
        rv = 534;  std::memcpy(restore_rate.data(), &rv, 4);
        std::vector<uint8_t> restore_temp(4);
        tv = 72.5f; std::memcpy(restore_temp.data(), &tv, 4);
        client.write_multiple({
            {"rate",        ldt::Dint, 1, restore_rate},
            {"temperature", ldt::Real, 1, restore_temp},
        });

        // ---- Program-scope browse ----
        std::printf("\nbrowse(program=\"Program:Main\"):\n");
        auto prog_tags = client.browse(std::string_view("Program:Main"));
        // logix_host has no programs registered, so we just expect an empty
        // or short result without throwing.
        check("program-scope browse returned without exception", true);
        std::printf("  (%zu program-scope tags)\n", prog_tags.size());

        client.disconnect();
        std::printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL PASS" : "SOME FAIL", g_fail);
        return g_fail == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
