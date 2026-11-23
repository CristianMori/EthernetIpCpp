// Smoke test for an installed EthernetIPCpp: headers resolve and the static
// libraries link (protocol, logix, safety).
#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <cstdio>

int main() {
    ethernetip::protocol::sock::ensure_initialized();

    ethernetip::logix::TagDatabase db;
    auto& tag = db.add_tag("rate", ethernetip::logix::logix_data_types::Dint);
    if (db.find_by_name("rate") != &tag) {
        std::puts("tag lookup failed");
        return 1;
    }
    std::puts("EthernetIPCpp package OK");
    return 0;
}
