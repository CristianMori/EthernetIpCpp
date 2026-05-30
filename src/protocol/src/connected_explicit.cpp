#include "ethernetip/protocol/connected_explicit.hpp"

#include "ethernetip/cip/path_builder.hpp"
#include "ethernetip/protocol/eip_scanner.hpp"

namespace ethernetip::protocol {

ConnectedExplicit::ConnectedExplicit(EipScanner& scanner,
                                       uint32_t oto_t_connection_id,
                                       uint32_t tto_o_connection_id,
                                       uint16_t connection_serial,
                                       uint16_t originator_vendor,
                                       uint32_t originator_serial)
    : scanner_(scanner),
      oto_t_connection_id_(oto_t_connection_id),
      tto_o_connection_id_(tto_o_connection_id),
      connection_serial_(connection_serial),
      originator_vendor_(originator_vendor),
      originator_serial_(originator_serial) {}

ConnectedExplicit::~ConnectedExplicit() {
    close();
}

cip::CipServiceResponse
ConnectedExplicit::send(uint8_t service_code,
                          uint32_t class_id, uint32_t instance_id,
                          std::optional<uint16_t> attribute_id,
                          std::span<const uint8_t> data) {
    auto path = cip::build_path(class_id, instance_id, attribute_id);
    return send_raw(service_code, path, data);
}

cip::CipServiceResponse
ConnectedExplicit::send_raw(uint8_t service_code,
                              std::span<const uint8_t> path_bytes,
                              std::span<const uint8_t> data) {
    if (!open_.load()) {
        throw std::runtime_error("ConnectedExplicit: closed");
    }
    uint16_t seq = seq_count_.fetch_add(1) + 1;
    return scanner_.send_connected_mr(oto_t_connection_id_, seq,
                                        service_code, path_bytes, data);
}

void ConnectedExplicit::close() {
    if (!open_.exchange(false)) return;
    try {
        scanner_.forward_close(connection_serial_, originator_vendor_, originator_serial_);
    } catch (...) {}
}

} // namespace ethernetip::protocol
