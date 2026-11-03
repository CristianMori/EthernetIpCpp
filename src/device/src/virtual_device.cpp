#include "ethernetip/device/virtual_device.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/device/ethernet_link_object.hpp"
#include "ethernetip/device/identity_object.hpp"
#include "ethernetip/device/tcpip_interface_object.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <utility>

namespace ethernetip::device {

using namespace ethernetip::cip;
using namespace ethernetip::connections;
using namespace ethernetip::protocol;
namespace ser = ethernetip::cip::serializer;
using namespace std::chrono_literals;

// ---- Construction ----------------------------------------------------------

VirtualDevice::VirtualDevice(IdentityInfo identity, std::string bind_address,
                               std::string name)
    : identity_(std::move(identity)),
      bind_address_(std::move(bind_address)),
      name_(name.empty() ? identity_.product_name : std::move(name)) {

    // Wire ConnectionManager hooks to dispatcher + assemblies.
    connection_manager_.validate_assembly = [this](uint32_t instance_id) -> int {
        auto* asm_inst = assemblies_.get_assembly(instance_id);
        return asm_inst != nullptr ? asm_inst->data_size() : -1;
    };
    connection_manager_.dispatch_request =
        [this](uint8_t service_code, const CipPath& path,
                std::span<const uint8_t> data) -> CipServiceResponse {
            return dispatcher_.dispatch(service_code, path, data);
        };
    connection_manager_.on_connection_established.push_back(
        [this](IoConnection& conn) { on_connection_established(conn); });
    // Cancel-and-join the production thread BEFORE the connection manager
    // drops its shared_ptr. Combined with the weak_ptr the thread captures,
    // this guarantees the thread cannot be observing the IoConnection by
    // the time it destructs.
    connection_manager_.on_connection_removed.push_back(
        [this](IoConnection& conn) { stop_production_thread(conn.oto_t_connection_id); });

    // Register standard CIP classes.
    dispatcher_.register_class(identity_object::create(identity_));
    dispatcher_.register_class(tcpip_interface_object::create(bind_address_));
    dispatcher_.register_class(ethernet_link_object::create(bind_address_));
    dispatcher_.register_class(assemblies_.release_cip_class());
    dispatcher_.register_class(connection_manager_.release_cip_class());
}

VirtualDevice::~VirtualDevice() {
    close();
}

AssemblyInstance& VirtualDevice::add_assembly(uint32_t instance_id, int data_size,
                                                std::optional<std::string> name) {
    return assemblies_.add_instance(instance_id, data_size, std::move(name));
}

// ---- Lifecycle -------------------------------------------------------------

void VirtualDevice::start(int tcp_port, int udp_port) {
    tcp_port_ = tcp_port;
    udp_port_ = udp_port;

    adapter_ = std::make_unique<IoEipAdapter>(dispatcher_, identity_);
    adapter_->set_udp_port(static_cast<uint16_t>(udp_port_));
    adapter_->set_on_connection_opened(
        [this](const CipServiceResponse& r, const IpEndpoint& plc) {
            on_connection_opened_from_adapter(r, plc);
        });
    adapter_->listen({bind_address_, static_cast<uint16_t>(tcp_port_)});

    udp_transport_ = std::make_unique<EipUdpTransport>();
    udp_transport_->set_on_message(
        [this](std::unique_ptr<messages::Message> msg) { on_udp_message(std::move(msg)); });
    udp_transport_->start({bind_address_, static_cast<uint16_t>(udp_port_)});

    watchdog_running_.store(true);
    watchdog_thread_ = std::thread([this] { watchdog_loop(); });
}

void VirtualDevice::close() {
    // Stop the watchdog first so it can't keep finding connections to time out.
    watchdog_running_.store(false);
    if (watchdog_thread_.joinable()) watchdog_thread_.join();

    stop_production_threads();

    // Drop all active connections (fires removal callbacks). The snapshot
    // is a vector<shared_ptr>; each pin stays valid for the iteration.
    for (auto& conn : connection_manager_.active_connections()) {
        connection_manager_.remove_connection(*conn);
    }

    if (udp_transport_) { udp_transport_->stop(); udp_transport_.reset(); }
    if (adapter_)        { adapter_->stop();        adapter_.reset(); }
}

// ---- Virtual hooks (default behavior) --------------------------------------

void VirtualDevice::on_connection_ready(IoConnection& conn) {
    if (conn.produced_assembly_instance != 0 && conn.tto_o_rpi > 0) {
        start_production_thread(conn);
    }
}

void VirtualDevice::produce_io_data(IoConnection& conn) {
    if (conn.state.load() != ConnectionState::Established) return;
    auto [host, port, is_set] = conn.get_remote_endpoint();
    if (!is_set) return;
    auto* assembly = assemblies_.get_assembly(conn.produced_assembly_instance);
    if (assembly == nullptr) return;

    bool is_class1 = conn.transport_class == TransportClass::Class1;
    int io_size = is_class1 ? 2 + assembly->data_size() : assembly->data_size();
    std::vector<uint8_t> io_data(io_size);
    if (is_class1) {
        uint16_t seq = conn.cip_sequence_count.fetch_add(1) + 1;
        ser::write_uint(io_data, seq);
        assembly->copy_data_to(std::span<uint8_t>(io_data).subspan(2));
    } else {
        assembly->copy_data_to(io_data);
    }
    send_udp_io_data(conn, io_data);
}

void VirtualDevice::handle_received_io_data(IoConnection& conn,
                                              std::span<const uint8_t> data) {
    auto* assembly = assemblies_.get_assembly(conn.consumed_assembly_instance);
    if (assembly == nullptr) return;

    // O->T Class 1 framing: 2-byte CIP seq + 4-byte run/idle header.
    if (conn.transport_class == TransportClass::Class1 && data.size() >= 6) {
        assembly->set_data(data.subspan(6));
    } else {
        assembly->set_data(data);
    }
}

void VirtualDevice::on_remote_endpoint_updated(IoConnection&, const IpEndpoint&) {}

void VirtualDevice::send_udp_io_data(IoConnection& conn,
                                       std::span<const uint8_t> data) {
    if (!udp_transport_) return;
    auto [host, port, is_set] = conn.get_remote_endpoint();
    if (!is_set) return;
    tto_o_send_count_.fetch_add(1, std::memory_order_relaxed);
    uint32_t seq = conn.encapsulation_sequence_number.fetch_add(1);
    udp_transport_->send_io_data(
        IpEndpoint{std::move(host), port},
        conn.tto_o_connection_id,
        seq,
        data);
}

// ---- Private ---------------------------------------------------------------

void VirtualDevice::on_connection_established(IoConnection& conn) {
    conn.last_received.store(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    if (!conn.config_data.empty() && conn.config_assembly_instance != 0) {
        if (auto* asm_inst = assemblies_.get_assembly(conn.config_assembly_instance)) {
            asm_inst->set_data(conn.config_data);
        }
    }
    on_connection_ready(conn);
}

void VirtualDevice::on_connection_opened_from_adapter(
        const CipServiceResponse& /*response*/, const IpEndpoint& plc_udp) {
    // The adapter just sent a successful Forward Open response. Match the
    // newest connection (no remote endpoint yet) to this PLC and stash it.
    for (auto& conn : connection_manager_.active_connections()) {
        auto [h, p, is_set] = conn->get_remote_endpoint();
        (void)h; (void)p;
        if (!is_set) {
            conn->set_remote_endpoint(plc_udp.host, plc_udp.port);
            break;
        }
    }
}

void VirtualDevice::on_udp_message(std::unique_ptr<messages::Message> msg) {
    if (msg->kind != messages::MessageKind::CpfConnectedData) return;
    auto& cpf = static_cast<messages::CpfConnectedDataMessage&>(*msg);
    // Hold the shared_ptr for the full duration of this handler. A
    // concurrent Forward Close can drop the manager's reference between
    // the lookup and handle_received_io_data, but as long as this
    // shared_ptr is live the IoConnection cannot destruct.
    auto conn = connection_manager_.find_by_oto_t_id(cpf.connection_id);
    if (!conn || conn->state.load() != ConnectionState::Established) return;

    // Learn / update the scanner's UDP sender endpoint — the originator
    // typically sends from a port other than 2222.
    auto [host, port, is_set] = conn->get_remote_endpoint();
    if (!is_set || port != cpf.remote_endpoint.port) {
        conn->set_remote_endpoint(cpf.remote_endpoint.host, cpf.remote_endpoint.port);
        on_remote_endpoint_updated(*conn, cpf.remote_endpoint);
    }

    conn->last_received.store(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    conn->first_received.store(true);
    handle_received_io_data(*conn, cpf.payload);
}

// ---- Production threads ----------------------------------------------------

void VirtualDevice::start_production_thread(IoConnection& conn) {
    std::scoped_lock lock(production_mu_);
    if (production_threads_.count(conn.oto_t_connection_id) != 0) return;

    // Obtain the manager's shared_ptr so the thread can hold a weak_ptr.
    // If the connection is already gone (e.g. a very fast FwdClose that
    // raced the on_connection_ready callback), we have nothing to produce.
    auto conn_sp = connection_manager_.find_by_oto_t_id(conn.oto_t_connection_id);
    if (!conn_sp) return;

    auto cancel = std::make_shared<std::atomic<bool>>(false);
    production_cancel_[conn.oto_t_connection_id] = cancel;

    std::weak_ptr<IoConnection> conn_weak = conn_sp;
    int64_t rpi_us = conn.tto_o_rpi;
    production_threads_[conn.oto_t_connection_id] = std::thread(
        [this, conn_weak, cancel, rpi_us] {
            auto interval = std::chrono::microseconds(rpi_us);
            auto next_send = std::chrono::steady_clock::now() + interval;
            while (!cancel->load(std::memory_order_relaxed)) {
                std::this_thread::sleep_until(next_send);
                if (cancel->load(std::memory_order_relaxed)) break;
                // Lock the weak_ptr once per cycle. A null result means the
                // connection manager has dropped its reference and the
                // thread exits. A valid lock pins the IoConnection for the
                // full duration of produce_io_data — it cannot destruct
                // underneath us mid-call.
                auto conn = conn_weak.lock();
                if (!conn) break;
                if (conn->state.load() != ConnectionState::Established) break;
                produce_io_data(*conn);
                next_send += interval;
                // If we've fallen more than one period behind, re-anchor to
                // now so we don't burst catch-up frames.
                auto now = std::chrono::steady_clock::now();
                if (now - next_send > interval) next_send = now + interval;
            }
        });
}

void VirtualDevice::stop_production_thread(uint32_t oto_t_id) {
    std::thread t;
    {
        std::scoped_lock lock(production_mu_);
        if (auto it = production_cancel_.find(oto_t_id); it != production_cancel_.end()) {
            it->second->store(true, std::memory_order_relaxed);
            production_cancel_.erase(it);
        }
        if (auto it = production_threads_.find(oto_t_id); it != production_threads_.end()) {
            t = std::move(it->second);
            production_threads_.erase(it);
        }
    }
    // Guard against self-join if this is ever invoked from the production
    // thread itself (never today, but cheap insurance).
    if (t.joinable() && t.get_id() != std::this_thread::get_id()) {
        t.join();
    }
}

void VirtualDevice::stop_production_threads() {
    std::unordered_map<uint32_t, std::thread> threads;
    {
        std::scoped_lock lock(production_mu_);
        for (auto& [_, cancel] : production_cancel_) {
            cancel->store(true, std::memory_order_relaxed);
        }
        threads = std::move(production_threads_);
        production_threads_.clear();
        production_cancel_.clear();
    }
    for (auto& [_, t] : threads) {
        if (t.joinable()) t.join();
    }
}

void VirtualDevice::watchdog_loop() {
    while (watchdog_running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(50ms);
        if (!watchdog_running_.load(std::memory_order_relaxed)) break;
        int64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        for (auto& conn : connection_manager_.active_connections()) {
            if (conn->state.load() != ConnectionState::Established) continue;
            if (conn->oto_t_rpi == 0) continue;   // T->O-only connection has no inbound watchdog
            if (!conn->first_received.load()) continue;  // CIP Vol 1 §3-4.5.2: don't count until first frame
            int64_t elapsed = now_us - conn->last_received.load();
            if (elapsed > conn->connection_timeout_us()) {
                connection_manager_.timeout_connection(*conn);
            }
        }
    }
}

} // namespace ethernetip::device
