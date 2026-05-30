#pragma once

#include "ethernetip/logix/logix_data_types.hpp"
#include "ethernetip/protocol/socket_compat.hpp"

#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ethernetip::logix {

/// One tag discovered via TagClient::browse(). Holds the symbol-object
/// instance ID plus enough metadata to decide structure vs atomic.
struct TagInfo {
    std::string name;
    uint32_t    instance_id = 0;
    uint16_t    symbol_type = 0;
    bool        is_struct   = false;
    bool        is_system   = false;
    int         array_dimensions = 0;
    /// Atomic: CIP type code. Struct: template instance ID.
    uint16_t    type_code   = 0;
};

/// One member within a structure template.
struct TemplateMemberDetail {
    std::string name;
    uint16_t    data_type = 0;
    /// Array size for arrays, bit position for BOOLs, 0 for scalars.
    uint16_t    info      = 0;
    uint32_t    offset    = 0;

    [[nodiscard]] bool is_array() const noexcept {
        return info > 0 && data_type != logix_data_types::Bool;
    }
};

/// Structure template definition read via TagClient::read_template().
struct TemplateInfo {
    uint16_t    instance_id      = 0;
    std::string name;
    uint16_t    structure_handle = 0;
    uint16_t    member_count     = 0;
    uint32_t    definition_size  = 0;   ///< in 32-bit words (Template Object attr 4)
    uint32_t    structure_size   = 0;   ///< bytes on wire (attr 5)
    std::vector<TemplateMemberDetail> members;
};

/// Synchronous CIP/EtherNet/IP client for reading and writing Logix tags.
/// TCP-only: connects, registers a session, sends explicit messages via
/// SendRRData. No UDP, no Forward Open, no I/O connections.
///
/// Methods throw std::runtime_error on network or CIP-protocol errors.
class TagClient {
public:
    static constexpr int DefaultPort = 44818;

    explicit TagClient(std::string host, int port = DefaultPort);
    ~TagClient();

    TagClient(const TagClient&)            = delete;
    TagClient& operator=(const TagClient&) = delete;

    /// Open TCP, RegisterSession.
    void connect();

    /// UnregisterSession, close. Idempotent.
    void disconnect() noexcept;

    [[nodiscard]] bool       is_connected()   const noexcept;
    [[nodiscard]] uint32_t   session_handle() const noexcept { return session_handle_; }
    [[nodiscard]] const std::string& host()   const noexcept { return host_; }

    // ---- Tag access (atomic) ----

    /// Read a scalar value by tag name. Throws on CIP error / wrong size.
    template <class T>
    T read(std::string_view tag_name) {
        static_assert(std::is_trivially_copyable_v<T>);
        auto resp = read_tag_raw(tag_name, 1);
        // Response layout: tag_type(2) + data
        if (resp.size() < 2 + sizeof(T)) {
            throw std::runtime_error("read: response too short for requested type");
        }
        T out{};
        std::memcpy(&out, resp.data() + 2, sizeof(T));
        return out;
    }

    /// Read N elements of an array tag.
    template <class T>
    std::vector<T> read_array(std::string_view tag_name, uint16_t element_count) {
        static_assert(std::is_trivially_copyable_v<T>);
        auto resp = read_tag_raw(tag_name, element_count);
        if (resp.size() < 2u + static_cast<size_t>(element_count) * sizeof(T)) {
            throw std::runtime_error("read_array: response too short");
        }
        std::vector<T> out(element_count);
        std::memcpy(out.data(), resp.data() + 2, element_count * sizeof(T));
        return out;
    }

    /// Write a scalar value by tag name.
    template <class T>
    void write(std::string_view tag_name, T value) {
        static_assert(std::is_trivially_copyable_v<T>);
        std::vector<uint8_t> bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        write_raw(tag_name, guess_tag_type<T>(), /*element_count=*/1, bytes);
    }

    /// Raw read: returns the body of the Read Tag response (tag_type(2) + data).
    [[nodiscard]] std::vector<uint8_t> read_tag_raw(std::string_view tag_name,
                                                       uint16_t element_count);

    /// Raw write: caller provides the tag type, element count, and bytes.
    void write_raw(std::string_view tag_name, uint16_t tag_type,
                    uint16_t element_count, std::span<const uint8_t> value);

    // ---- Logix STRING (88-byte UDT) ----

    /// Read a Logix STRING tag as a std::string. Reads the structure and
    /// extracts LEN + DATA per Logix STRING layout.
    [[nodiscard]] std::string read_string(std::string_view tag_name);

    /// Write a Logix STRING tag. `structure_handle` comes from the template
    /// (e.g. via browse() / read_template()).
    void write_string(std::string_view tag_name, std::string_view value,
                       uint16_t structure_handle);

    /// Write a structure tag (already-encoded bytes). Uses the 0x02A0 +
    /// structure_handle preamble per the Logix structured Write Tag form.
    void write_struct(std::string_view tag_name, uint16_t structure_handle,
                       uint16_t element_count, std::span<const uint8_t> value);

    /// Read a structure tag and return the raw bytes (header stripped — just
    /// the structure_size bytes the controller sent). Caller wraps these in a
    /// StructureValue using the matching TemplateInfo.
    [[nodiscard]] std::vector<uint8_t>
        read_struct_bytes(std::string_view tag_name);

    // ---- Multi-tag access (Multiple Service Packet, 0x0A) ----

    /// Read many tags in one round-trip. Returns a map keyed by tag name.
    /// Each value is the raw Read Tag response body: tag_type(2) + data.
    /// Entries for tags that returned a CIP error are omitted from the map.
    [[nodiscard]] std::map<std::string, std::vector<uint8_t>>
        read_multiple(const std::vector<std::string>& tag_names);

    /// One atomic write in a batch.
    struct WriteEntry {
        std::string          name;
        uint16_t             tag_type      = 0;   ///< CIP type code (e.g. logix_data_types::Dint)
        uint16_t             element_count = 1;
        std::vector<uint8_t> value;
    };

    /// Write many tags in one round-trip. Returns a map keyed by tag name
    /// with the CIP general status per write (0x00 = success).
    [[nodiscard]] std::map<std::string, uint8_t>
        write_multiple(const std::vector<WriteEntry>& writes);

    // ---- Tag browsing ----

    /// Enumerate tags via Symbol Object class-level Get_Instance_Attribute_List
    /// (0x55). Paginates until the controller reports no more. If `program` is
    /// set (e.g. "Program:MainProgram"), enumerates that program's scope tags;
    /// otherwise enumerates the controller scope.
    [[nodiscard]] std::vector<TagInfo>
        browse(std::optional<std::string_view> program = std::nullopt);

    /// Fetch a structure template by instance ID. Reads attributes 1/2/4/5
    /// then Template_Read (0x4C) to get the member info + names.
    [[nodiscard]] TemplateInfo read_template(uint16_t template_instance_id);

private:
    /// Send an MR request via Unconnected Send (wrapped in SendRRData) and
    /// return (general_status, response_data). Caller decides how to interpret
    /// the status. Throws on transport / encapsulation failure.
    std::pair<uint8_t, std::vector<uint8_t>>
        send_cip_with_status(uint8_t service_code,
                              std::span<const uint8_t> cip_path,
                              std::span<const uint8_t> service_data);

    /// Same as above, but throws on non-success / non-"more data" status.
    /// Returns just the response data.
    std::vector<uint8_t>
        send_cip(uint8_t service_code,
                  std::span<const uint8_t> cip_path,
                  std::span<const uint8_t> service_data);

    /// Low-level encapsulation send. Writes the header + payload, reads the
    /// reply, returns the reply payload (after the encapsulation header).
    std::vector<uint8_t>
        send_encapsulated(uint16_t command, std::span<const uint8_t> payload);

    /// Helpers — ANSI Extended Symbolic path for dotted tag names, and a
    /// .NET-style type → Logix-type lookup for write<T>.
    [[nodiscard]] static std::vector<uint8_t> build_symbolic_path(std::string_view name);

    template <class T>
    [[nodiscard]] static constexpr uint16_t guess_tag_type() {
        using namespace logix_data_types;
        if constexpr (std::is_same_v<T, bool>)                                              return Bool;
        else if constexpr (std::is_same_v<T, int8_t>  || std::is_same_v<T, uint8_t>)        return Sint;
        else if constexpr (std::is_same_v<T, int16_t> || std::is_same_v<T, uint16_t>)       return Int;
        else if constexpr (std::is_same_v<T, int32_t> || std::is_same_v<T, uint32_t>)       return Dint;
        else if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>)       return Lint;
        else if constexpr (std::is_same_v<T, float>)                                        return Real;
        else if constexpr (std::is_same_v<T, double>)                                       return Lreal;
        else                                                                                static_assert(sizeof(T) == 0, "Unsupported type for TagClient::write<T>");
    }

    void read_exact(uint8_t* dst, size_t n);

    std::string         host_;
    int                 port_           = DefaultPort;
    protocol::sock::socket_t socket_     = protocol::sock::invalid;
    uint32_t            session_handle_ = 0;
    std::mutex          io_mu_;                   // serializes request/response on the socket
};

} // namespace ethernetip::logix
