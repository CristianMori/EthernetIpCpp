# EthernetIPCpp

A complete EtherNet/IP and CIP Safety protocol stack written in C++20. Acts as **adapter** (target / I/O slave), **scanner** (originator / I/O master), or **Logix-compatible tag server / client** — with or without CIP Safety. Tested against real Allen-Bradley ControlLogix and CompactLogix PLCs as well as 1734 distributed safety I/O modules.

The library is split into independent static libraries so you can link only the parts you need: bring in `ethernetip_cip` if you just want a CIP message router, add `ethernetip_device` for I/O assemblies, layer on `ethernetip_safety` if you need a SIL-3-style safety connection, or use `ethernetip_logix` for symbolic tag access against a real PLC.

This is a C++20 port of [EthernetIPSharp](../EthernetIPSharp). All three ports (C#, Python, C++) share the same architecture and are wire-compatible.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
  - [Standard adapter (Generic Ethernet Module)](#standard-adapter-generic-ethernet-module)
  - [CIP Safety adapter](#cip-safety-adapter)
  - [Standard I/O scanner](#standard-io-scanner)
  - [CIP Safety scanner](#cip-safety-scanner)
  - [Logix tag client](#logix-tag-client)
  - [Logix tag server](#logix-tag-server)
- [Samples](#samples)
- [Building and testing](#building-and-testing)
- [Library reference](#library-reference)
- [CIP services supported](#cip-services-supported)
- [CIP Safety details](#cip-safety-details)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Features

**Standard EtherNet/IP**
- TCP encapsulation (port 44818) — `RegisterSession`, `SendRRData`, `SendUnitData`, `UnregisterSession`, `ListIdentity`, `ListServices`, `ListInterfaces`
- UDP I/O transport (port 2222) — Class 0 and Class 1 implicit messaging
- Forward Open / Large Forward Open / Forward Close with full parameter parsing
- Run/Idle header handling on Class 1 connections
- CIP Identity, Assembly, Connection Manager, TCP/IP Interface, and Ethernet Link objects pre-registered
- Cross-platform sockets (Winsock + BSD) abstracted by `TcpSocket` / `UdpSocket`

**CIP Safety (originator and target)**
- Base Format and Extended Format safety frames (short and long variants)
- Connection Parameter CRC (CPCRC) computation and validation
- Safety Network Segment parser/encoder
- Time Coordination (TCOO) message exchange and ping cycle
- Producer-rollover tracking so CRC-S5 stays valid across the 8.4 s 16-bit timestamp wrap window
- Safety Supervisor and Safety Validator CIP objects
- Configuration Identifier (SCCRC + SCTS) handling
- Interop-tested against Allen-Bradley ControlLogix as originator and 1734-IB8S as target

**Logix tag protocol**
- `Read Tag` (0x4C), `Write Tag` (0x4D), Fragmented variants (0x52/0x53), `Read Modify Write` (0x4E)
- `Multiple Service Packet` (0x0A) for batched explicit messages
- Tag browsing via `Get Instance Attribute List` (0x55) — paginated
- UDT template queries and structure read/write (auto-fragmented for >504-byte structs)
- `TagClient` for connecting to a real PLC and reading/writing tags by name
- Logix STRING handling (88-byte UDT: LEN(DINT) + DATA(SINT[82]))

**Diagnostics**
- Connection lifecycle callbacks on `ConnectionManager::on_connection_established` / `on_connection_removed`
- Per-frame send/receive counters
- Heavy in-source comments explaining wire formats and edge cases

---

## Architecture

The codebase is split into small, focused static libraries with one-way dependencies:

```
                         ┌────────────────────────┐
                         │ ethernetip_cip         │
                         │ (pure protocol)        │
                         └───────────┬────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
┌───────────▼──────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐
│ ethernetip_protocol  │  │ ethernetip_         │  │ ethernetip_logix    │
│ (TCP/UDP sockets)    │  │ connections         │  │ (tag client/server) │
└───────────┬──────────┘  │ (Forward Open/Close)│  └─────────────────────┘
            │             └──────────┬──────────┘
            └────────────┬───────────┘
                         │
              ┌──────────▼──────────┐
              │ ethernetip_device   │
              │ (VirtualDevice,     │
              │  AssemblyObject)    │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │ ethernetip_safety   │
              │ (SafetyDevice,      │
              │  CRCs, TCOO,        │
              │  validators)        │
              └─────────────────────┘
```

- **`ethernetip_cip`** — Pure CIP: paths + `build_path`, services, `CipDispatcher` + `CatchAllDispatcher`, encapsulation header, CPF, identity. No sockets.
- **`ethernetip_protocol`** — Sockets only: `EipAdapter` (Class-3-clean TCP listener), `IoEipAdapter` (subclass adding Sockaddr Info for Class 0/1 I/O), `EipScanner` + `ConnectedExplicit` (TCP client + Class 3 explicit messaging), `EipUdpTransport` (UDP I/O), typed encapsulation messages.
- **`ethernetip_connections`** — Forward Open/Close parsing and connection lifecycle, used by both adapter and scanner.
- **`ethernetip_device`** — `VirtualDevice` (uses `IoEipAdapter`) + `AssemblyObject`. Ties dispatcher + assemblies + I/O transport together.
- **`ethernetip_safety`** — `SafetyDevice` (extends `VirtualDevice` with safety framing), CRC routines (S1–S5), TCOO logic, Safety Supervisor/Validator objects, plus `SafetyScannerConnection` for the originator side.
- **`ethernetip_logix`** — `LogixDispatcher` (server side: serves tags), `TagClient` (client side: reads/writes tags on a real PLC), tag database with change events, UDT templates, `StructureValue` helper.

---

## Project layout

```
src/
  cip/              Core CIP protocol (no I/O dependencies)
  protocol/         TCP/UDP transport (adapter + scanner)
  connections/      Forward Open/Close, connection lifecycle
  device/           Virtual device composition (VirtualDevice, AssemblyObject)
  safety/           CIP Safety: framing, CRCs, TCOO, validators
  logix/            Logix tag client & server, UDT templates

samples/
  safety_adapter/             CIP Safety adapter — runs against a real PLC or compatible emulator
  echo_module/                Plain EtherNet/IP adapter compatible with Studio 5000 Generic Ethernet Module
  cip_echo_server/            Catch-all CIP server — logs any unhandled request (UCMM or Class 3)
  scanner_smoke/              Class 1 scanner + UCMM/Class 3 explicit smoke tests
  tag_client_smoke/           Logix tag reader/writer round-trip tests
  logix_host/                 Stand-alone Logix tag server (pycomm3-compatible)
  safety_scanner_1734/        CIP Safety originator targeting a 1734 safety I/O module
  safety_scanner_loopback/    Safety scanner ↔ safety adapter loopback test

tests/
  cip_tests/           CIP path parsing, MR codec, service registration
  connections_tests/   Forward Open parameter parsing
  protocol_tests/      Encapsulation, scanner ↔ adapter loopback
  device_tests/        Assembly + virtual-device wiring
  logix_tests/         Tag database, read/write, edge cases
  safety_tests/        CRC check values, frame codec round-trips, segment parser
```

---

## Quick start

### Standard adapter (Generic Ethernet Module)

```cpp
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/device/virtual_device.hpp"

using namespace ethernetip;

cip::IdentityInfo identity;
identity.vendor_id      = 0x0001;
identity.device_type    = 0x000C;    // Communications Adapter
identity.product_code   = 1;
identity.major_revision = 1;
identity.minor_revision = 0;
identity.serial_number  = 0xC0FFEE42;
identity.product_name   = "My Simulator";

device::VirtualDevice device(identity, "192.168.1.100", "MySim");

// Matches Studio 5000 "Generic Ethernet Module" with Comm Format = Data - DINT
auto& produced = device.add_assembly(100, 500, "T->O Input (125 DINTs)");
auto& consumed = device.add_assembly(102, 496, "O->T Output (124 DINTs)");
device.add_assembly(105, 10, "Configuration");

device.start();

// Update produced data — the PLC will see this in its Input tag
produced.write<int32_t>(0, 42);

// Read what the PLC sent us — its Output tag
int32_t plc_output_dint0 = consumed.read<int32_t>(0);
```

### CIP Safety adapter

```cpp
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/safety/safety_device.hpp"

using namespace ethernetip;

cip::IdentityInfo identity;
identity.vendor_id      = 1;
identity.device_type    = 0;
identity.product_code   = 26;
identity.major_revision = 1;
identity.minor_revision = 1;
identity.serial_number  = 0xC0FFEE42;
identity.product_name   = "My Safety Module";

// Safety Network Number (12 hex chars displayed BE, stored LE on the wire)
safety::SafetyNetworkNumber snn(
    std::array<uint8_t, 6>{0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D});

// Safety node address = your IP packed BE as uint32
uint32_t node_address = 0xC0A80154;   // 192.168.1.84

safety::SafetyDevice device(identity, "192.168.1.84", snn, node_address, "SafeTest");

// 1-byte safety data assemblies; config often overlaps one of the data instances
auto& safety_in  = device.add_assembly(  1, 1, "Safety Data In");
auto& safety_out = device.add_assembly(199, 1, "Safety Data Out");

device.start();
safety_in.write<uint8_t>(0, 0x42);
```

### Standard I/O scanner

```cpp
#include "ethernetip/protocol/eip_scanner.hpp"
#include "ethernetip/protocol/eip_udp_transport.hpp"

using namespace ethernetip;

protocol::EipScanner scanner;
scanner.connect("192.168.1.84");

protocol::EipUdpTransport udp;
udp.start(protocol::IpEndpoint{"0.0.0.0", protocol::EipUdpTransport::IoPort});

protocol::ForwardOpenConfig cfg;
cfg.consumed_assembly  = 102;
cfg.produced_assembly  = 100;
cfg.config_assembly    = 105;
cfg.consumed_size      = 496;
cfg.produced_size      = 500;
cfg.rpi                = 10'000;            // 10 ms
cfg.transport_class    = 1;                 // Class 1 cyclic
cfg.timeout_multiplier = 2;                 // x16

auto conn = scanner.forward_open(udp, cfg);
conn->on_data_received = [](std::span<const uint8_t> data) {
    std::printf("Got %zu bytes\n", data.size());
};
conn->write<int32_t>(0, 1234);                  // What target reads as input
int32_t received = conn->read<int32_t>(0);      // What target produced

conn->close();
```

### CIP Safety scanner

See `samples/safety_scanner_1734/main.cpp` for a worked example against a 1734-IB8S safety input module behind a 1734-ENT EtherNet/IP adapter. The originator side requires:

- Originator identity + Safety Network Number (UNID)
- Target identity (TUNID) — the SNN burned into the safety module
- Safety Configuration Identifier (SCCRC + SCTS) — proves you have the right config
- Electronic key for the target module
- Route prefix (e.g. backplane port + slot)
- Server and Client `SafetyForwardOpenConfig` — RPIs, ping interval multipliers, timeout multipliers

```cpp
auto conn = safety::SafetyScannerConnection::open(
    scanner, udp, server_config, client_config,
    orig_vendor, orig_serial,
    route_prefix, server_app_path, client_app_path);

std::array<uint8_t, 1> safe_state{0x00};
conn->set_output_data(safe_state);          // safe state output
conn->set_data_received_handler(
    [](std::span<const uint8_t> data) { /* ... */ });
```

### Logix tag client

```cpp
#include "ethernetip/logix/tag_client.hpp"
#include "ethernetip/logix/structure_value.hpp"

using ethernetip::logix::TagClient;
using ethernetip::logix::StructureValue;

TagClient client("192.168.1.96");
client.connect();

// Read & write simple atomic tags
int32_t rate = client.read<int32_t>("rate");
client.write<int32_t>("rate", 1500);

// Read a structured tag by template
auto tags = client.browse();
auto it = std::find_if(tags.begin(), tags.end(),
                        [](const auto& t) { return t.name == "MyUdt"; });
auto tmpl = client.read_template(it->type_code);

auto raw = client.read_struct_bytes("MyUdt");
StructureValue value(tmpl, std::move(raw));
std::printf("counter = %d\n", value.get<int32_t>("Counter"));

// Write a structure
StructureValue writer(tmpl);
writer.set_bool("enable", true);
writer.set<int32_t>("setpoint", 100);
client.write_struct("MyUdt", tmpl.structure_handle, 1, writer.raw_data());

client.disconnect();
```

### Logix tag server

```cpp
#include "ethernetip/cip/identity_info.hpp"
#include "ethernetip/logix/logix_dispatcher.hpp"
#include "ethernetip/logix/tag_database.hpp"
#include "ethernetip/protocol/eip_adapter.hpp"

using namespace ethernetip;

logix::TagDatabase tags;
tags.add_tag("rate",        logix::logix_data_types::Dint).write<int32_t>(0, 1500);
tags.add_tag("temperature", logix::logix_data_types::Real).write<float>(0, 72.5f);
tags.add_tag("counts",      logix::logix_data_types::Int, /*elements=*/100);

// React to client writes
tags.find_by_name("rate")->on_value_changed.push_back(
    [](auto& tag, auto&) { std::printf("rate = %d\n", tag.template read<int32_t>(0)); });

cip::IdentityInfo identity;
identity.product_name = "CppLogix Sim";

logix::LogixDispatcher dispatcher(tags, identity);
protocol::EipAdapter adapter(dispatcher, identity);
adapter.listen("0.0.0.0", 44818);
```

---

## Samples

Eight runnable executables under `samples/`. Each one has a header comment block listing usage and CLI options.

| Sample | Role | Safety | Brief |
|---|---|---|---|
| `safety_adapter` | Target | Yes | CIP Safety adapter. Two profiles (`test2`, `plc`) or fully custom via CLI |
| `echo_module` | Target | No | Plain EtherNet/IP adapter compatible with Studio 5000 Generic Ethernet Module |
| `cip_echo_server` | Target | No | Catch-all CIP server — logs any unhandled request and optionally returns N bytes of incremental data. Handles UCMM + Class 3 from Logix MSG instructions. |
| `logix_host` | Target | No | Stand-alone Logix tag server with preloaded tags. Compatible with pycomm3. |
| `scanner_smoke` | Scanner | No | Class 1 I/O scanner + UCMM/Class 3 explicit round-trip smoke tests |
| `tag_client_smoke` | Client | No | Logix tag reader/writer round-trip tests (browse, atomic, UDT) |
| `safety_scanner_1734` | Scanner | Yes | CIP Safety originator targeting a 1734 safety I/O module |
| `safety_scanner_loopback` | Scanner | Yes | Self-contained safety scanner ↔ safety adapter loopback test |

Run any sample after building:

```powershell
build\samples\<name>\Release\<name>.exe [args...]
```

Defaults are set up so `scanner_smoke` can talk to `echo_module` on the same machine (loopback) without any wiring:

```powershell
# Terminal 1
build\samples\echo_module\Release\echo_module.exe

# Terminal 2
build\samples\scanner_smoke\Release\scanner_smoke.exe 127.0.0.1
```

---

## Building and testing

### Windows (Visual Studio 2026)

```powershell
cmake -G "Visual Studio 18 2026" -B build
cmake --build build --config Release
ctest --test-dir build --build-config Release
```

For faster inner-loop builds, open a Developer PowerShell for VS 2026 and:

```powershell
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build
```

### Linux

```sh
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build
```

### Requirements

- C++20 compiler (MSVC 14.50+, Clang 14+, GCC 12+)
- CMake 3.20+
- No runtime dependencies; tests pull GoogleTest via `FetchContent`.

The test suite covers CIP path parsing, MR codec, encapsulation, scanner ↔ adapter loopback, tag read/write/browse, CRC check values, safety frame round-trips, and safety segment parsing.

---

## Library reference

### `ethernetip::cip`

| Type | What it is |
|---|---|
| `CipDispatcher` | Routes service requests through the class → instance → attribute tree. `on_unhandled` is a virtual catch-all hook called for every unmatched path. |
| `CatchAllDispatcher` | `CipDispatcher` subclass that routes every unmatched request through a single callback — `(const CatchAllRequest&) -> CatchAllReply`. Useful for echo servers / sniffers without subclassing. |
| `CipClass`, `CipInstance`, `CipAttribute` | CIP object model |
| `CipPath`, `build_path` | EPATH parser (logical + symbolic + electronic key segments) and helper for building logical EPATHs from class/instance/attribute/element fields. |
| `MrCodec` | Message Router request/response binary codec |
| `EncapsulationHeader` | 24-byte TCP framing |
| `CpfParser`, `CpfItem` | Common Packet Format |
| `IdentityInfo` | Strongly-typed device identity (vendor/serial/product/etc.) |
| `data_serializer` | Wire-format type IDs and (de)serialization (`write_uint`, `write_udint`, ...) |
| `CipStatus` | All general-status codes |

### `ethernetip::protocol`

| Type | What it is |
|---|---|
| `EipAdapter` | TCP listener (port 44818). Hosts a `CipDispatcher`. Class-3-clean by default (no Sockaddr Info on Forward Open replies); has a `connection_id_lookup` hook for SendUnitData OT→TO translation. |
| `IoEipAdapter` | `EipAdapter` subclass that attaches Sockaddr Info O→T / T→O items on Class 0/1 Forward Open replies and fires `on_connection_opened`. Used by `VirtualDevice`. |
| `EipScanner` | TCP client. `connect` + `send_explicit` (UCMM) + `open_explicit` (Class 3 connected explicit) + `forward_open` (Class 0/1 I/O) |
| `ConnectedExplicit` | Class 3 connected explicit messaging handle returned by `EipScanner::open_explicit()`. `send(svc, class, inst, attr, data)` runs over `SendUnitData`. |
| `EipUdpTransport` | UDP I/O transport (port 2222) — send + receive callbacks |
| `TcpSocket`, `UdpSocket` | Cross-platform socket abstractions (Winsock + BSD) |
| `ScannerConnection` | Active I/O connection from the scanner side |

### `ethernetip::connections`

| Type | What it is |
|---|---|
| `ConnectionManagerObject` | Implements the Connection Manager CIP class (handles Forward Open/Close) |
| `ForwardOpenRequest` | Binary parser for Forward Open / Large Forward Open |
| `IoConnection` | Per-connection state (CIDs, RPIs, safety state, timers) |
| `parse_connection_path` | Extracts assembly instances from a Forward Open path |
| `ISafetyConnectionHandler` | Interface ConnectionManager calls into for safety validation |

### `ethernetip::device`

| Type | What it is |
|---|---|
| `VirtualDevice` | Wires together adapter, UDP transport, dispatcher, and assemblies |
| `AssemblyObject` | CIP Assembly (0x04) with per-instance byte buffer |
| `AssemblyInstance` | Per-instance byte buffer with `add_data_changed_handler` callback and typed `read<T>` / `write<T>` |
| Identity, TCP-IP Interface, Ethernet Link objects | Standard CIP objects pre-registered |

### `ethernetip::safety`

| Type | What it is |
|---|---|
| `SafetyDevice` | Target-side safety adapter (extends `VirtualDevice`) |
| `SafetyScannerConnection` | Originator-side safety connection pair (server + client) |
| `frame_codec` | Safety frame encode/decode (Base + Extended, Short + Long) |
| `SafetyCrc` | All five CRCs (S1, S2, S3, S4, S5) with lookup tables |
| `cpcrc` | Connection Parameter CRC computation |
| `SafetyNetworkSegment` | Forward Open safety segment (0x50) parse/encode |
| `SafetySupervisorObject` | Safety Supervisor CIP class (0x39) |
| `SafetyValidatorObject` | Safety Validator CIP class (0x3A) |
| `ModeByte`, `SafetyNetworkNumber`, `UniqueNetworkId`, `SafetyConfigurationId` | Strongly-typed safety identifiers |
| `SafetyForwardOpenBuilder`, `SafetyForwardOpenConfig` | Originator-side Forward Open builder |

### `ethernetip::logix`

| Type | What it is |
|---|---|
| `LogixDispatcher` | Server side. Dispatches tag services + UDT template queries |
| `TagClient` | Client side. Connect to a real PLC and read/write tags. Auto-fragments large struct reads. |
| `TagDatabase`, `Tag` | In-memory tag store with `on_value_changed` callbacks |
| `logix_data_types` | Standard Logix atomic types (Dint, Real, Int, Sint, Lint, Lreal, Bool) |
| `StructureValue` | Helper for reading/writing UDT structures by member name |
| `TemplateObject`, `SymbolObject` | Template Read and `Get_Instance_Attribute_List` support |
| `MultiServiceHandler` | Multiple Service Packet batching |

---

## CIP services supported

| Service | Code | Description |
|---|---|---|
| Get Attribute All | 0x01 | Read all attributes |
| Set Attribute All | 0x02 | Write all attributes |
| Get Attribute List | 0x03 | Read selected attributes |
| Reset | 0x05 | Reset CIP object |
| Multiple Service Packet | 0x0A | Batch multiple requests in one frame |
| Get Attribute Single | 0x0E | Read one CIP attribute |
| Set Attribute Single | 0x10 | Write one CIP attribute |
| Read Tag | 0x4C | Read tag data (symbolic or instance ID) |
| Write Tag | 0x4D | Write tag data with type validation |
| Forward Close | 0x4E | Close I/O connection |
| Read Modify Write | 0x4E | Bit-level OR/AND mask modification |
| Read Tag Fragmented | 0x52 | Chunked read for large tags |
| Write Tag Fragmented | 0x53 | Chunked write for large tags |
| Forward Open | 0x54 | Establish I/O connection |
| Get Instance Attribute List | 0x55 | Browse tags / instances (paginated) |
| Large Forward Open | 0x5B | Forward Open with 32-bit connection size fields |

---

## CIP Safety details

CIP Safety is a SIL-3-capable layer on top of standard EtherNet/IP. This library implements both producer (target) and consumer (originator) roles. Wire-format details (frame layouts, CRC polynomials, timing constants) follow the published CIP Safety specification — refer to the spec for protocol-level documentation.

**A "safety connection" is a pair of two underlying connections** — server and client — one in each direction for full bidirectional safety. Each carries the producer's safety data plus its own time-coordination (TCOO) exchange.

**Connection establishment:**
- Originator computes the Connection Parameter CRC over the Forward Open fields and includes it in the safety segment
- Target validates CPCRC, TUNID, electronic key, and Safety Configuration Identifier before accepting
- Production starts immediately on Forward Open; outgoing frames stay in IDLE mode until the first TCOO arrives and time coordination is established

**Timestamp rollover:**
The 16-bit producer timestamp wraps every ~8.4 s of connection uptime. `SafetyScannerConnection` tracks separate rollover counts for the producer's incoming stream and its own outgoing stream so CRC-S5 validation stays correct across wraps.

**Safety ownership (work in progress):**
The full safety ownership state machine (Propose_TUNID / Apply_TUNID / Configure / Run / Idle transitions in the Safety Supervisor) is not yet implemented. The current target-side check is that the originator's SNN and the safety configuration signature (SCCRC + SCTS) must match what the target was commissioned with — connections are accepted if both match. Commissioning workflows (changing a target's owner or its config from the originator side) are not yet supported.

---

## Known limitations

- 10 ms RPI runs stably for hours on Linux and tuned Windows hosts. On stock Windows the scheduler tail can occasionally exceed 50 ms — disable NIC green-Ethernet features and pin the producer thread.
- No persistent storage — assembly contents and tag values are in-memory only.
- Originator-side connection bridging through multiple hops is not implemented.
- Safety reset / safety configuration apply services are wired in but not extensively interop-tested.

---

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.

```
Copyright 2026 Cristian Mori

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
