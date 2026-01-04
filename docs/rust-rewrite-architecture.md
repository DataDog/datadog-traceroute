# Rust Rewrite Architecture

This document defines the Rust workspace layout, platform abstractions, and Windows driver integration plan.
It is the reference for Phase 1 of the rewrite.

## Workspace Layout

Proposed Cargo workspace:

- `crates/common`: shared constants, types, helpers (ports of `common`).
- `crates/result`: JSON output types and normalization (ports of `result`).
- `crates/packets`: packet source/sink abstractions and filters.
- `crates/icmp`: ICMP traceroute driver.
- `crates/udp`: UDP traceroute driver.
- `crates/tcp`: TCP traceroute driver (SYN + SACK + prefer_sack).
- `crates/sack`: TCP SACK probe/parse helpers (if separate is still needed).
- `crates/publicip`: public IP fetcher.
- `crates/reversedns`: reverse DNS enrichment.
- `crates/traceroute`: core runner and orchestration (serial/parallel).
- `crates/server`: HTTP server.
- `crates/cli`: `datadog-traceroute` binary.
- `crates/testutils`: shared helpers for e2e tests.
- `crates/winconn`: Windows socket helpers (ports of `winconn`).

## Platform Abstractions

### Packet IO Traits

Define traits for packet IO that mirror the Go interfaces:

- `PacketSource`:
  - `read(&mut self, buf: &mut [u8]) -> io::Result<usize>`
  - `set_read_deadline(&mut self, deadline: Instant)`
- `PacketSink`:
  - `write_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()>`
- `SourceSinkHandle`:
  - `source: Box<dyn PacketSource>`
  - `sink: Box<dyn PacketSink>`
  - `must_close_port: bool`

### Packet Filters

Carry over `PacketFilterSpec` and `FilterType` into `crates/packets`.
Implement platform-specific filters:

- Linux: raw socket + cBPF/AF_PACKET (port of `packet_sink_linux.go`, `afpacket_source_linux.go`).
- macOS: BPF device via `/dev/bpf` (port of `bpfdev_darwin.go`).
- Windows:
  - Raw socket path (port of `rawconn_windows.go`).
  - Driver path (port of `driver_source_windows.go`, `driver_sink_windows.go`).

## Windows Driver Integration

The Rust implementation must preserve Windows driver integration as used by Go.
The existing integration is based on `github.com/DataDog/datadog-agent/pkg/network/driver`.

### Initialization

Port `packets/StartDriver()`:

- Call `driver.Init()` once (idempotent).
- Call `driver.Start()` before using driver handles.
- Errors must match Go behavior (`StartDriver failed to init driver`, `StartDriver failed to start driver`).

### Driver Handles

Port of driver handle usage:

- Source (read path): `driver.NewHandle(FILE_FLAG_OVERLAPPED, driver.DataHandle, nil)`.
- Sink (write path): `driver.NewHandle(0, driver.DataHandle, nil)`.

### Driver IOCTLs + Filters

Packet filters are set via:

- `driver.SetDataFilterIOCTL` with `driver.FilterDefinition`.

Filter definitions match the Go `windows_filters.go` behavior:

- Always install ICMP + ICMPv6 inbound filters for source driver setup.
- TCP filters: local/remote address + port.
- SYNACK filters: remote address + port.
- UDP: reuse ICMP filters only (no extra UDP filter).
- `FilterTypeNone`: capture all inbound IPv4/IPv6, plus discard filters.

### Source Driver Read Path

Port the overlapped I/O and IOCP strategy:

- Create IOCP (`CreateIoCompletionPort`) with `readBufferCount = 800`.
- Allocate `readbuffer` blocks of 150 bytes and initiate `ReadFile` on each.
- `Read` uses `GetQueuedCompletionStatus` with timeout derived from read deadline.
- On timeout, return `ReceiveProbeNoPktError`.
- After a read completes, re-submit `ReadFile` for the same buffer.

### Sink Driver Write Path

Port `WriteFile` to send packet bytes via driver handle.

### Error Handling Parity

- Timeouts must map to `ReceiveProbeNoPktError`.
- Packet filter setup errors must wrap with `failed to set filter` / `failed to create packet filters`.
- Close must cancel IO, close IOCP, close handle, free buffers.

### Windows Non-Raw Socket Path

Port `winconn` module:

- `NewConn()` uses `AF_INET`, `SOCK_STREAM`, `IPPROTO_IP`.
- Enable non-blocking socket (`FIONBIO`) and `TCP_FAIL_CONNECT_ON_ICMP_ERROR`.
- `SetTTL()` via `IP_TTL`.
- `GetHop()` uses `connect`, `WSAPoll`, and `TCP_ICMP_ERROR_INFO` to retrieve hop address/type/code.
- Polling errors and timeouts must preserve Go semantics.

## Notes

- Rust must preserve the dual-path Windows strategy: driver path for full packet capture and raw socket path when driver is disabled.
- The driver path is mandatory for Windows Server protocol parity.
