# Windows Driver API Mapping (Rust Rewrite)

This document captures the Windows driver API usage, IOCTLs, and I/O behavior
observed in the Go implementation. It is the source of truth for the Rust
driver wrapper and packet source/sink ports.

## Driver Lifecycle

- `driver.Init()` is called once (guarded by `sync.Once`).
- `driver.Start()` is called for every traceroute run that needs the driver.
- Error messages must preserve Go prefixes:
  - `StartDriver failed to init driver: ...`
  - `StartDriver failed to start driver: ...`

## Handles

The driver is accessed via `driver.NewHandle(flags, driver.DataHandle, nil)`.

- Source (read): `flags = windows.FILE_FLAG_OVERLAPPED`
- Sink (write): `flags = 0`
- Handle type: `driver.Handle` (wraps Windows handle + `DeviceIoControl` helpers).

## IOCTLs + Filter Definitions

Packet filters are applied via `DeviceIoControl`:

- IOCTL: `driver.SetDataFilterIOCTL`
- Input buffer: `driver.FilterDefinition`
- Output buffer: `int64 id` (ignored by Go beyond success)

Filter construction uses `driver.FilterDefinition` fields:

- `FilterVersion = driver.Signature`
- `Size = driver.FilterDefinitionSize`
- `FilterLayer = driver.LayerTransport`
- `Af = windows.AF_INET | windows.AF_INET6`
- `InterfaceIndex = 0`
- `Direction = driver.DirectionInbound`
- `Protocol = windows.IPPROTO_ICMP | IPPROTO_ICMPV6 | IPPROTO_TCP`
- `LocalAddress` / `RemoteAddress` = `driver.FilterAddress`
- `LocalPort` / `RemotePort` set for TCP capture
- `Discard = 1` for the discard filter

### FilterAddress

`FilterAddress` is populated as follows:

- IPv4: `Af = windows.AF_INET`, `V4_address = addr.As4()`, `Mask = 0xffffffff`
- IPv6: `Af = windows.AF_INET6`, `V6_address = addr.As16()`, `Mask = 0xffffffffffffffff`

### Filter Sets

The Go implementation always installs base ICMP filters on setup:

- IPv4 ICMP inbound
- IPv6 ICMP inbound

Then it appends protocol-specific filters:

- TCP: capture + discard filter matching local/remote address + port.
- SYNACK: capture + discard filter matching remote address + port.
- UDP: no additional filters (ICMP-only).
- None: capture + discard for IPv4 and IPv6 (should not be used in practice).

## Source Driver (Read Path)

The source driver uses overlapped I/O + IOCP.

Setup:

- `readBufferCount = 800`
- Each `readbuffer` is 150 bytes with an `OVERLAPPED`.
- Create IOCP with `CreateIoCompletionPort`.
- For each buffer, call `ReadFile(handle, buf, NULL, &ol)`.

Read:

- `GetQueuedCompletionStatus(iocp, &bytesRead, &key, &ol, timeoutMs)`
- Timeout uses `getReadTimeout(deadline)` (Go), mapping `WAIT_TIMEOUT` to
  `ReceiveProbeNoPktError`.
- On success, data starts after `driver.FilterPacketHeaderSize`.
- After reading, re-issue `ReadFile` on the same buffer.

Close:

- `CancelIoEx`
- `CloseHandle(iocp)`
- `handle.Close()`
- `free` each buffer (C malloc/free in Go; Rust must pin allocations).

## Sink Driver (Write Path)

- `WriteFile(handle, buf, NULL, NULL)` sends packet bytes (IP-layer payload).
- Close just closes the handle.

## Rust Port Notes

- `driver.Handle` APIs must be recreated (or FFI bound) with:
  - `NewHandle(flags, DataHandle, nil)`
  - `DeviceIoControl`
  - `CancelIoEx`
  - `Close`
- `FilterDefinition` and `FilterAddress` layouts must match the driver ABI.
- Read buffers must remain valid across overlapped calls; use pinned memory
  (e.g., `Box<[u8; 150]>` + `OVERLAPPED`) and store them for driver lifetime.
