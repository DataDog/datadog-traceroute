# Datadog Traceroute - Rust Rewrite Plan

## Overview

Rewrite the Go-based datadog-traceroute repository in Rust with full feature parity:
- **Protocols**: TCP (SYN, SACK), UDP, ICMP
- **Platforms**: Linux, macOS, Windows
- **Interfaces**: CLI + HTTP Server
- **Runtime**: Tokio async
- **Windows Driver**: FFI bindings to existing Datadog driver

---

## 1. Cargo Workspace Structure

```
datadog-traceroute-rs/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── traceroute-core/        # Core types, traits, errors
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs        # thiserror-based errors
│   │       ├── types.rs        # ProbeResponse, TracerouteParams
│   │       ├── traits.rs       # TracerouteDriver trait
│   │       ├── result.rs       # Results, TracerouteHop (serde)
│   │       └── execution/
│   │           ├── mod.rs
│   │           ├── parallel.rs # Parallel traceroute with tokio
│   │           └── serial.rs   # Serial traceroute
│   │
│   ├── traceroute-packets/     # Packet I/O abstraction
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── source.rs       # Source trait
│   │       ├── sink.rs         # Sink trait
│   │       ├── parser.rs       # FrameParser (etherparse)
│   │       ├── filters.rs      # BPF filters
│   │       └── platform/
│   │           ├── mod.rs
│   │           ├── linux.rs    # AF_PACKET source
│   │           ├── darwin.rs   # BPF device source
│   │           └── windows.rs  # Driver + raw socket
│   │
│   ├── traceroute-tcp/         # TCP SYN traceroute
│   ├── traceroute-udp/         # UDP traceroute
│   ├── traceroute-icmp/        # ICMP traceroute
│   ├── traceroute-sack/        # TCP SACK traceroute
│   ├── traceroute-server/      # HTTP REST API (axum)
│   ├── traceroute-cli/         # CLI binary (clap)
│   └── datadog-driver-sys/     # Windows driver FFI bindings
│
├── tests/                      # Integration tests
└── benches/                    # Benchmarks
```

---

## 2. Key Dependencies

| Go Dependency | Rust Equivalent |
|--------------|-----------------|
| `gopacket` | `pnet` (construction) + `etherparse` (parsing) |
| `cobra` | `clap` (derive) |
| `golang.org/x/net` | `socket2` + `libc` |
| `vishvananda/netlink` | `rtnetlink` |
| `go-cache` | `moka` (async TTL cache) |
| `backoff/v5` | `backoff` |
| `DataDog agent driver` | Custom FFI in `datadog-driver-sys` |

### Workspace Dependencies (Cargo.toml)

```toml
[workspace.dependencies]
tokio = { version = "1.40", features = ["full"] }
pnet = "0.35"
etherparse = "0.16"
socket2 = "0.5"
clap = { version = "4.5", features = ["derive"] }
axum = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
tracing = "0.1"
moka = { version = "0.12", features = ["future"] }
hickory-resolver = "0.25"
uuid = { version = "1.11", features = ["v4"] }
```

---

## 3. Core Traits

### TracerouteDriver (from `common/traceroute_types.go`)

```rust
#[async_trait]
pub trait TracerouteDriver: Send + Sync {
    fn get_driver_info(&self) -> TracerouteDriverInfo;
    async fn send_probe(&mut self, ttl: u8) -> Result<(), TracerouteError>;
    async fn receive_probe(&mut self, timeout: Duration) -> Result<Option<ProbeResponse>, TracerouteError>;
    async fn close(&mut self) -> Result<(), TracerouteError>;
}
```

### Source/Sink (from `packets/packet_source.go`, `packets/packet_sink.go`)

```rust
#[async_trait]
pub trait Source: Send + Sync {
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<()>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn set_packet_filter(&mut self, spec: PacketFilterSpec) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}

#[async_trait]
pub trait Sink: Send + Sync {
    async fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}
```

---

## 4. Implementation Phases

### Phase 1: Foundation
**Goal**: Core infrastructure + UDP traceroute on Linux

1. Set up workspace with all crate stubs
2. Implement `traceroute-core`:
   - Error types (`TracerouteError` with `thiserror`)
   - Core types (`ProbeResponse`, `TracerouteParams`, `TracerouteConfig`)
   - `TracerouteDriver` trait
   - Result types with serde serialization
3. Implement `traceroute-packets` (Linux):
   - `Source`/`Sink` traits
   - `AfPacketSource` using `libc::AF_PACKET`
   - `FrameParser` using `etherparse`
   - cBPF filter application
4. Implement `traceroute-udp`:
   - `UdpDriver` implementing `TracerouteDriver`
   - UDP packet construction with `pnet`
   - Serial execution

**Key files to reference**:
- `common/traceroute_types.go` - Core types
- `udp/udp_driver.go` - UDP driver pattern
- `packets/afpacket_source_linux.go` - AF_PACKET implementation

### Phase 2: TCP + Parallel Execution
**Goal**: TCP SYN traceroute with parallel mode

1. Implement `traceroute-tcp`:
   - TCP SYN packet construction
   - Paris traceroute mode (fixed packet ID)
   - `TcpDriver` with SYNACK/RST detection
2. Implement parallel execution:
   - `traceroute_parallel()` using `tokio::select!`
   - Sender/receiver tasks with channel coordination
3. TCP-specific BPF filters

**Key files to reference**:
- `tcp/tcp_driver.go` - TCP driver
- `tcp/tcpv4.go` - Packet construction
- `common/traceroute_parallel.go` - Parallel algorithm

### Phase 3: ICMP + SACK
**Goal**: Complete protocol coverage

1. Implement `traceroute-icmp`:
   - ICMP Echo request/reply
   - ICMPv4 and ICMPv6 support
2. Implement `traceroute-sack`:
   - TCP handshake sequence
   - SACK option parsing
   - Fallback to SYN when unsupported

**Key files to reference**:
- `icmp/icmp_driver.go` - ICMP driver
- `sack/sack_driver.go` - SACK implementation
- `sack/sack_packet.go` - SACK packet handling

### Phase 4: macOS Support
**Goal**: Cross-platform for macOS

1. Implement `BpfDevice`:
   - `/dev/bpfN` device selection
   - `BIOCIMMEDIATE`, `BIOCSETIF` ioctls
   - DLT_NULL vs DLT_EN10MB handling
2. macOS raw socket sink
3. Loopback interface detection

**Key files to reference**:
- `packets/bpfdevice_darwin.go` - BPF device
- `packets/sourcesink_darwin.go` - macOS factories

### Phase 5: Windows Support
**Goal**: Windows with driver option

1. Implement raw socket mode (non-driver):
   - `RawConn` using `windows` crate
   - IP_HDRINCL socket option
2. Implement driver FFI (`datadog-driver-sys`):
   - `SourceDriver` with IOCP
   - `SinkDriver` for transmission
   - Filter definition structures
3. Sequential socket fallback for TCP

**Key files to reference**:
- `packets/driver_source_windows.go` - Driver source
- `packets/driver_sink_windows.go` - Driver sink
- `tcp/seqsocket_windows.go` - Socket fallback

### Phase 6: CLI + HTTP Server
**Goal**: User interfaces

1. Implement `traceroute-cli`:
   - Clap argument parsing (mirror Go flags)
   - JSON output formatting
   - Logging with `tracing`
2. Implement `traceroute-server`:
   - Axum HTTP server
   - `GET /traceroute?target=&protocol=&port=`
3. Supporting features:
   - Public IP fetching (5 fallback URLs)
   - Reverse DNS with moka cache
   - TTL cache layer

**Key files to reference**:
- `cmd/root.go` - CLI flags
- `server/server.go` - HTTP endpoints
- `publicip/fetcher.go` - Public IP fetching

### Phase 7: Testing + Polish
**Goal**: Production readiness

1. Unit tests with `mockall` for traits
2. Integration tests (port from Go `e2etests/`)
3. Property-based tests with `proptest`
4. Documentation (rustdoc)
5. CI/CD with cross-compilation

---

## 5. Error Handling

Use `thiserror` for structured errors:

```rust
#[derive(Error, Debug)]
pub enum TracerouteError {
    #[error("Socket creation failed: {0}")]
    SocketCreation(#[source] std::io::Error),

    #[error("Read timeout exceeded")]
    ReadTimeout,

    #[error("Packet mismatch")]
    PacketMismatch,

    #[error("Driver not available")]
    DriverNotAvailable,
    // ...
}

impl TracerouteError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::ReadTimeout | Self::PacketMismatch)
    }
}
```

---

## 6. Platform Abstraction

Use conditional compilation:

```rust
// traceroute-packets/src/platform/mod.rs
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "windows")]
mod windows;

pub async fn new_source_sink(addr: IpAddr, use_driver: bool) -> Result<SourceSinkHandle> {
    #[cfg(target_os = "linux")]
    return linux::new_source_sink(addr).await;

    #[cfg(target_os = "macos")]
    return darwin::new_source_sink(addr).await;

    #[cfg(target_os = "windows")]
    return windows::new_source_sink(addr, use_driver).await;
}
```

---

## 7. CI/CD

### GitHub Actions

```yaml
# Test on all platforms
test:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
  steps:
    - cargo test --all-features
    - cargo clippy -- -D warnings
    - cargo fmt --check

# Release with cross-compilation
release:
  targets:
    - x86_64-unknown-linux-gnu
    - x86_64-unknown-linux-musl
    - aarch64-unknown-linux-gnu
    - x86_64-apple-darwin
    - aarch64-apple-darwin
    - x86_64-pc-windows-msvc
```

---

## 8. Critical Go Files to Reference

| Go File | Purpose | Rust Equivalent |
|---------|---------|-----------------|
| `common/traceroute_types.go` | Core interfaces | `traceroute-core/src/traits.rs` |
| `common/traceroute_parallel.go` | Parallel algorithm | `traceroute-core/src/execution/parallel.rs` |
| `common/traceroute_serial.go` | Serial algorithm | `traceroute-core/src/execution/serial.rs` |
| `packets/frame_parser.go` | Packet parsing | `traceroute-packets/src/parser.rs` |
| `packets/afpacket_source_linux.go` | Linux AF_PACKET | `traceroute-packets/src/platform/linux.rs` |
| `packets/bpfdevice_darwin.go` | macOS BPF | `traceroute-packets/src/platform/darwin.rs` |
| `packets/driver_source_windows.go` | Windows driver | `traceroute-packets/src/platform/windows.rs` |
| `tcp/tcp_driver.go` | TCP implementation | `traceroute-tcp/src/driver.rs` |
| `udp/udp_driver.go` | UDP implementation | `traceroute-udp/src/driver.rs` |
| `icmp/icmp_driver.go` | ICMP implementation | `traceroute-icmp/src/driver.rs` |
| `sack/sack_driver.go` | SACK implementation | `traceroute-sack/src/driver.rs` |
| `result/result.go` | Result structures | `traceroute-core/src/result.rs` |
| `cmd/root.go` | CLI definition | `traceroute-cli/src/main.rs` |
| `server/server.go` | HTTP server | `traceroute-server/src/lib.rs` |

---

## 9. Notes

- Start implementation in a new `rust/` directory or separate branch
- Maintain Go version during transition for comparison testing
- Use `cargo-nextest` for faster test execution
- Consider `criterion` for performance benchmarks comparing to Go
