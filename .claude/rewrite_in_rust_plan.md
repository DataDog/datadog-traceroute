# Datadog Traceroute - Rust Rewrite Plan

## Overview

Rewrite the Go-based datadog-traceroute repository in Rust with full feature parity:
- **Protocols**: TCP (SYN, SACK), UDP, ICMP
- **Platforms**: Linux, macOS, Windows
- **Interfaces**: CLI + HTTP Server
- **Runtime**: Tokio async
- **Windows Driver**: FFI bindings to existing Datadog driver

### Key Requirements
1. **API Compatibility**: Preserve existing CLI flags and HTTP server API exactly as-is
2. **E2E Testing**: Comprehensive E2E tests for all protocols on all platforms in GitHub CI

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

### Phase 6: CLI + HTTP Server (API Compatibility Required)
**Goal**: User interfaces with exact API compatibility

1. Implement `traceroute-cli` (must match existing Go CLI exactly):
   - **Preserve all existing flags**:
     - `-P, --proto` (udp, tcp, icmp)
     - `-p, --port` (default: 33434)
     - `-q, --traceroute-queries` (default: 3)
     - `-m, --max-ttl` (default: 30)
     - `-v, --verbose`
     - `--tcp-method` (syn, sack, prefer_sack)
     - `--ipv6`
     - `--timeout`
     - `--reverse-dns`
     - `--source-public-ip`
     - `-Q, --e2e-queries` (default: 50)
     - `--windows-driver`
     - `--skip-private-hops`
   - JSON output format must be identical
   - Logging with `tracing`
2. Implement `traceroute-server` (must match existing API exactly):
   - Axum HTTP server on port 3765
   - `GET /traceroute?target=&protocol=&port=` - same query params
   - Same JSON response format
   - `-a, --addr` and `-l, --log-level` flags
3. Supporting features:
   - Public IP fetching (same 5 fallback URLs)
   - Reverse DNS with moka cache
   - TTL cache layer

**Key files to reference**:
- `cmd/root.go` - CLI flags (MUST match exactly)
- `server/server.go` - HTTP endpoints (MUST match exactly)
- `publicip/fetcher.go` - Public IP fetching

### Phase 7: E2E Testing + Polish
**Goal**: Comprehensive E2E tests for all protocols on all platforms

1. **Unit tests** with `mockall` for traits
2. **E2E tests for all protocols** (port and expand from Go `e2etests/`):
   - UDP traceroute tests (localhost + public targets)
   - TCP SYN traceroute tests
   - TCP SACK traceroute tests
   - ICMP traceroute tests
   - Server API tests
3. **Platform coverage** - all E2E tests run on:
   - Linux (ubuntu-latest)
   - macOS (macos-latest)
   - Windows (windows-latest)
4. Property-based tests with `proptest`
5. Documentation (rustdoc)
6. CI/CD with cross-compilation

**Key files to reference**:
- `e2etests/cli_test.go` - CLI E2E tests to port
- `e2etests/server_test.go` - Server E2E tests to port
- `.github/workflows/test.yml` - Existing CI configuration

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

### GitHub Actions - Test Workflow

```yaml
name: Test
on: [push, pull_request]

jobs:
  unit-tests:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all-features
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check

  e2e-tests:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        protocol: [udp, tcp, icmp]
        include:
          - os: ubuntu-latest
            protocol: sack
          - os: macos-latest
            protocol: sack
          - os: windows-latest
            protocol: sack
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build
        run: cargo build --release
      - name: E2E - Localhost (${{ matrix.protocol }})
        run: cargo test --test e2e_cli -- --protocol ${{ matrix.protocol }} localhost
      - name: E2E - Public Target (${{ matrix.protocol }})
        run: cargo test --test e2e_cli -- --protocol ${{ matrix.protocol }} public
      - name: E2E - Server API
        if: matrix.protocol == 'udp'
        run: cargo test --test e2e_server

  e2e-fake-network:
    runs-on: ubuntu-latest  # Linux only (uses network namespaces)
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: E2E - Fake Network (all protocols)
        run: sudo cargo test --test e2e_fake_network
```

### GitHub Actions - Release Workflow

```yaml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  release:
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-apple-darwin
            os: macos-latest
          - target: aarch64-apple-darwin
            os: macos-latest
          - target: x86_64-pc-windows-msvc
            os: windows-latest
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - run: cargo build --release --target ${{ matrix.target }}
      - uses: actions/upload-artifact@v4
        with:
          name: datadog-traceroute-${{ matrix.target }}
          path: target/${{ matrix.target }}/release/datadog-traceroute*
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
| `result/result.go` | Result structures (JSON format) | `traceroute-core/src/result.rs` |
| `cmd/root.go` | CLI flags (MUST MATCH) | `traceroute-cli/src/main.rs` |
| `server/server.go` | HTTP API (MUST MATCH) | `traceroute-server/src/lib.rs` |
| `e2etests/cli_test.go` | CLI E2E tests | `tests/e2e_cli.rs` |
| `e2etests/server_test.go` | Server E2E tests | `tests/e2e_server.rs` |
| `.github/workflows/test.yml` | CI configuration | `.github/workflows/test.yml` |

---

## 9. API Compatibility Testing

To ensure the Rust implementation is a drop-in replacement:

1. **CLI Flag Compatibility Tests**:
   - Parse same arguments as Go version
   - `--help` output should match structure
   - Invalid flag handling should match

2. **JSON Output Compatibility Tests**:
   - Compare JSON output structure field-by-field
   - Use JSON schema validation
   - Test all result fields: `protocol`, `source`, `destination`, `traceroute`, `e2e_probe`

3. **Server API Compatibility Tests**:
   - Same query parameters accepted
   - Same HTTP status codes
   - Same JSON response format
   - Same error responses

4. **Regression Testing**:
   - Run both Go and Rust versions against same targets
   - Compare JSON outputs (ignoring timing-sensitive fields like RTT values)
   - Ensure same hop detection behavior

---

## 10. Notes

- Start implementation in a new `rust/` directory or separate branch
- Maintain Go version during transition for comparison testing
- Use `cargo-nextest` for faster test execution
- Consider `criterion` for performance benchmarks comparing to Go
- Run Go and Rust E2E tests in parallel during transition to catch regressions
