# Rust Rewrite TODO

This is the tracked TODO list for the Rust rewrite plan. Update statuses as work progresses.

## Phase 0: Contract Freeze

- [x] Capture CLI API contract (flags, defaults, behavior).
- [x] Capture HTTP server API contract (params, defaults, errors).
- [x] Capture output JSON schema and add golden example.
- [x] Document hosted-runner expectation matrix.
- [x] Commit contract doc as source of truth.

## Phase 1: Architecture + Windows Driver Integration

- [x] Define Rust workspace layout and crate boundaries.
- [x] Define platform abstraction layer for raw sockets/packet capture.
- [x] Map Windows driver API usage and IOCTL/device interactions.
- [x] Implement Rust wrapper for Windows driver and smoke tests (manual Windows-only test).

## Phase 2: Core Traceroute Engine

- [x] Implement traceroute scheduler and TTL loop.
- [x] Implement concurrency model (serial/parallel behavior parity).
- [x] Implement hop aggregation and stats (hop_count, reachable, RTTs).
- [x] Port core unit tests for traceroute behavior and normalization.

## Phase 3: Protocol Drivers

- [x] ICMP driver (Linux/Windows/macOS).
- [x] UDP driver (Linux/Windows/macOS).
- [x] TCP SYN driver (Linux/Windows/macOS).
- [x] TCP SACK driver (Linux/Windows/macOS).
- [x] TCP prefer_sack handling and fallback logic.
- [ ] Packet parsing/filters parity (BPF/cBPF equivalents).
  - [x] Port core frame parser helpers (IPv4/IPv6, ICMP info, TCP/UDP header helpers).
- [x] Protocol-specific unit tests (parser + integration tests).

## Phase 4: CLI + HTTP Server Parity

- [x] CLI implementation with identical flags and JSON output.
- [x] HTTP server implementation with identical endpoints and query parsing.
- [x] Log levels and verbose behavior parity.
- [x] Windows driver startup on CLI flag.

## Phase 5: E2E + CI

- [x] Port e2e tests to Rust or keep Go harness calling Rust binaries.
- [x] Encode hosted-runner expectations for OS/protocol/target combos.
- [x] Ensure fake network tests run on Linux (router setup/teardown).
- [x] Update CI workflows for Rust build/test/e2e on hosted runners.

## Phase 6: Completion Gate

- [ ] Run `cargo fmt` and unit tests locally.
- [ ] Run e2e locally on supported targets.
- [ ] Verify GitHub CI checks via GitHub MCP.
- [ ] Declare completion only after local + CI pass.
