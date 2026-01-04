# Rust Rewrite TODO

This is the tracked TODO list for the Rust rewrite plan. Update statuses as work progresses.

## Phase 0: Contract Freeze

- [x] Capture CLI API contract (flags, defaults, behavior).
- [x] Capture HTTP server API contract (params, defaults, errors).
- [x] Capture output JSON schema and add golden example.
- [x] Document hosted-runner expectation matrix.
- [x] Commit contract doc as source of truth.

## Phase 1: Architecture + Windows Driver Integration

- [ ] Define Rust workspace layout and crate boundaries.
- [ ] Define platform abstraction layer for raw sockets/packet capture.
- [ ] Map Windows driver API usage and IOCTL/device interactions.
- [ ] Implement Rust wrapper for Windows driver and smoke tests.

## Phase 2: Core Traceroute Engine

- [ ] Implement traceroute scheduler and TTL loop.
- [ ] Implement concurrency model (serial/parallel behavior parity).
- [ ] Implement hop aggregation and stats (hop_count, reachable, RTTs).
- [ ] Port core unit tests for traceroute behavior and normalization.

## Phase 3: Protocol Drivers

- [ ] ICMP driver (Linux/Windows/macOS).
- [ ] UDP driver (Linux/Windows/macOS).
- [ ] TCP SYN driver (Linux/Windows/macOS).
- [ ] TCP SACK driver (Linux/Windows/macOS).
- [ ] TCP prefer_sack handling and fallback logic.
- [ ] Packet parsing/filters parity (BPF/cBPF equivalents).
- [ ] Protocol-specific unit tests (parser + integration tests).

## Phase 4: CLI + HTTP Server Parity

- [ ] CLI implementation with identical flags and JSON output.
- [ ] HTTP server implementation with identical endpoints and query parsing.
- [ ] Log levels and verbose behavior parity.
- [ ] Windows driver startup on CLI flag.

## Phase 5: E2E + CI

- [ ] Port e2e tests to Rust or keep Go harness calling Rust binaries.
- [ ] Encode hosted-runner expectations for OS/protocol/target combos.
- [ ] Ensure fake network tests run on Linux (router setup/teardown).
- [ ] Update CI workflows for Rust build/test/e2e on hosted runners.

## Phase 6: Completion Gate

- [ ] Run `cargo fmt` and unit tests locally.
- [ ] Run e2e locally on supported targets.
- [ ] Verify GitHub CI checks via GitHub MCP.
- [ ] Declare completion only after local + CI pass.
