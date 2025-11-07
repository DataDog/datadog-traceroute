# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Datadog Traceroute is a Go library and CLI tool that produces traceroute results reflecting real traffic paths. It supports multiple protocols (ICMP, UDP, TCP SYN, TCP SACK) across Linux, macOS, and Windows platforms. The library is designed to be embedded in the Datadog Agent for network path monitoring.

## Development Commands

### Building
```bash
go build
```
This creates the `datadog-traceroute` binary.

### Running Tests
```bash
go test -tags=test -v ./...
```
Tests require the `-tags=test` build tag. The test suite runs on all three platforms (Linux, Windows, macOS) in CI.

### Running a Single Test
```bash
go test -tags=test -v ./path/to/package -run TestName
```

### Running the CLI
```bash
# After building
./datadog-traceroute [target]

# Or directly with go run
go run traceroute.go [target]

# Example with options
./datadog-traceroute -P tcp --tcp-method prefer_sack -p 443 example.com
```

### Dependency Management
```bash
go mod tidy
```

## Architecture

### Entry Point and Flow
1. **Main Entry**: `traceroute.go` → `cmd/root.go` (Cobra CLI)
2. **Runner Orchestration**: `runner/runner.go` coordinates traceroute execution
3. **Protocol Implementations**: Individual packages (`icmp/`, `udp/`, `tcp/`, `sack/`)
4. **Results**: `result/result.go` defines the output structure

### Package Structure

- **`cmd/`**: CLI command definitions using Cobra
- **`runner/`**: Main orchestration layer that:
  - Parses targets and resolves DNS
  - Runs multiple traceroute queries concurrently
  - Runs e2e probes (end-to-end connectivity tests)
  - Coordinates fallback logic (e.g., SACK → SYN)
  - Enriches results with reverse DNS
- **`common/`**: Shared constants, types, and utilities including:
  - Default values (ports, timeouts, TTLs)
  - Serial and parallel traceroute base implementations
  - Network utility functions
- **`icmp/`, `udp/`, `tcp/`, `sack/`**: Protocol-specific implementations
  - Each implements traceroute logic for its protocol
  - TCP has multiple methods: SYN, SACK, syn_socket (Windows-only)
- **`result/`**: Result structures and normalization logic
  - Defines JSON output format
  - Calculates statistics (hop counts, RTT, jitter, packet loss)
  - Handles reverse DNS enrichment
- **`packets/`**: Low-level packet parsing and BPF filters
- **`reversedns/`**: Reverse DNS lookup functionality
- **`log/`**: Logging utilities (verbose mode support)
- **`winconn/`**: Windows driver integration for raw socket access

### Key Concepts

#### Traceroute Queries vs E2E Probes
- **Traceroute queries** (`-q`): Full path discovery with hop-by-hop probing
- **E2E probes** (`-Q`): Direct probes to destination only (MinTTL = MaxTTL)
  - Provides RTT statistics, packet loss, and jitter
  - Default: 50 probes with calculated delays between them

#### TCP Methods and Fallback
The TCP implementation supports multiple methods:
- **syn**: Standard TCP SYN traceroute (uses raw sockets)
- **sack**: TCP Selective Acknowledgment traceroute (establishes full TCP connection)
- **prefer_sack**: Tries SACK first, falls back to SYN if remote doesn't support SACK
- **syn_socket**: Uses socket-based SYN for Windows clients without driver

SACK method is preferred for accuracy but requires handshake. The fallback logic is in `runner/runner.go:performTCPFallback()`.

#### Platform-Specific: Windows Driver
Windows support has two modes:
1. Without driver: Limited to specific methods (syn_socket for clients)
2. With driver (`--windows-driver`): Full raw socket access via `winconn` package

See `packets/driver_windows.go` for driver initialization.

### Results Structure
Results include:
- **Params**: Protocol, hostname, port used
- **Traceroute**: Array of runs, each with source, destination, and hops
- **E2eProbe**: RTT statistics (min/avg/max), packet loss %, jitter

Results are normalized via `result.Normalize()` which:
- Assigns UUIDs to runs
- Marks reachable hops
- Calculates hop count statistics
- Computes e2e probe metrics

## Testing Notes

- Tests use build tag `test`: Always include `-tags=test`
- Mock implementations use variable assignment pattern (e.g., `runTracerouteOnceFn` in `runner/runner.go:27`)
- Platform-specific tests have `_windows`, `_linux`, `_darwin` suffixes
- `testutils/` package provides shared test utilities

## Common Development Patterns

### Adding a New Protocol
1. Create package under root (e.g., `newproto/`)
2. Implement traceroute logic returning `*result.TracerouteRun`
3. Add case in `runner/runner.go:runTracerouteOnce()` switch statement
4. Update CLI help text and constants in `common/common.go`

### Modifying Result Structure
1. Update types in `result/result.go`
2. Update normalization logic in `result.Normalize()` if needed
3. Update tests in `result/result_test.go`
4. Consider backward compatibility for JSON output

## Publishing
Creating a release triggers goreleaser workflow:
1. Navigate to GitHub Releases page
2. Create new tag with `v` prefix (e.g., `v0.1.30`)
3. Generate release notes
4. Publish release → goreleaser adds artifacts automatically

See readme.md "Publishing Changes" section for details.
