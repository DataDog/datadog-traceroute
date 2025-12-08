# End-to-End Tests

This directory contains comprehensive end-to-end tests for the `datadog-traceroute` library and binaries. The tests validate functionality across different protocols, network conditions, and usage patterns.

## Test Structure

The e2e test suite includes two types of tests:

### 1. CLI Tests (`cli_test.go`)
Tests that execute the compiled `datadog-traceroute` CLI binary as a subprocess and validate JSON output.

### 2. HTTP Server Tests (`server_test.go`)
Tests that validate the HTTP server API (`datadog-traceroute-server`) by making REST API requests and validating JSON responses.

## Test Configurations

Each test type runs against three target categories:

### Localhost Tests
- Target: `127.0.0.1`
- Protocols: ICMP, UDP, TCP (SYN, SACK, prefer_sack)
- Purpose: Verify basic functionality in a controlled environment

### Public Target Tests
- Target: `github.com:443`
- Protocols: ICMP, UDP, TCP (SYN, SACK, prefer_sack)
- Purpose: Validate real-world internet traceroutes

### Fake Network Tests
- Target: `198.51.100.2` (TEST-NET-2)
- Protocols: ICMP, UDP, TCP (SYN, SACK, prefer_sack)
- Purpose: Validate functionality with a fake network configuration that should always be reachable with a valid intermediate hop.

## Running the Tests

### Prerequisites

1. **Administrative/Root Privileges**: (Linux and MacOS) Required to create raw sockets and send/receive network packets.
2. **Network Access**: Public target tests require internet connectivity.

### Run E2E Tests

```bash
# NOTE: When running tests manually, use 'sudo' as specified in the example commands below on Linux/MacOS, but not on Windows
```

```bash
# All E2E tests
sudo go test -tags=e2etest -v ./e2etests/
```

### Run Specific Test Categories

```bash
# CLI tests only
sudo go test -tags=e2etest -v ./e2etests/ -run CLI

# HTTP server tests only
sudo go test -tags=e2etest -v ./e2etests/ -run HTTPServer

# Localhost tests only (both CLI and server)
sudo go test -tags=e2etest -v ./e2etests/ -run Localhost

# Public target tests only (both CLI and server)
sudo go test -tags=e2etest -v ./e2etests/ -run PublicTarget

# Fake network tests only (both CLI and server)
sudo go test -tags=e2etest -v ./e2etests/ -run FakeNetwork
```

### Run Individual Tests

```bash
# Specific CLI test
sudo go test -tags=e2etest -v ./e2etests/ -run TestLocalhostCLI/ICMP

# Specific HTTP server test
sudo go test -tags=e2etest -v ./e2etests/ -run TestPublicTargetHTTPServer/TCP_syn

# Specific protocol across all targets
sudo go test -tags=e2etest -v ./e2etests/ -run ICMP
```

## Test Validation

Each test performs validation of the results returned by the CLI or HTTP server.  The validations include:

### 1. Error Handling
- Verifies no unexpected errors during execution
- For expected error tests, validates expected error message is present in stdout/stderr (CLI) or HTTP response body (server)

### 2. Basic Result Structure
- Protocol matches the requested protocol
- Source public IP is populated
- Destination hostname matches the target
- Port matches the requested port (for TCP/UDP only, not ICMP)

### 3. Traceroute Runs
- Correct number of runs (3 by default)
- Each run has source and destination IP addresses
- Destination port matches (for TCP/UDP only, not ICMP)
- Each run has at least one hop

### 4. Destination Reachability (when expected)
- Last hop is marked as reachable
- Last hop has a valid IP address
- Last hop RTT is positive (except Windows localhost due to timer resolution)
- Last hop IP matches the run's destination IP
- For public targets, allows some runs to fail due to network flakiness (requires at least 1 successful run)
- For local targets, all runs must reach the destination

### 5. Hop Information
- Each hop has a non-zero TTL value
- Reachable hops have IP addresses
- Reachable hops have positive RTT values (except Windows localhost due to timer resolution)
- Minimum number of reachable hops is validated (1 for localhost, 2+ for targets with intermediate hops)

### 6. Hop Count Statistics
- Average hop count is positive
- Min hop count is positive
- Max hop count is positive
- Statistical consistency (max >= min)

### 7. E2E Probe Results (when destination is reachable)
- RTT array is populated with correct number of entries (10 by default)
- Packets sent count equals requested number of probes
- Packet loss percentage is reasonable (0.0% for localhost, ≤50% for public targets)
- When packets are received:
  - Average RTT is positive and < 5 seconds
  - Min RTT is positive
  - Max RTT is positive
  - Statistical consistency (max >= min)

### 8. Reverse DNS (for public targets)
- When reverse DNS is enabled, at least one hop in successful runs has reverse DNS data populated

## Test Matrix

| Test Type    | Target       | Protocol | TCP Method   | Port | Queries | E2E Probes |
|--------------|--------------|----------|--------------|------|---------|------------|
| Localhost    | 127.0.0.1    | ICMP     | -            | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | UDP      | -            | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | TCP      | SYN          | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | TCP      | SACK         | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | TCP      | prefer_sack  | -    | 3       | 10         |
| Public       | github.com   | ICMP     | -            | 443  | 3       | 10         |
| Public       | github.com   | UDP      | -            | 443  | 3       | 10         |
| Public       | github.com   | TCP      | SYN          | 443  | 3       | 10         |
| Public       | github.com   | TCP      | SACK         | 443  | 3       | 10         |
| Public       | github.com   | TCP      | prefer_sack  | 443  | 3       | 10         |
| Fake Network | 198.51.100.2 | ICMP     | -            | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | UDP      | -            | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | TCP      | SYN          | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | TCP      | SACK         | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | TCP      | prefer_sack  | -    | 3       | 10         |
|--------------|--------------|----------|--------------|------|---------|------------|

Each configuration is tested with both the CLI binary and HTTP server API.

## CI/CD Integration

The tests are integrated into GitHub Actions CI pipeline (`.github/workflows/test.yml`):

- **Platforms**: Ubuntu, Windows, macOS

## Troubleshooting

- The output from stderr is included in test output for help in debugging.
- For more detailed debugging, there is a job in the CI pipeline, `ssh_debug_for_manual_tests` that allows you to connect to an active GitHub runner and manually run tests.  For instructions on how to use this job, see the comments in the job definition in `.github/workflows/test.yml`.

## Files

- **`cli_test.go`**: CLI tests
- **`server_test.go`**: HTTP server tests
- **`e2etestutil.go`**: Shared utilities and test configurations
- **`doc.go`**: Package-level documentation
- **`README.md`**: This file

