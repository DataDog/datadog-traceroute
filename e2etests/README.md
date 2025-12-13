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
- Purpose: Validate funcctionality with a fake network configuration that should always be reachable with a valid intermediate hop.

## Running the Tests

### Prerequisites

1. **Administrative/Root Privileges**: (Linux and MacOS) Required to create raw sockets and send/receive network packets.
2. **Network Access**: Public target tests require internet connectivity.
3. **Go 1.x**: Compatible Go installation.

### Run All E2E Tests

```bash
# On Linux/macOS
sudo go test -tags=e2etest -v ./e2etests/

# On Windows (run from an elevated PowerShell/CMD)
go test -tags=e2etest -v ./e2etests/
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
sudo go test -tags=e2etest -v ./e2etests/ -run TestPublicTargetHTTPServer/TCP-SYN

# Specific protocol across all targets
sudo go test -tags=e2etest -v ./e2etests/ -run ICMP
```

### Adjust Test Timeout

```bash
# Increase timeout for slow networks (default is 10 minutes)
sudo go test -tags=e2etest -v -timeout 15m ./e2etests/
```

## Test Validation

Each test performs comprehensive validation:

### 1. Error Handling
- Verifies no unexpected errors during execution
- For error tests, validates expected error messages are present

### 2. Result Structure
- All expected fields are populated
- Source and destination information is correct
- Protocol-specific fields are valid

### 3. Traceroute Runs
- Correct number of runs (3 by default)
- Each run has a unique RunID
- Hops are present and within TTL limits (1-30)
- Valid hop information (TTL, IP, RTT, reachability)

### 4. Hop Information
- TTL values are in valid range
- Reachable hops have IP addresses
- RTT values are positive for reachable hops
- Multiple responses per hop are properly recorded

### 5. Hop Statistics
- Average, min, and max hop counts are calculated
- Statistical consistency (max >= avg >= min)
- Values match actual hop data

### 6. E2E Probe Results
- Correct number of probes (10 by default)
- Packet send/receive counts are valid
- Packet loss percentage is calculated correctly
- RTT statistics (avg, min, max) are present when packets received
- Jitter is calculated

### 7. Reverse DNS
- When enabled, validates hostname fields are populated
- Checks for both source and intermediate hop DNS results

### 8. Public IP Detection
- When enabled, validates source public IP is detected
- Verifies IP format and validity

## Test Matrix

| Test Type | Target | Protocol | TCP Method | Port | Queries | E2E Probes |
|-----------|--------|----------|------------|------|---------|------------|
| Localhost | 127.0.0.1 | ICMP | - | - | 3 | 10 |
| Localhost | 127.0.0.1 | UDP | - | - | 3 | 10 |
| Localhost | 127.0.0.1 | TCP | SYN | - | 3 | 10 |
| Localhost | 127.0.0.1 | TCP | SACK | - | 3 | 10 |
| Localhost | 127.0.0.1 | TCP | prefer_sack | - | 3 | 10 |
| Public | github.com | ICMP | - | 443 | 3 | 10 |
| Public | github.com | UDP | - | 443 | 3 | 10 |
| Public | github.com | TCP | SYN | 443 | 3 | 10 |
| Public | github.com | TCP | SACK | 443 | 3 | 10 |
| Public | github.com | TCP | prefer_sack | 443 | 3 | 10 |
| Fake Network | 198.51.100.2 | ICMP | - | - | 3 | 10 |
| Fake Network | 198.51.100.2 | UDP | - | - | 3 | 10 |
| Fake Network | 198.51.100.2 | TCP | SYN | - | 3 | 10 |
| Fake Network | 198.51.100.2 | TCP | SACK | - | 3 | 10 |
| Fake Network | 198.51.100.2 | TCP | prefer_sack | - | 3 | 10 |

Each configuration is tested with both the CLI binary and HTTP server API.

## CI/CD Integration

The tests are integrated into GitHub Actions CI pipeline (`.github/workflows/test.yml`):

- **Platforms**: Ubuntu, Windows, macOS
- **Execution**: Individual test functions run separately for better visibility
- **Privileges**: Uses `sudo` on Unix systems, elevated execution on Windows
- **Binary Reuse**: Pre-built binaries from build stage are used when available

Example CI job:

```yaml
cli_e2e_localhost:
  name: "CLI E2E Tests - Localhost"
  runs-on: ${{ matrix.os }}
  strategy:
    matrix:
      os: [ubuntu-latest, windows-latest, macos-latest]
  steps:
    - name: Run Localhost ICMP Test
      run: go test -tags=e2etest -v ./e2etests/... -run TestLocalhostCLI/ICMP
```

## Troubleshooting

### Permission Denied Errors

```
Error: permission denied / operation not permitted
```

**Solution**: Ensure elevated privileges
- Linux/macOS: Use `sudo`
- Windows: Run from Administrator terminal

### Timeout Errors

```
Error: test timed out / context deadline exceeded
```

**Solution**: Check network connectivity or increase timeout
```bash
sudo go test -tags=e2etest -v -timeout 15m ./e2etests/
```

### Connection Refused (HTTP Server Tests)

```
Error: connection refused on 127.0.0.1:3765
```

**Solution**: The test will automatically start the server, but if it fails:
- Check if port 3765 is available
- Verify the server binary builds successfully
- Check firewall settings

### Flaky Public Target Tests

Public endpoint tests may occasionally fail due to:
- Network congestion
- Firewall interference
- Route changes

**Solution**: Re-run the specific failing test or adjust timeout values.

### Binary Build Failures

```
Error: Failed to build datadog-traceroute
```

**Solution**: Ensure clean build environment
```bash
# Clean and rebuild
go clean
go build .
go build ./cmd/traceroute-server
```

## Test Development

### Adding New Tests

1. **Add test configuration** to `e2etestutil.go`:
```go
myTestConfigs := []testConfig{
    {
        hostname: "example.com",
        port:     80,
        protocol: traceroute.ProtocolTCP,
        tcpMethod: traceroute.TCPConfigSYN,
    },
}
```

2. **Add test function** to appropriate test file:
```go
func TestMyNewTest(t *testing.T) {
    for _, config := range myTestConfigs {
        t.Run(config.testName(), func(t *testing.T) {
            testCLI(t, config)  // or testHTTPServer(t, config)
        })
    }
}
```

3. **Update this README** with new test documentation.

4. **Add CI job** to `.github/workflows/test.yml` if needed.

### Custom Validation

For tests requiring custom validation logic, create a custom `expectation` function:

```go
func (c testConfig) customValidation(t *testing.T) string {
    if c.hostname == "special-case.com" {
        return "expected-behavior"
    }
    return ""
}
```

## Files

- **`cli_test.go`**: CLI binary tests
- **`server_test.go`**: HTTP server API tests
- **`e2etestutil.go`**: Shared utilities and test configurations
- **`doc.go`**: Package-level documentation
- **`README.md`**: This file

## Best Practices

1. **Run locally before pushing**: Always run the full test suite locally before committing.
2. **Test new protocols/features**: Add corresponding e2e tests for new functionality.
3. **Keep tests fast**: Localhost tests should complete in < 5 seconds.
4. **Document expectations**: Update test configurations with clear expectations.
5. **Handle flaky tests**: Use appropriate timeouts and retries for network tests.

## Related Documentation

- Main project README: `../readme.md`
- CI/CD workflow: `../.github/workflows/test.yml`
- Server API documentation: `../server/README.md`
- Package documentation: Run `go doc ./e2etests`
