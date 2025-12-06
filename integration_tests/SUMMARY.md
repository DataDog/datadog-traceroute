# Integration Tests Summary

## Overview

This directory contains comprehensive integration tests that use the `datadog-traceroute` library programmatically, similar to how it's integrated in the [datadog-agent](https://github.com/DataDog/datadog-agent/blob/b208e91261a7e4abc82c7320d6abe81a5daf0be8/pkg/networkpath/traceroute/runner/runner.go#L108-L149).

## Files Created

### 1. `library_test.go`
Main integration test file containing:

- **6 test functions** that mirror the CLI tests in `.github/workflows/test.yml`:
  - `TestLocalhostICMP` - ICMP traceroute to 127.0.0.1
  - `TestLocalhostUDP` - UDP traceroute to 127.0.0.1
  - `TestLocalhostTCP` - TCP SYN traceroute to 127.0.0.1
  - `TestPublicEndpointTCP` - TCP SYN traceroute to github.com:443
  - `TestPublicEndpointTCPSACK` - TCP SACK traceroute to github.com:443
  - `TestPublicEndpointTCPPreferSACK` - TCP prefer_sack traceroute to github.com:443

- **2 validation functions** that comprehensively validate results:
  - `validateLocalhostResults()` - Validates results for localhost tests
  - `validatePublicEndpointResults()` - Validates results for public endpoint tests

### 2. `doc.go`
Package documentation file that:
- Describes the purpose of the integration tests
- Provides usage instructions
- Notes the privilege requirements

### 3. `README.md`
Comprehensive documentation covering:
- How to run the tests (with and without specific test names)
- What each test validates
- Differences from CLI tests
- Troubleshooting guide
- How to add new tests

### 4. Updated `.github/workflows/test.yml`
Added new CI job `integration_tests` that:
- Runs on all three platforms (Linux, macOS, Windows)
- Executes each integration test individually
- Uses the same privilege escalation as CLI tests (`sudo` on Unix)

## Key Features

### Library Usage Pattern
The tests follow the same pattern as the datadog-agent:

```go
ctx := context.Background()
params := runner.TracerouteParams{
    Hostname:          "github.com",
    Port:              443,
    Protocol:          "tcp",
    MinTTL:            common.DefaultMinTTL,
    MaxTTL:            common.DefaultMaxTTL,
    Delay:             common.DefaultDelay,
    Timeout:           1000 * time.Millisecond,
    TCPMethod:         traceroute.TCPConfigSYN,
    WantV6:            false,
    ReverseDns:        false,
    TracerouteQueries: 3,
    E2eQueries:        10,
    UseWindowsDriver:  false,
}

results, err := runner.RunTraceroute(ctx, params)
```

### Comprehensive Validation
Each test validates:

1. **Error Handling**: No errors during execution
2. **Result Structure**: All expected fields populated
3. **Traceroute Runs**:
   - Correct number of runs (3)
   - Unique RunID for each run
   - Valid hop information (TTL, IP, RTT, reachability)
   - Source and destination correctness
4. **Hop Statistics**:
   - Average, min, max hop counts
   - Statistical consistency
5. **E2E Probe Results**:
   - Correct probe count (10)
   - Packet send/receive counts
   - Packet loss percentage
   - RTT statistics (avg, min, max)
   - Jitter calculation

### Platform-Specific Handling
- Detects Windows and checks for admin privileges
- Skips tests when privileges are insufficient
- Handles platform-specific driver requirements

## Comparison: CLI vs Library Tests

| Aspect | CLI Tests (existing) | Library Tests (new) |
|--------|---------------------|---------------------|
| **Execution** | Run compiled binary | Import and call library functions |
| **Validation** | Exit code only | Detailed result structure validation |
| **Data Access** | Stdout/stderr parsing | Direct access to data structures |
| **Usage Pattern** | End-user perspective | Developer/integration perspective |
| **Coverage** | Functional correctness | Functional + API contract validation |

## Test Matrix

| Test Name | Protocol | Method | Target | Port | Queries | E2E Probes |
|-----------|----------|--------|--------|------|---------|------------|
| TestLocalhostICMP | ICMP | - | 127.0.0.1 | - | 3 | 10 |
| TestLocalhostUDP | UDP | - | 127.0.0.1 | - | 3 | 10 |
| TestLocalhostTCP | TCP | SYN | 127.0.0.1 | - | 3 | 10 |
| TestPublicEndpointTCP | TCP | SYN | github.com | 443 | 3 | 10 |
| TestPublicEndpointTCPSACK | TCP | SACK | github.com | 443 | 3 | 10 |
| TestPublicEndpointTCPPreferSACK | TCP | prefer_sack | github.com | 443 | 3 | 10 |

## CI/CD Integration

The integration tests are now part of the CI pipeline via GitHub Actions:

```yaml
integration_tests:
  name: "Library Integration Tests"
  runs-on: ${{ matrix.os }}
  strategy:
    matrix:
      os: [ubuntu-latest, windows-latest, macos-latest]
```

Each test runs independently, making it easy to identify which specific test/platform combination fails.

## Running Tests Locally

```bash
# All integration tests
sudo go test -tags=integration -v ./integration_tests/

# Specific test
sudo go test -tags=integration -v ./integration_tests/ -run TestLocalhostICMP

# All localhost tests
sudo go test -tags=integration -v ./integration_tests/ -run TestLocalhost

# All public endpoint tests
sudo go test -tags=integration -v ./integration_tests/ -run TestPublicEndpoint
```

## Benefits

1. **API Validation**: Ensures the library API works correctly for downstream consumers
2. **Datadog-Agent Alignment**: Mirrors actual usage in the datadog-agent
3. **Detailed Assertions**: Validates data structure correctness, not just exit codes
4. **Regression Detection**: Catches breaking changes in the library interface
5. **Documentation**: Serves as working examples of library usage
6. **CI Coverage**: Automated validation across all platforms

## Future Enhancements

Potential additions to consider:

- Tests with IPv6 destinations
- Tests with reverse DNS enabled
- Tests with private hop filtering
- Tests with Windows driver enabled (Windows-specific)
- Performance/benchmark tests
- Tests with various timeout configurations
- Tests against more diverse network endpoints
- Network error condition tests

