# Integration Tests

This directory contains integration tests that use the datadog-traceroute library programmatically, similar to how it's used in the [datadog-agent](https://github.com/DataDog/datadog-agent/blob/main/pkg/networkpath/traceroute/runner/runner.go).

## Overview

The integration tests validate the library's functionality by:
- Running traceroutes using different protocols (ICMP, UDP, TCP)
- Testing different TCP methods (SYN, SACK, prefer_sack)
- Testing against localhost and public endpoints
- Validating the structure and correctness of returned results

## Running the Tests

### Prerequisites

1. **Administrative/Root Privileges**: These tests require elevated privileges to create raw sockets and send/receive network packets.

2. **Network Access**: Public endpoint tests require internet connectivity.

### Run All Integration Tests

```bash
# On Linux/macOS
sudo go test -tags=integration -v ./integration_tests/

# On Windows (run from an elevated PowerShell/CMD)
go test -tags=integration -v ./integration_tests/
```

### Run Specific Tests

```bash
# Test only localhost ICMP
sudo go test -tags=integration -v ./integration_tests/ -run TestLocalhostICMP

# Test only public endpoint TCP
sudo go test -tags=integration -v ./integration_tests/ -run TestPublicEndpointTCP

# Test all localhost tests
sudo go test -tags=integration -v ./integration_tests/ -run TestLocalhost

# Test all public endpoint tests
sudo go test -tags=integration -v ./integration_tests/ -run TestPublicEndpoint
```

## Test Coverage

### Localhost Tests

These tests verify basic functionality against localhost (127.0.0.1):

- **TestLocalhostICMP**: ICMP Echo traceroute to localhost
- **TestLocalhostUDP**: UDP traceroute to localhost
- **TestLocalhostTCP**: TCP SYN traceroute to localhost

### Public Endpoint Tests

These tests verify functionality against real internet endpoints (github.com):

- **TestPublicEndpointTCP**: TCP SYN traceroute to github.com:443
- **TestPublicEndpointTCPSACK**: TCP SACK traceroute to github.com:443
- **TestPublicEndpointTCPPreferSACK**: TCP prefer_sack traceroute to github.com:443

## What's Validated

Each test validates:

1. **No errors during execution**: The traceroute completes successfully
2. **Result structure**: All expected fields are populated
3. **Traceroute runs**: 
   - Correct number of runs (3 as configured)
   - Each run has a unique RunID
   - Hops are present and within TTL limits
   - Source and destination information is correct
4. **Hop information**:
   - TTL values are valid
   - Reachable hops have IP addresses and RTT values
   - RTT values are positive for reachable hops
5. **Hop count statistics**:
   - Average, min, and max hop counts are valid
   - Stats are consistent (max >= min)
6. **E2E probe results**:
   - Correct number of probes (10 as configured)
   - Packet counts and loss percentage are valid
   - RTT statistics are valid for received packets
   - Jitter is calculated

## Differences from CLI Tests

The CLI tests in `.github/workflows/test.yml` run the compiled binary as a subprocess, while these integration tests:

1. **Use the library directly**: Import and call the `runner.RunTraceroute()` function
2. **Validate result structures**: Check the actual data structures returned, not just exit codes
3. **Provide detailed assertions**: Validate specific fields and their relationships
4. **Match datadog-agent usage**: Follow the same patterns used in production by the datadog-agent

## Troubleshooting

### Permission Denied Errors

If you see errors like "permission denied" or "operation not permitted":
- Ensure you're running with `sudo` on Linux/macOS
- Ensure you're running from an elevated terminal on Windows

### Timeout Errors

If tests timeout or fail to connect:
- Check your internet connection (for public endpoint tests)
- Verify firewall settings aren't blocking ICMP/UDP/TCP packets
- Some networks may block certain types of traceroute packets

### Windows Driver Errors

On Windows, if you encounter driver-related errors:
- The tests default to not using the Windows driver (`UseWindowsDriver: false`)
- You can modify the tests to enable it if needed

## Adding New Tests

To add new integration tests:

1. Create a new test function following the pattern: `TestXXXX(t *testing.T)`
2. Set the build tag: `//go:build integration`
3. Configure `TracerouteParams` with your desired settings
4. Call `runner.RunTraceroute(ctx, params)`
5. Use the appropriate validation function or create a custom one
6. Add documentation to this README

## Integration with CI/CD

These tests can be integrated into CI/CD pipelines:

```yaml
- name: Run Integration Tests
  run: sudo go test -tags=integration -v ./integration_tests/
```

Note: Ensure the CI environment has the necessary privileges and network access.

