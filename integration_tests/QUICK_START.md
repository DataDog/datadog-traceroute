# Quick Start Guide

## Run All Tests

```bash
sudo go test -tags=integration -v ./integration_tests/
```

## Run Individual Test Categories

### Localhost Tests
```bash
# All localhost tests
sudo go test -tags=integration -v ./integration_tests/ -run "^TestLocalhost"

# Specific protocol
sudo go test -tags=integration -v ./integration_tests/ -run "^TestLocalhostICMP$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestLocalhostUDP$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestLocalhostTCP$"
```

### Public Endpoint Tests
```bash
# All public endpoint tests
sudo go test -tags=integration -v ./integration_tests/ -run "^TestPublicEndpoint"

# Specific TCP methods
sudo go test -tags=integration -v ./integration_tests/ -run "^TestPublicEndpointTCP$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestPublicEndpointTCPSACK$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestPublicEndpointTCPPreferSACK$"
```

### Error Handling Tests
```bash
# All error handling tests
sudo go test -tags=integration -v ./integration_tests/ -run "^Test.*Error|Invalid|Zero|Minimal|Reverse|High|Context"

# Specific tests
sudo go test -tags=integration -v ./integration_tests/ -run "^TestInvalidProtocol$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestInvalidHostname$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestZeroQueries$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestMinimalConfiguration$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestReverseDNSEnabled$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestHighTTL$"
sudo go test -tags=integration -v ./integration_tests/ -run "^TestContextCancellation$"
```

## Quick Test Summary

| Test Name | Purpose | Expected Duration |
|-----------|---------|------------------|
| **TestLocalhostICMP** | ICMP to localhost | < 5s |
| **TestLocalhostUDP** | UDP to localhost | < 5s |
| **TestLocalhostTCP** | TCP to localhost | < 5s |
| **TestPublicEndpointTCP** | TCP SYN to GitHub | ~15s |
| **TestPublicEndpointTCPSACK** | TCP SACK to GitHub | ~15s |
| **TestPublicEndpointTCPPreferSACK** | TCP prefer_sack to GitHub | ~15s |
| **TestInvalidProtocol** | Error handling for bad protocol | < 1s |
| **TestInvalidHostname** | Error handling for bad hostname | < 2s |
| **TestZeroQueries** | Edge case: no queries | < 1s |
| **TestMinimalConfiguration** | Minimal params | < 5s |
| **TestReverseDNSEnabled** | With reverse DNS | ~20s |
| **TestHighTTL** | High TTL value | ~20s |
| **TestContextCancellation** | Context cancellation | < 1s |

## Test Output Example

```bash
$ sudo go test -tags=integration -v ./integration_tests/ -run TestLocalhostICMP
=== RUN   TestLocalhostICMP
--- PASS: TestLocalhostICMP (2.34s)
PASS
ok      github.com/DataDog/datadog-traceroute/integration_tests 2.348s
```

## Troubleshooting

### Permission Denied
```bash
# Make sure you're using sudo (Linux/macOS)
sudo go test -tags=integration -v ./integration_tests/

# On Windows, run from elevated PowerShell/CMD
go test -tags=integration -v ./integration_tests/
```

### Test Timeout
```bash
# Increase timeout if needed
sudo go test -tags=integration -v -timeout 5m ./integration_tests/
```

### Skip Slow Tests
```bash
# Run only fast localhost tests
sudo go test -tags=integration -v ./integration_tests/ -run "^TestLocalhost" -short
```

### Verbose Output
```bash
# Even more verbose output
sudo go test -tags=integration -v -count=1 ./integration_tests/ -run TestLocalhostICMP
```

## Integration with CI

See `.github/workflows/test.yml` for CI configuration. The workflow runs all tests on:
- Ubuntu (latest)
- Windows (latest)
- macOS (latest)

