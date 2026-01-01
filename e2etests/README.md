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
- Protocols: UDP, TCP (SYN, SACK, prefer_sack)
- Purpose: Verify basic functionality in a controlled environment

### Public Target Tests
- Target: `github.com:443`
- Protocols: UDP, TCP (SYN, SACK, prefer_sack)
- Purpose: Validate real-world internet traceroutes

### Fake Network Tests
- Target: `198.51.100.2` (TEST-NET-2)
- Protocols: UDP, TCP (SYN, SACK, prefer_sack)
- Purpose: Validate functionality with a fake network configuration that should always be reachable with a valid intermediate hop.

## Running the Tests

### Prerequisites

1. **Administrative/Root Privileges**: (Linux and macOS) Required to create raw sockets and send/receive network packets.
NOTE: When running tests manually, use 'sudo' as specified in the example commands below on Linux/macOS, but not on Windows

2. **Network Access**: Public target tests require internet connectivity.

### Run E2E Tests

The following commands can be used to manually run tests as they are run in the CI pipeline (`.github/workflows/test.yml`).  When run manually the test code will, as necessary, build the CLI and server binaries and start the server before executing the tests.

```bash
# Unit tests
go test -tags=test -v ./...

# E2E Localhost CLI Tests
sudo go test -tags=e2etest -v ./e2etests/... -run TestLocalhostCLI

# E2E Public Target CLI Tests
sudo go test -tags=e2etest -v ./e2etests/... -run TestPublicTargetCLI

# E2E Fake Network CLI Tests (Linux only)
sudo bash testutils/router_setup.sh
sudo go test -tags=e2etest -v ./e2etests/... -run TestFakeNetworkCLI
sudo bash testutils/router_teardown.sh

# E2E Localhost HTTP Server Tests
sudo go test -tags=e2etest -v ./e2etests/... -run TestLocalhostHTTPServer

# E2E Public Target HTTP Server Tests
sudo go test -tags=e2etest -v ./e2etests/... -run TestPublicTargetHTTPServer

# E2E Fake Network HTTP Server Tests (Linux only)
sudo bash testutils/router_setup.sh
sudo go test -tags=e2etest -v ./e2etests/... -run TestFakeNetworkHTTPServer
sudo bash testutils/router_teardown.sh
```

Following are more examples of running tests.

```bash
# All E2E tests
sudo go test -tags=e2etest -v ./e2etests/

# Specific CLI test
sudo go test -tags=e2etest -v ./e2etests/ -run TestLocalhostCLI/UDP

# Specific HTTP server test
sudo go test -tags=e2etest -v ./e2etests/ -run TestPublicTargetHTTPServer/TCP_syn

# Specific protocol across all targets
sudo go test -tags=e2etest -v ./e2etests/ -run UDP
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
- Port matches the requested port

### 3. Traceroute Runs
- Correct number of runs (3 by default)
- Each run has source and destination IP addresses
- Destination port matches
- Each run has at least one hop

### 4. Destination Reachability (when expected)
- Last hop is marked as reachable
- Last hop has a valid IP address
- Last hop RTT is positive (except Windows localhost due to timer resolution)
- Last hop IP matches the run's destination IP
- For public targets, allows some runs to fail due to network flakiness (requires at least 1 successful run)
- For Windows localhost, allows some runs to fail due to timer resolution limitations (requires at least 1 successful run)
- For local targets, all runs must reach the destination

### 5. Hop Information
- Each hop has a non-zero TTL value (except for Windows localhost due to timer resolution)
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
- Packet loss percentage is reasonable (0.0% for localhost, ≤50% for public targets and Windows localhost)
- When packets are received:
  - Average RTT is positive and < 5 seconds
  - Min RTT is positive
  - Max RTT is positive
  - Statistical consistency (max >= min)

### 8. Reverse DNS (for public targets)
- For the public target, at least one hop in successful runs has reverse DNS data populated

## Test Matrix

| Test Type    | Target       | Protocol | TCP Method   | Port | Queries | E2E Probes |
|--------------|--------------|----------|--------------|------|---------|------------|
| Localhost    | 127.0.0.1    | UDP      | -            | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | TCP      | SYN          | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | TCP      | SACK         | -    | 3       | 10         |
| Localhost    | 127.0.0.1    | TCP      | prefer_sack  | -    | 3       | 10         |
| Public       | github.com   | UDP      | -            | 443  | 3       | 10         |
| Public       | github.com   | TCP      | SYN          | 443  | 3       | 10         |
| Public       | github.com   | TCP      | SACK         | 443  | 3       | 10         |
| Public       | github.com   | TCP      | prefer_sack  | 443  | 3       | 10         |
| Fake Network | 198.51.100.2 | UDP      | -            | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | TCP      | SYN          | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | TCP      | SACK         | -    | 3       | 10         |
| Fake Network | 198.51.100.2 | TCP      | prefer_sack  | -    | 3       | 10         |

- Localhost and Public target tests are run on Linux, Windows, and macOS.  Fake Network tests are only run on Linux.
- Each configuration is tested with both the CLI binary and HTTP server API.

## CI/CD Integration

The tests are integrated into GitHub Actions CI pipeline (`.github/workflows/test.yml`):

- **Platforms**: Linux (Ubuntu), Windows, macOS

## Troubleshooting

- The output from stderr is included in test output for help in debugging.
- For more detailed debugging, there is a job in the CI pipeline, `ssh_debug_for_manual_tests` that allows you to connect to an active GitHub runner and manually run tests.  For instructions on how to use this job, see the comments in the job definition in `.github/workflows/test.yml`.

## Limitations

The e2e test suite encounters several limitations based on the test environment (Github runners) and different protocol/target/OS combinations.  The test suite makes use of a `testExpectations` map to define expected behaviors for each protocol/target/OS combination.

### Test Environment, Protocol and OS-Specific Limitations

#### Github Actions Network Restrictions
- Per https://docs.github.com/en/actions/concepts/runners/github-hosted-runners?supported-runners-and-hardware-resources=&utm_source=chatgpt.com#cloud-hosts-used-by-github-hosted-runners, inbound ICMP packets are blocked for all Azure virtual machines.  This affects Linux and Windows runners.  Inbound ICMP packets are not blocked on macOS runners because they are run as VMs on underlying Apple hardware.

#### UDP
- **Linux**: UDP works for localhost and fake network targets, but not public targets.
- **Windows and macOS**: UDP traceroutes do not work for localhost or public targets.

#### TCP SACK
- **Linux**: TCP SACK does not work with localhost or fake network targets.  The test validates that the expected error is returned.  TCP SACK generally works with the `github.com` public target used by the tests.
- **Windows**: TCP SACK does not work with localhost or publuc targets.  The test validates that the expected error is returned.
- **macOS**: TCP SACK does not work with localhost.  The test validates that the expected error is returned.  TCP SACK generally works with the `github.com` public target used by the tests, but can be flaky.  The test suite allows up to 5 attempts for macOS public target TCP SACK tests.

#### Intermediate Hops
- **Linux**: Only fake network targets consistently show intermediate hops on GitHub Actions runners.  Localhost has no intermediate hops because there is only one hop, and public targets don't capture intermediate hops because of GitHub Actions network restrictions.
- **Windows**: No intermediate hops are captured for the public target because of GitHub Actions network restrictions.
- **macOS**: The public target using TCP protocol shows intermediate hops.

#### Windows Driver
- The test suite does not currently validate functionality using the Windows Driver.  All Windows tests are run without the driver.

### Test Coverage Strategy

The test suite attempts to maximize coverage given the above limitations, by use of different target categories,
providing maximum coverage of cross-platform functionality across all supported protocols.

#### Localhost (`127.0.0.1`)
- **Purpose**: Validates basic protocol functionality in the most controlled environment

#### Public Target (`github.com:443`)
- **Purpose**: Validates real-world internet traceroutes with actual network conditions

#### Fake Network (`198.51.100.2`, TEST-NET-2)
- **Purpose**: Validates traceroute functionality with intermediate hops available in a controlled fake network environment.

### Alternative approaches to consider for improving coverage

- **GitHub Actions Self-Hosted Runners**: Using self-hosted runners would allow more control over network configurations, potentially enabling better UDP testing for public targets.  See: https://docs.github.com/en/actions/concepts/runners/self-hosted-runners
- **Support Datadog e2e test infrastructure**: Leverage Datadog's internal e2e testing infrastructure to run tests in a more controlled environment with fewer network restrictions.  See https://github.com/DataDog/test-infra-definitions

## Files

- **`cli_test.go`**: CLI tests
- **`server_test.go`**: HTTP server tests
- **`utils_test.go`**: Shared utilities and test configurations
- **`doc.go`**: Package-level documentation
- **`README.md`**: This file

