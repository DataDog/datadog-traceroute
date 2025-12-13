// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build e2etest

package e2etests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
)

const (
	localhostTarget = "127.0.0.1"

	publicTarget = "github.com"
	publicPort   = 443

	fakeNetworkTarget = "198.51.100.2"

	// Number of traceroute runs to perform in e2e tests
	//JMWnumTraceroutes = 3
	numTraceroutes = 1

	// Number of E2E probes to perform in e2e tests
	//JMWnumE2eProbes = 10
	numE2eProbes = 1
)

var (
	// CLI binary state for reuse across tests
	cliBinaryPath         string
	cliBinaryOnce         sync.Once
	cliBinaryNeedsCleanup bool

	// HTTP server binary state for reuse across tests
	serverBinaryPath         string
	serverBinaryOnce         sync.Once
	serverBinaryNeedsCleanup bool

	// HTTP server process state for reuse across tests
	serverProcess     *exec.Cmd
	serverProcessOnce sync.Once
	serverAddr        = "127.0.0.1:3765"

	// Common test configurations used across CLI and HTTP server tests
	localhostTestConfigs = []testConfig{
		{
			hostname: localhostTarget,
			protocol: traceroute.ProtocolICMP,
		},
		{
			hostname: localhostTarget,
			protocol: traceroute.ProtocolUDP,
		},
		{
			hostname:  localhostTarget,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSYN,
		},
		{
			hostname:  localhostTarget,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSACK,
		},
		{
			hostname:  localhostTarget,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigPreferSACK,
		},
	}

	publicTargetTestConfigs = []testConfig{
		{
			hostname: publicTarget,
			port:     publicPort,
			protocol: traceroute.ProtocolICMP,
		},
		{
			hostname: publicTarget,
			port:     publicPort,
			protocol: traceroute.ProtocolUDP,
		},
		{
			hostname:  publicTarget,
			port:      publicPort,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSYN,
		},
		{
			hostname:  publicTarget,
			port:      publicPort,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSACK,
		},
		{
			hostname:  publicTarget,
			port:      publicPort,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigPreferSACK,
		},
	}

	fakeNetworkTestConfigs = []testConfig{
		{
			hostname: fakeNetworkTarget,
			protocol: traceroute.ProtocolICMP,
		},
		{
			hostname: fakeNetworkTarget,
			protocol: traceroute.ProtocolUDP,
		},
		{
			hostname:  fakeNetworkTarget,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSYN,
		},
		{
			hostname:  fakeNetworkTarget,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSACK,
		},
		{
			hostname:  fakeNetworkTarget,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigPreferSACK,
		},
	}
)

// isGitHubRunner returns true if running on GitHub Actions
func isGitHubRunner() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

// reachabilityKey defines the conditions for looking up test expectations on GitHub runners
type reachabilityKey struct {
	os        string
	hostname  string
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

// testExpectations defines what to expect from a test run
type testExpectations struct {
	destinationReachable bool
	intermediateHops     bool
	expectedError        string
}

// reachabilityMap defines test expectations for different combinations when running on GitHub
// The key combines: OS, hostname, protocol, and TCP method
var reachabilityMap = map[reachabilityKey]testExpectations{
	{"linux", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"linux", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"linux", fakeNetworkTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"linux", fakeNetworkTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true, expectedError: ""},

	{"darwin", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"darwin", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"darwin", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true, expectedError: ""},

	{"windows", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"windows", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"windows", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},
}

// TestMain provides package-level setup and teardown for all tests.
// This is necessary for cleaning up shared resources (binaries and processes)
// that are created via sync.Once and used across multiple tests.
func TestMain(m *testing.M) {
	// Run all tests
	exitCode := m.Run()

	// Cleanup: remove test-built binaries and stop processes
	// This runs after ALL tests complete, not after individual tests
	if cliBinaryNeedsCleanup && cliBinaryPath != "" {
		if err := os.Remove(cliBinaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to remove CLI binary %s: %v\n", cliBinaryPath, err)
		}
	}

	if serverBinaryNeedsCleanup && serverBinaryPath != "" {
		if err := os.Remove(serverBinaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to remove server binary %s: %v\n", serverBinaryPath, err)
		}
	}

	if serverProcess != nil && serverProcess.Process != nil {
		// Kill the server process. No need to Wait() since we're exiting immediately
		// and the OS will clean up the process.
		if err := serverProcess.Process.Kill(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to kill server process: %v\n", err)
		}
	}

	os.Exit(exitCode)
}

// testConfig holds configuration for running one test
type testConfig struct {
	hostname  string
	port      int
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

// expectDestinationReachable returns whether to expect the destination to be reachable for the specific testConfig
func (tc *testConfig) expectDestinationReachable(t *testing.T) bool {
	// Not running on GitHub runner, always expect reachable except for TCP SACK on Linux and Windows, and UDP to github.com
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				return false
			}
		}
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolUDP {
			return false
		}
		return true
	}

	// When running on GitHub runners look up in the reachability map
	expectations := tc.getGitHubExpectations(t)
	return expectations.destinationReachable
}

// expectIntermediateHops returns whether to expect intermediate hops for the specific testConfig
func (tc *testConfig) expectIntermediateHops(t *testing.T) bool {
	// Not on GitHub runner: expect intermediate hops for all OSes and protocols, except for localhost target and UDP to github.com
	if !isGitHubRunner() {
		if tc.hostname == localhostTarget {
			return false
		}
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolUDP {
			return false
		}
		return true
	}

	// When running on GitHub runners look up in the reachability map
	expectations := tc.getGitHubExpectations(t)
	return expectations.intermediateHops
}

// expectError returns the expected error message for this test configuration
// Returns empty string if no error is expected
func (tc *testConfig) expectError(t *testing.T) string {
	var expectedError string

	// Not on GitHub: TCP SACK fails on Linux and Windows with known error
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				expectedError = "SACK not supported for this target/source"
			}
		}
	} else {
		// When running on GitHub runners look up in the reachability map
		expectations := tc.getGitHubExpectations(t)
		expectedError = expectations.expectedError
	}

	return expectedError
}

// getGitHubExpectations returns the test expectations for GitHub runner environments
// Fails the test if the configuration is not found in the map
func (tc *testConfig) getGitHubExpectations(t *testing.T) testExpectations {
	key := reachabilityKey{
		os:        runtime.GOOS,
		hostname:  tc.hostname,
		protocol:  tc.protocol,
		tcpMethod: tc.tcpMethod,
	}

	expectations, found := reachabilityMap[key]
	if !found {
		t.Fatalf("Missing test configuration in reachabilityMap for: OS=%s, hostname=%s, protocol=%s, tcpMethod=%s",
			runtime.GOOS, tc.hostname, tc.protocol, tc.tcpMethod)
	}

	return expectations
}

// testName returns a test name combining protocol and TCP method
func (c testConfig) testName() string {
	name := string(c.protocol)
	if c.tcpMethod != "" {
		name += "_" + string(c.tcpMethod)
	}
	return name
}

// validateResults validates traceroute results
func validateResults(t *testing.T, results *result.Results, config testConfig) {
	t.Logf("Validating results with testConfig %+v expectDestinationReachable %v expectIntermediateHops=%v expectedError=%s",
		config, config.expectDestinationReachable(t), config.expectIntermediateHops(t), config.expectError(t))

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Logf("Failed to marshal results to JSON: %v", err)
	} else {
		t.Logf("Validating traceroute results:\n%s", string(jsonBytes))
	}

	// Validate basic parameters
	assert.Equal(t, strings.ToLower(string(config.protocol)), results.Protocol, "protocol should match")
	assert.NotNil(t, results.Source.PublicIP, "should have source public IP")
	assert.Equal(t, config.hostname, results.Destination.Hostname, "hostname should match")
	// Port validation: ICMP doesn't use ports (it's a network layer protocol),
	// so we only validate port for TCP and UDP protocols when port > 0
	if config.port > 0 && config.protocol != traceroute.ProtocolICMP {
		assert.Equal(t, config.port, results.Destination.Port, "port should match")
	}

	// Validate traceroute runs
	assert.Equal(t, numTraceroutes, len(results.Traceroute.Runs), "should have %d traceroute runs", numTraceroutes)

	// For public targets, traceroutes can be flaky, so we only require at least one run to reach the destination
	// For local targets, all runs should reach the destination
	isPublicTarget := config.hostname == publicTarget
	runsWithReachableDestination := 0

	for i, run := range results.Traceroute.Runs {
		// Validate source and destination
		assert.NotNil(t, run.Source.IPAddress, "run %d should have source IP", i)
		assert.NotNil(t, run.Destination.IPAddress, "run %d should have destination IP", i)
		if config.port > 0 && config.protocol != traceroute.ProtocolICMP {
			assert.Equal(t, uint16(config.port), run.Destination.Port, "run %d destination port should match", i)
		}

		assert.NotEmpty(t, run.Hops, "run %d should have at least one hop", i)

		if config.expectDestinationReachable(t) {
			// Validate that the last hop is the destination and is reachable
			lastHop := run.Hops[len(run.Hops)-1]

			// For public targets, allow some runs to not reach the destination due to network flakiness
			if isPublicTarget {
				if lastHop.Reachable {
					runsWithReachableDestination++
				} else {
					// Log but don't fail if destination is unreachable for a public target run
					t.Logf("run %d last hop not reachable (acceptable for public target)", i)
					continue // Skip further validation for this run
				}
			} else {
				// For local targets, all runs must reach the destination
				assert.True(t, lastHop.Reachable, "run %d last hop should be reachable", i)
			}

			assert.NotNil(t, lastHop.IPAddress, "run %d last hop should have an IP address", i)

			// On Windows, RTT for localhost target with destination reachable can be 0 due to the resolution of time.Now() being only ~0.5 ms
			if config.hostname != localhostTarget || runtime.GOOS != "windows" {
				assert.Greater(t, lastHop.RTT, 0.0, "run %d last hop should have positive RTT", i)
			}

			// Verify the last hop IP matches the run's destination IP
			assert.True(t, lastHop.IPAddress.Equal(run.Destination.IPAddress),
				"run %d last hop IP should match run destination IP", i)

			// If we expect intermediate hops, we need at least 2 reachable hops (1 intermediate + destination)
			// Otherwise, we just need at least 1 reachable hop (the destination)

			// Count reachable hops and hops with reverse DNS
			reachableCount := 0
			hopsWithReverseDnsCount := 0
			for j, hop := range run.Hops {
				assert.NotZero(t, hop.TTL, "run %d, hop %d should have a TTL", i, j)

				if hop.Reachable {
					reachableCount++
					assert.NotNil(t, hop.IPAddress, "run %d, hop %d should have an IP address if reachable", i, j)
					// On Windows, RTT for localhost target with destination reachable can be 0 due to the resolution of time.Now() being only ~0.5 ms
					if config.hostname != localhostTarget || runtime.GOOS != "windows" {
						assert.Greater(t, hop.RTT, 0.0, "run %d, hop %d should have positive RTT if reachable", i, j)
					}
				}

				// Count hops with valid reverse DNS strings
				if len(hop.ReverseDns) > 0 {
					hopsWithReverseDnsCount++
				}
			}

			minReachableHops := 1
			if config.expectIntermediateHops(t) {
				minReachableHops = 2
			}
			assert.GreaterOrEqual(t, reachableCount, minReachableHops, "run %d should have at least %d reachable hop(s)", i, minReachableHops)

			// For public targets, at least one hop should have reverse DNS data in successful runs
			if isPublicTarget {
				assert.GreaterOrEqual(t, hopsWithReverseDnsCount, 1,
					"run %d (public target with reachable destination) should have at least one hop with reverse DNS, got %d",
					i, hopsWithReverseDnsCount)
			}
		}
	}

	// For public targets, ensure at least one run reached the destination
	if config.expectDestinationReachable(t) && isPublicTarget {
		assert.GreaterOrEqual(t, runsWithReachableDestination, 1,
			"at least one run should reach the destination for public target, got %d out of %d",
			runsWithReachableDestination, len(results.Traceroute.Runs))
	}

	// Validate hop count stats
	assert.Greater(t, results.Traceroute.HopCount.Avg, 0.0, "average hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Min, 0, "min hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Max, 0, "max hop count should be positive")
	assert.GreaterOrEqual(t, results.Traceroute.HopCount.Max, results.Traceroute.HopCount.Min, "max hop count should be >= min")

	if config.expectDestinationReachable(t) {
		// Validate E2E probe results
		assert.NotEmpty(t, results.E2eProbe.RTTs, "should have E2E probe RTTs")
		assert.Equal(t, numE2eProbes, len(results.E2eProbe.RTTs), "should have %d E2E probes as requested", numE2eProbes)
		assert.Equal(t, numE2eProbes, results.E2eProbe.PacketsSent, "should have sent %d E2E packets", numE2eProbes)

		// Validate packet loss
		// On Windows, RTT for localhost target with destination reachable can be 0 due to the resolution of time.Now() being only ~0.5 ms
		if config.hostname != localhostTarget || runtime.GOOS != "windows" {
			if config.hostname == publicTarget {
				// The public target "github.com" should be available from Github runners, but since it is a real network traceroute there
				// can be some flakiness, so some packet loss is acceptable
				assert.LessOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(0.5), "packet loss should be <= 0.5 for public target")
			} else {
				assert.Equal(t, float32(0.0), results.E2eProbe.PacketLossPercentage, "packet loss should be == 0.0")
			}
		}

		// If we received any packets, validate RTT stats
		if results.E2eProbe.PacketsReceived > 0 {
			assert.Greater(t, results.E2eProbe.RTT.Avg, 0.0, "E2E average RTT should be positive")
			assert.Greater(t, results.E2eProbe.RTT.Min, 0.0, "E2E min RTT should be positive")
			assert.Greater(t, results.E2eProbe.RTT.Max, 0.0, "E2E max RTT should be positive")
			assert.GreaterOrEqual(t, results.E2eProbe.RTT.Max, results.E2eProbe.RTT.Min, "E2E max RTT should be >= min")

			// RTT should be reasonable
			assert.Less(t, results.E2eProbe.RTT.Avg, 5000.0, "E2E average RTT should be less than 5 seconds")
		}
	}
}
