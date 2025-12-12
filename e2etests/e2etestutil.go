// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build e2etest

package e2etests

import (
	"encoding/json"
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

	// JMW fakeNetworkTarget --> fakeNetworkDestination? OR fakeNetworkTarget?
	fakeNetworkTarget = "198.51.100.2"
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

// TestMain runs before all tests and cleans up after all tests complete
func TestMain(m *testing.M) {
	// Run all tests
	exitCode := m.Run()

	// Cleanup binaries if they were built
	cleanupCLIBinary()
	cleanupServerBinary()
	cleanupServerProcess()

	// Exit with the test result code
	os.Exit(exitCode)
}

// testConfig holds configuration for running traceroute tests
type testConfig struct {
	hostname  string
	port      int
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

// expectDestinationReachable returns whether to expect the destination to be reachable
// based on the target, protocol, OS, and whether running on GitHub Actions
func (tc *testConfig) expectDestinationReachable(t *testing.T) bool {
	//JMWt.Helper()

	// Not running on GitHub runner, always reachable except for TCP SACK on Linux and Windows, and UDP to github.com
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

// expectIntermediateHops returns whether to expect intermediate hops based on
// the target, protocol, OS, and whether running on GitHub Actions
func (tc *testConfig) expectIntermediateHops(t *testing.T) bool {
	//JMWt.Helper()

	// Not on GitHub runner: expect intermediate hops for all OSes and protocols, except for localhost target
	if !isGitHubRunner() {
		if tc.hostname == localhostTarget {
			return false
		}
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolUDP {
			return false
		}
		return true
	}

	// On GitHub: look up in the reachability map
	expectations := tc.getGitHubExpectations(t)
	return expectations.intermediateHops
}

// expectError returns the expected error message for this test configuration
// Returns empty string if no error is expected
func (tc *testConfig) expectError(t *testing.T) string {
	//JMWt.Helper()

	var expectedError string

	// Not on GitHub: TCP SACK fails on Linux and Windows with known error
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				expectedError = "SACK not supported for this target/source"
			}
		}
	} else {
		// On GitHub: look up in the reachability map
		expectations := tc.getGitHubExpectations(t)
		expectedError = expectations.expectedError
	}

	//JMWRMt.Logf("expectError: config={hostname=%s, protocol=%s, tcpMethod=%s}, onGitHub=%v, OS=%s, expectedError=%q", tc.hostname, tc.protocol, tc.tcpMethod, isGitHubRunner(), runtime.GOOS, expectedError)

	return expectedError
}

// getGitHubExpectations returns the test expectations for GitHub runner environments
// Fails the test if the configuration is not found in the map
func (tc *testConfig) getGitHubExpectations(t *testing.T) testExpectations {
	//JMWt.Helper()

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

	//JMWRMt.Logf("getGitHubExpectations: key={OS=%s, hostname=%s, protocol=%s, tcpMethod=%s}, expectations={destinationReachable=%v, intermediateHops=%v, expectedError=%q}", key.os, key.hostname, key.protocol, key.tcpMethod, expectations.destinationReachable, expectations.intermediateHops, expectations.expectedError)

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
	t.Helper()

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
	assert.Equal(t, config.hostname, results.Destination.Hostname, "hostname should match")
	// Port validation: ICMP doesn't use ports (it's a network layer protocol),
	// so we only validate port for TCP and UDP protocols when port > 0
	if config.port > 0 && config.protocol != traceroute.ProtocolICMP {
		assert.Equal(t, config.port, results.Destination.Port, "port should match")
	}

	// Validate traceroute runs
	assert.Equal(t, 3, len(results.Traceroute.Runs), "should have 3 traceroute runs")

	for i, run := range results.Traceroute.Runs {
		// Validate source and destination
		assert.NotNil(t, run.Source.IPAddress, "run %d should have source IP", i)
		assert.NotNil(t, run.Destination.IPAddress, "run %d should have destination IP", i)
		if config.port > 0 && config.protocol != traceroute.ProtocolICMP {
			assert.Equal(t, uint16(config.port), run.Destination.Port, "run %d destination port should match", i)
		}

		assert.NotEmpty(t, run.Hops, "run %d should have at least one hop", i)

		// Validate that the last hop is the destination and is reachable (if we expect it to be)
		if config.expectDestinationReachable(t) {
			lastHop := run.Hops[len(run.Hops)-1]
			assert.True(t, lastHop.Reachable, "run %d last hop should be reachable", i)
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

			// Count reachable hops
			reachableCount := 0
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
			}

			minReachableHops := 1
			if config.expectIntermediateHops(t) {
				minReachableHops = 2
			}
			assert.GreaterOrEqual(t, reachableCount, minReachableHops, "run %d should have at least %d reachable hop(s)", i, minReachableHops)
		}
	}

	// Validate hop count stats
	assert.Greater(t, results.Traceroute.HopCount.Avg, 0.0, "average hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Min, 0, "min hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Max, 0, "max hop count should be positive")
	assert.GreaterOrEqual(t, results.Traceroute.HopCount.Max, results.Traceroute.HopCount.Min, "max hop count should be >= min")

	if config.expectDestinationReachable(t) {
		// Validate E2E probe results
		assert.NotEmpty(t, results.E2eProbe.RTTs, "should have E2E probe RTTs")
		assert.Equal(t, 10, len(results.E2eProbe.RTTs), "should have 10 E2E probes as requested")
		assert.Equal(t, 10, results.E2eProbe.PacketsSent, "should have sent 10 E2E packets")

		// JMWTHU can we validate 0% packet loss or is that too flaky?
		// Validate packet loss
		//JMWassert.GreaterOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "packet loss should be >= 0")
		//JMWassert.LessOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(1.0), "packet loss should be <= 1.0")
		// On Windows, RTT for localhost target with destination reachable can be 0 due to the resolution of time.Now() being only ~0.5 ms
		if config.hostname != localhostTarget || runtime.GOOS != "windows" {
			assert.Equal(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "packet loss should be == 0.0")
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

	// JMW other checks?
}
