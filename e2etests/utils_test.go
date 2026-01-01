// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build e2etest

package e2etests

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	localhostTarget = "127.0.0.1"

	publicTarget = "github.com"
	publicPort   = 443

	fakeNetworkTarget = "198.51.100.2"

	numTraceroutes = 3
	numE2eProbes   = 10
)

var (
	sackNotSupported = "SACK not supported for this target/source"

	// common testConfigs used for both CLI and HTTP server tests
	localhostTestConfigs = []testConfig{
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
		{
			hostname: localhostTarget,
			protocol: traceroute.ProtocolICMP,
		},
	}

	publicTargetTestConfigs = []testConfig{
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
		{
			hostname: publicTarget,
			port:     publicPort,
			protocol: traceroute.ProtocolICMP,
		},
	}

	fakeNetworkTestConfigs = []testConfig{
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
		{
			hostname: fakeNetworkTarget,
			protocol: traceroute.ProtocolICMP,
		},
	}
)

// testConfig holds configuration for one test
type testConfig struct {
	hostname  string
	port      int
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

type expectationsKey struct {
	os        string
	hostname  string
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

// expectations defines expected results from a test run
type expectations struct {
	destinationReachable bool
	intermediateHops     bool
	expectedError        string
	maxAttempts          int // max attempts for flaky tests (1 = no retry).  Default is 1 if not set.
}

// testExpectations defines expectations for various test scenarios
var testExpectations = map[expectationsKey]expectations{
	{"linux", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: false},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: sackNotSupported},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false},
	{"linux", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false},

	{"linux", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: true, intermediateHops: false},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false},
	{"linux", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false}, // GitHub blocks ICMP Echo

	{"linux", fakeNetworkTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: true},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: true},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: sackNotSupported},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true},
	{"linux", fakeNetworkTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: true},

	{"darwin", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: sackNotSupported},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false},
	{"darwin", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false},

	{"darwin", publicTarget, traceroute.ProtocolUDP, ""}:                      {destinationReachable: false, intermediateHops: false},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}: {destinationReachable: true, intermediateHops: true},
	// use maxAttempts of 5 here because TCP SACK usually works on macOS but can sometimes fail
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: true, intermediateHops: true, maxAttempts: 5},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true},
	{"darwin", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false}, // GitHub blocks ICMP Echo

	{"windows", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: sackNotSupported},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false},
	{"windows", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false},

	{"windows", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: sackNotSupported},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false},
	{"windows", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false}, // GitHub blocks ICMP Echo
}

// TestMain provides package-level setup and teardown for all tests.
func TestMain(m *testing.M) {
	exitCode := m.Run()

	cleanupCLI()
	cleanupHTTPServer()

	os.Exit(exitCode)
}

// isGitHubRunner returns true if running on GitHub Actions
func isGitHubRunner() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

// expectDestinationReachable returns whether to expect the destination to be reachable for the specific testConfig
func (tc *testConfig) expectDestinationReachable(t *testing.T) bool {
	// When not running on GitHub runner, always expect destination to be reachable except for TCP SACK on Linux
	// and Windows, UDP to github.com, and ICMP to github.com (GitHub blocks ICMP Echo)
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				return false
			}
		}
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolUDP {
			return false
		}
		// ICMP to github.com - GitHub blocks ICMP Echo
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolICMP {
			return false
		}
		// UDP to localhost on darwin doesn't reach destination
		if tc.hostname == localhostTarget && tc.protocol == traceroute.ProtocolUDP && runtime.GOOS == "darwin" {
			return false
		}
		return true
	}

	expectations := tc.getExpectations(t)
	return expectations.destinationReachable
}

// expectIntermediateHops returns whether to expect intermediate hops for the specific testConfig
func (tc *testConfig) expectIntermediateHops(t *testing.T) bool {
	// When not running on GitHub runner, always expect intermediate hops, except for localhost target and UDP/ICMP to github.com
	if !isGitHubRunner() {
		if tc.hostname == localhostTarget {
			return false
		}
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolUDP {
			return false
		}
		// ICMP to github.com - GitHub blocks ICMP Echo, so we don't expect intermediate hops
		if tc.hostname == publicTarget && publicTarget == "github.com" && tc.protocol == traceroute.ProtocolICMP {
			return false
		}
		return true
	}

	expectations := tc.getExpectations(t)
	return expectations.intermediateHops
}

// expectError returns the expected error message for this test configuration
// Returns empty string if no error is expected
func (tc *testConfig) expectError(t *testing.T) string {
	var expectedError string

	// When not running on GitHub runner, expect TCP SACK to fail on Linux and Windows
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				expectedError = "SACK not supported for this target/source"
			}
		}
		return expectedError
	}

	return tc.getExpectations(t).expectedError
}

// getMaxAttempts returns the maximum number of attempts for this test
// Returns 1 (no retry) if not specified
func (tc *testConfig) getMaxAttempts(t *testing.T) int {
	expectations := tc.getExpectations(t)
	if expectations.maxAttempts > 0 {
		return expectations.maxAttempts
	}

	return 1
}

// getExpectations returns the test expectations
// Fails the test if the configuration is not found in the map
func (tc *testConfig) getExpectations(t *testing.T) expectations {
	key := expectationsKey{
		os:        runtime.GOOS,
		hostname:  tc.hostname,
		protocol:  tc.protocol,
		tcpMethod: tc.tcpMethod,
	}

	expectations, found := testExpectations[key]
	if !found {
		t.Fatalf("Missing test configuration in testExpectations for: OS=%s, hostname=%s, protocol=%s, tcpMethod=%s",
			runtime.GOOS, tc.hostname, tc.protocol, tc.tcpMethod)
	}

	return expectations
}

// testName returns a test name combining protocol and TCP method
func (tc *testConfig) testName() string {
	name := string(tc.protocol)
	if tc.tcpMethod != "" {
		name += "_" + string(tc.tcpMethod)
	}
	return name
}

func validateResults(t *testing.T, buf []byte, config testConfig) {
	t.Logf("validating results with testConfig %+v expectDestinationReachable %v expectIntermediateHops=%v expectedError=%s",
		config, config.expectDestinationReachable(t), config.expectIntermediateHops(t), config.expectError(t))

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, buf, "", "  "); err != nil {
		t.Logf("failed to pretty print JSON: %v", err)
	} else {
		t.Logf("validating traceroute results:\n%s", prettyJSON.String())
	}

	var results result.Results
	err := json.Unmarshal(buf, &results)
	require.NoError(t, err, "Failed to unmarshal JSON results:\n%s", string(buf))

	// Validate basic parameters
	assert.Equal(t, strings.ToLower(string(config.protocol)), results.Protocol, "protocol should match")
	assert.NotNil(t, results.Source.PublicIP, "should have source public IP")
	assert.Equal(t, config.hostname, results.Destination.Hostname, "hostname should match")
	// Validate port for TCP and UDP protocols when port > 0
	if config.port > 0 {
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
		// Validate port for TCP and UDP protocols
		if config.port > 0 {
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
