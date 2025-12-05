// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build integration

package integration_tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	publicEndpointHostname = "github.com"
	publicEndpointPort     = 443
	fakeNetworkHostname    = "198.51.100.2"
)

var (
	// CLI binary state for reuse across tests
	cliBinaryPath         string
	cliBinaryOnce         sync.Once
	cliBinaryNeedsCleanup bool
)

// TestMain runs before all tests and cleans up after all tests complete
func TestMain(m *testing.M) {
	// Run all tests
	exitCode := m.Run()

	// Cleanup CLI binary if it was built
	cleanupCLIBinary()

	// Exit with the test result code
	os.Exit(exitCode)
}

// testConfig holds configuration for running traceroute tests
type testConfig struct {
	hostname               string
	port                   int
	protocol               traceroute.Protocol
	tcpMethod              traceroute.TCPMethod
	expectIntermediateHops bool
}

// testName returns a test name combining protocol and TCP method
func (c testConfig) testName() string {
	name := string(c.protocol)
	if c.tcpMethod != "" {
		name += "_" + string(c.tcpMethod)
	}
	return name
}

var (
	ICMPProtocol = []testConfig{
		{protocol: traceroute.ProtocolICMP},
	}
	UDPProtocol = []testConfig{
		{protocol: traceroute.ProtocolUDP},
	}

	TCPSYNProtocol = []testConfig{
		{protocol: traceroute.ProtocolTCP, tcpMethod: traceroute.TCPConfigSYN},
	}

	TCPSACKProtocol = []testConfig{
		{protocol: traceroute.ProtocolTCP, tcpMethod: traceroute.TCPConfigSACK},
	}

	TCPPreferSACKProtocol = []testConfig{
		{protocol: traceroute.ProtocolTCP, tcpMethod: traceroute.TCPConfigPreferSACK},
	}

	// AllProtocolsExceptSACK defines all protocol tests except SACK
	AllProtocolsExceptSACK = []testConfig{
		{protocol: traceroute.ProtocolICMP},
		{protocol: traceroute.ProtocolUDP},
		{protocol: traceroute.ProtocolTCP, tcpMethod: traceroute.TCPConfigSYN},
		{protocol: traceroute.ProtocolTCP, tcpMethod: traceroute.TCPConfigPreferSACK},
	}
)

// testCommon runs a library traceroute test with the given configuration
func testCommon(t *testing.T, config testConfig) {
	t.Helper()

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          config.hostname,
		Port:              config.port,
		Protocol:          string(config.protocol),
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            common.DefaultMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           common.DefaultNetworkPathTimeout * time.Millisecond,
		TCPMethod:         config.tcpMethod,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "%s traceroute to %s should not fail", config.testName(), config.hostname)
	require.NotNil(t, results, "Results should not be nil")

	validateResults(t, results, config)
}

// TestLocalhost runs traceroute tests to localhost for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestLocalhost(t *testing.T) {
	for _, baseConfig := range AllProtocolsExceptSACK {
		t.Run(baseConfig.testName(), func(t *testing.T) {
			config := baseConfig
			config.hostname = "127.0.0.1"
			config.port = 0
			config.expectIntermediateHops = false
			testCommon(t, config)
		})
	}
}

// TestPublicEndpointICMP runs traceroute tests to a public endpoint for ICMP protocol
// In CI this will run on MacOS
func TestPublicEndpointICMP(t *testing.T) {
	for _, baseConfig := range ICMPProtocol {
		t.Run(baseConfig.testName(), func(t *testing.T) {
			config := baseConfig
			config.hostname = publicEndpointHostname
			config.port = publicEndpointPort
			config.expectIntermediateHops = false
			testCommon(t, config)
		})
	}
}

// TestPublicEndpointUDP runs traceroute tests to a public endpoint for UDP protocol
// In CI this will run on MacOS
func TestPublicEndpointUDP(t *testing.T) {
	for _, baseConfig := range UDPProtocol {
		t.Run(baseConfig.testName(), func(t *testing.T) {
			config := baseConfig
			config.hostname = publicEndpointHostname
			config.port = publicEndpointPort
			config.expectIntermediateHops = false
			testCommon(t, config)
		})
	}
}

// TestPublicEndpointTCPSYN runs traceroute tests to a public endpoint for TCP SYN protocol
// In CI this will run on Linux, MacOS, and Windows
func TestPublicEndpointTCPSYN(t *testing.T) {
	for _, baseConfig := range TCPSYNProtocol {
		t.Run(baseConfig.testName(), func(t *testing.T) {
			config := baseConfig
			config.hostname = publicEndpointHostname
			config.port = publicEndpointPort
			config.expectIntermediateHops = false
			testCommon(t, config)
		})
	}
}

// TestPublicEndpointTCPPreferSACK runs traceroute tests to a public endpoint for TCP PreferSACK protocol
// In CI this will run on Linux, MacOS, and Windows
func TestPublicEndpointTCPPreferSACK(t *testing.T) {
	for _, baseConfig := range TCPPreferSACKProtocol {
		t.Run(baseConfig.testName(), func(t *testing.T) {
			config := baseConfig
			config.hostname = publicEndpointHostname
			config.port = publicEndpointPort
			config.expectIntermediateHops = false
			testCommon(t, config)
		})
	}
}

// JMWTHU add SACK tests w/ expected failures

// TestFakeNetwork runs traceroute tests in a fake network environment for all protocols.
// This test should be run in a sandboxed environment where testutils/router_setup.sh is
// run first to set up network namespaces and virtual routing.
// In CI this will only run on Linux.
func TestFakeNetwork(t *testing.T) {
	for _, baseConfig := range AllProtocolsExceptSACK {
		t.Run(baseConfig.testName(), func(t *testing.T) {
			config := baseConfig
			config.hostname = fakeNetworkHostname
			config.port = 0
			config.expectIntermediateHops = true
			testCommon(t, config)
		})
	}
}

// getCLIBinaryPath returns the path to the CLI binary, building it if necessary
func getCLIBinaryPath(t *testing.T) string {
	t.Helper()

	cliBinaryOnce.Do(func() {
		projectRoot := filepath.Join("..")

		preBuiltBinaryPath := filepath.Join(projectRoot, "datadog-traceroute")
		if _, err := os.Stat(preBuiltBinaryPath); err == nil {
			t.Log("Using pre-built binary from CI")
			cliBinaryPath = preBuiltBinaryPath
			cliBinaryNeedsCleanup = false
			return
		}

		t.Log("Pre-built binary not found, building test binary")
		binaryName := "datadog-traceroute-test"
		cliBinaryPath = filepath.Join(projectRoot, binaryName)

		buildCmd := exec.Command("go", "build", "-o", binaryName, ".")
		buildCmd.Dir = projectRoot
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build datadog-traceroute: %v\nOutput: %s", err, string(buildOutput))
		}

		cliBinaryNeedsCleanup = true
	})

	return cliBinaryPath
}

func cleanupCLIBinary() {
	if cliBinaryNeedsCleanup && cliBinaryPath != "" {
		os.Remove(cliBinaryPath)
	}
}

func testCLI(t *testing.T, config testConfig) {
	t.Helper()

	binaryPath := getCLIBinaryPath(t)

	args := []string{
		"--e2e-queries", "10",
		"--max-ttl", "5",
		"--proto", strings.ToLower(string(config.protocol)),
		"--timeout", "500",
		"--traceroute-queries", "3",
		//JMW breaks unmarshalling JSON for validation"--verbose",

		//JMW
  // --port int                 Destination port (default 33434)
  //     --reverse-dns              Enrich IPs with Reverse DNS names
  //     --skip-private-hops        Skip private hops
  //     --source-public-ip         Enrich with Source Public IP
  //     --tcp-method string        Method used to run TCP (syn, sack, prefer_sack) (default "syn")
  //     --windows-driver           Use Windows driver for traceroute (Windows only)
	}
	if config.port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", config.port))
	}
	if config.tcpMethod != "" {
		args = append(args, "--tcp-method", string(config.tcpMethod))
	}
	args = append(args, config.hostname)

	cmd := exec.Command(binaryPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run datadog-traceroute: %v\nOutput: %s", err, string(output))
	}

	var results result.Results
	err = json.Unmarshal(output, &results)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v\nOutput: %s", err, string(output))
	}

	validateResults(t, &results, config)
}

// TestLocalhostCLI runs CLI tests to localhost for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestLocalhostCLI(t *testing.T) {
	testConfigs := []testConfig{
		{
			hostname:               "127.0.0.1",
			port:                   0,
			protocol:               traceroute.ProtocolICMP,
			expectIntermediateHops: false,
		},
		{
			hostname:               "127.0.0.1",
			port:                   0,
			protocol:               traceroute.ProtocolUDP,
			expectIntermediateHops: false,
		},
		{
			hostname:               "127.0.0.1",
			port:                   0,
			protocol:               traceroute.ProtocolTCP,
			tcpMethod:              traceroute.TCPConfigSYN,
			expectIntermediateHops: false,
		},
		{
			hostname:               "127.0.0.1",
			port:                   0,
			protocol:               traceroute.ProtocolTCP,
			tcpMethod:              traceroute.TCPConfigPreferSACK,
			expectIntermediateHops: false,
		},
	}

	for _, config := range testConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testCLI(t, config)
		})
	}
}

// validateResults validates traceroute results
func validateResults(t *testing.T, results *result.Results, config testConfig) {
	t.Helper()

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
		assert.NotEmpty(t, run.Hops, "run %d should have at least one hop", i)

		// Count reachable hops
		reachableCount := 0
		for j, hop := range run.Hops {
			assert.NotZero(t, hop.TTL, "run %d, hop %d should have a TTL", i, j)

			if hop.Reachable {
				reachableCount++
				assert.NotNil(t, hop.IPAddress, "run %d, hop %d should have an IP address if reachable", i, j)
				assert.Greater(t, hop.RTT, 0.0, "run %d, hop %d should have positive RTT if reachable", i, j)
			}
		}

		// If we expect intermediate hops, we need at least 2 reachable hops (1 intermediate + destination)
		// Otherwise, we just need at least 1 reachable hop (the destination)
		minReachableHops := 1
		if config.expectIntermediateHops {
			minReachableHops = 2
		}
		assert.GreaterOrEqual(t, reachableCount, minReachableHops, "run %d should have at least %d reachable hop(s)", i, minReachableHops)

		// Validate that the last hop is the destination and is reachable
		lastHop := run.Hops[len(run.Hops)-1]
		assert.True(t, lastHop.Reachable, "run %d last hop should be reachable", i)
		assert.NotNil(t, lastHop.IPAddress, "run %d last hop should have an IP address", i)
		assert.Greater(t, lastHop.RTT, 0.0, "run %d last hop should have positive RTT", i)

		// Verify the last hop IP matches the run's destination IP
		assert.True(t, lastHop.IPAddress.Equal(run.Destination.IPAddress),
			"run %d last hop IP should match run destination IP", i)

		// Validate source and destination
		assert.NotNil(t, run.Source.IPAddress, "run %d should have source IP", i)
		assert.NotNil(t, run.Destination.IPAddress, "run %d should have destination IP", i)
		if config.port > 0 && config.protocol != traceroute.ProtocolICMP {
			assert.Equal(t, uint16(config.port), run.Destination.Port, "run %d destination port should match", i)
		}
	}

	// Validate hop count stats
	assert.Greater(t, results.Traceroute.HopCount.Avg, 0.0, "average hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Min, 0, "min hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Max, 0, "max hop count should be positive")
	assert.GreaterOrEqual(t, results.Traceroute.HopCount.Max, results.Traceroute.HopCount.Min, "max hop count should be >= min")

	// Validate E2E probe results
	assert.NotEmpty(t, results.E2eProbe.RTTs, "should have E2E probe RTTs")
	assert.Equal(t, 10, len(results.E2eProbe.RTTs), "should have 10 E2E probes as requested")
	assert.Equal(t, 10, results.E2eProbe.PacketsSent, "should have sent 10 E2E packets")

	// JMWTHU can we validate 0% packet loss or is that too flaky?
	// Validate packet loss
	//JMWassert.GreaterOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "packet loss should be >= 0")
	//JMWassert.LessOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(1.0), "packet loss should be <= 1.0")
	assert.Equal(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "packet loss should be == 0.0")

	// If we received any packets, validate RTT stats
	if results.E2eProbe.PacketsReceived > 0 {
		assert.Greater(t, results.E2eProbe.RTT.Avg, 0.0, "E2E average RTT should be positive")
		assert.Greater(t, results.E2eProbe.RTT.Min, 0.0, "E2E min RTT should be positive")
		assert.Greater(t, results.E2eProbe.RTT.Max, 0.0, "E2E max RTT should be positive")
		assert.GreaterOrEqual(t, results.E2eProbe.RTT.Max, results.E2eProbe.RTT.Min, "E2E max RTT should be >= min")

		// RTT should be reasonable
		assert.Less(t, results.E2eProbe.RTT.Avg, 5000.0, "E2E average RTT should be less than 5 seconds")
	}

	// JMW other checks?
}
