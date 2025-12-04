// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build integration

package integration_tests

import (
	"context"
	"encoding/json"
	"testing"

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

// Protocol test configurations
type protocolTest struct {
	name      string
	protocol  string
	tcpMethod traceroute.TCPMethod
}

var (
	ICMPProtocol = []protocolTest{
		{name: "ICMP", protocol: "icmp"},
	}
	UDPProtocol = []protocolTest{
		{name: "UDP", protocol: "udp"},
	}

	TCPSYNProtocol = []protocolTest{
		{name: "TCP_SYN", protocol: "tcp", tcpMethod: traceroute.TCPConfigSYN},
	}

	TCPSACKProtocol = []protocolTest{
		{name: "TCP_SACK", protocol: "tcp", tcpMethod: traceroute.TCPConfigSACK},
	}

	TCPPreferSACKProtocol = []protocolTest{
		{name: "TCP_PreferSACK", protocol: "tcp", tcpMethod: traceroute.TCPConfigPreferSACK},
	}

	// TCPProtocols defines all TCP protocol tests
	AllProtocolsExceptSACK = []protocolTest{
		{name: "ICMP", protocol: "icmp"},
		{name: "UDP", protocol: "udp"},
		{name: "TCP_SYN", protocol: "tcp", tcpMethod: traceroute.TCPConfigSYN},
		{name: "TCP_PreferSACK", protocol: "tcp", tcpMethod: traceroute.TCPConfigPreferSACK},
	}
)

// testConfig holds configuration for running traceroute tests
type testConfig struct {
	hostname         string
	port             int
	protocols        []protocolTest
	expectMultiHops  bool
}

// testCommon runs traceroute tests for the specified protocols with the given configuration
func testCommon(t *testing.T, config testConfig) {
	t.Helper()

	for _, tt := range config.protocols {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			params := traceroute.TracerouteParams{
				Hostname:          config.hostname,
				Port:              config.port,
				Protocol:          tt.protocol,
				MinTTL:            common.DefaultMinTTL,
				MaxTTL:            common.DefaultMaxTTL,
				Delay:             common.DefaultDelay,
				Timeout:           common.DefaultNetworkPathTimeout,
				TCPMethod:         tt.tcpMethod,
				WantV6:            false,
				ReverseDns:        false,
				TracerouteQueries: 3,
				E2eQueries:        10,
				UseWindowsDriver:  false,
			}

			tr := traceroute.NewTraceroute()
			results, err := tr.RunTraceroute(ctx, params)
			require.NoError(t, err, "%s traceroute to %s should not fail", tt.name, config.hostname)
			require.NotNil(t, results, "Results should not be nil")

			validateResults(t, results, tt.protocol, config.hostname, config.port)
		})
	}
}

// TestLocalhost runs traceroute tests to localhost for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestLocalhost(t *testing.T) {
	testCommon(t, testConfig{
		hostname:         "127.0.0.1",
		port:             0,
		protocols:        AllProtocolsExceptSACK,
		expectMultiHops:  false,
	})
}

// TestPublicEndpointICMP runs traceroute tests to a public endpoint for ICMP protocol
// In CI this will run on MacOS
func TestPublicEndpointICMP(t *testing.T) {
	testCommon(t, testConfig{
		hostname:         publicEndpointHostname,
		port:             publicEndpointPort,
		protocols:        ICMPProtocol,
		expectMultiHops:  true,
	})
}

// TestPublicEndpointUDP runs traceroute tests to a public endpoint for UDP protocol
// In CI this will run on MacOS
func TestPublicEndpointUDP(t *testing.T) {
	testCommon(t, testConfig{
		hostname:         publicEndpointHostname,
		port:             publicEndpointPort,
		protocols:        UDPProtocol,
		expectMultiHops:  true,
	})
}

// TestPublicEndpointTCPSYN runs traceroute tests to a public endpoint for TCP SYN protocol
// In CI this will run on Linux, MacOS, and Windows
func TestPublicEndpointTCPSYN(t *testing.T) {
	testCommon(t, testConfig{
		hostname:         publicEndpointHostname,
		port:             publicEndpointPort,
		protocols:        TCPSYNProtocol,
		expectMultiHops:  true,
	})
}

// TestPublicEndpointTCPPreferSACK runs traceroute tests to a public endpoint for TCP PreferSACK protocol
// In CI this will run on Linux, MacOS, and Windows
func TestPublicEndpointTCPPreferSACK(t *testing.T) {
	testCommon(t, testConfig{
		hostname:         publicEndpointHostname,
		port:             publicEndpointPort,
		protocols:        TCPPreferSACKProtocol,
		expectMultiHops:  true,
	})
}

// JMWTHU add SACK tests w/ expected failures

// TestFakeNetwork runs traceroute tests in a fake network environment for all protocols.
// This test should be run in a sandboxed environment where testutils/router_setup.sh is
// run first to set up network namespaces and virtual routing.
// In CI this will only run on Linux.
func TestFakeNetwork(t *testing.T) {
	testCommon(t, testConfig{
		hostname:         fakeNetworkHostname,
		port:             0,
		protocols:        AllProtocolsExceptSACK,
		expectMultiHops:  true,
	})
}

// validateResults validates traceroute results
func validateResults(t *testing.T, results *result.Results, protocol, hostname string, port int) {
	t.Helper()

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Logf("Failed to marshal results to JSON: %v", err)
	} else {
		t.Logf("Validating traceroute results:\n%s", string(jsonBytes))
	}

	// Validate basic parameters
	assert.Equal(t, protocol, results.Protocol, "protocol should match")
	assert.Equal(t, hostname, results.Destination.Hostname, "hostname should match")
	if port > 0 {
		assert.Equal(t, port, results.Destination.Port, "port should match")
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

		assert.Greater(t, reachableCount, 0, "run %d should have at least one reachable hop", i)

		// Validate source and destination
		assert.NotNil(t, run.Source.IPAddress, "run %d should have source IP", i)
		assert.NotNil(t, run.Destination.IPAddress, "run %d should have destination IP", i)
		if port > 0 {
			assert.Equal(t, uint16(port), run.Destination.Port, "run %d destination port should match", i)
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
	assert.GreaterOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "packet loss should be >= 0")
	assert.LessOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(1.0), "packet loss should be <= 1.0")

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
