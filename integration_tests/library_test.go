// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build integration

package integration_tests

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	localhostTimeout      = 500 * time.Millisecond
	localhostMaxTTL       = 5
	publicEndpointTimeout = 1000 * time.Millisecond
)

// TestLocalhostICMP tests ICMP traceroute to localhost
func TestLocalhostICMP(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	// JMWDIFF how are these different from just running datadog-traceroute CLI commands?  setup params, call RunTraceroute()
	params := traceroute.TracerouteParams{
		Hostname:          "127.0.0.1",
		Port:              0,
		Protocol:          "icmp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            localhostMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           localhostTimeout,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "ICMP traceroute should not fail")
	require.NotNil(t, results, "Results should not be nil")

	validateLocalhostResults(t, results, "icmp")
}

// TestLocalhostUDP tests UDP traceroute to localhost
func TestLocalhostUDP(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "127.0.0.1",
		Port:              0,
		Protocol:          "udp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            localhostMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           localhostTimeout,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "UDP traceroute should not fail")
	require.NotNil(t, results, "Results should not be nil")

	validateLocalhostResults(t, results, "udp")
}

// TestLocalhostTCP tests TCP traceroute to localhost
func TestLocalhostTCP(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "127.0.0.1",
		Port:              0,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            localhostMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           localhostTimeout,
		TCPMethod:         traceroute.TCPConfigSYN,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "TCP traceroute should not fail")
	require.NotNil(t, results, "Results should not be nil")

	validateLocalhostResults(t, results, "tcp")
}

// JMWTHU organize tests better
// 1) localhost
// 2) public endpoint
// 3) fakenetwork
// for each, test ICMP, UDP, TCP SYN, TCP SACK, TCP PREFER_SACK

// JMWTHU add localhost SACK and PREFER_SACK
// JMWTHU add expected failure from fakenetwork SACK
// JMWTHU add expect all hops reachable from fakenetwork (except SACK)
// JMWTHU add public endpoint ICMP and UDP

// TestPublicEndpointTCP tests TCP traceroute to GitHub (public endpoint)
func TestPublicEndpointTCP(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "github.com",
		Port:              443,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            common.DefaultMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           publicEndpointTimeout,
		TCPMethod:         traceroute.TCPConfigSYN,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "TCP traceroute to GitHub should not fail")
	require.NotNil(t, results, "Results should not be nil")

	validatePublicEndpointResults(t, results, "tcp", "github.com", 443)
}

// TestPublicEndpointTCPSACK tests TCP SACK traceroute to GitHub
func TestPublicEndpointTCPSACK(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "github.com",
		Port:              443,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            common.DefaultMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           publicEndpointTimeout,
		TCPMethod:         traceroute.TCPConfigSACK,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "TCP SACK traceroute to GitHub should not fail")
	require.NotNil(t, results, "Results should not be nil")

	validatePublicEndpointResults(t, results, "tcp", "github.com", 443)
}

// TestPublicEndpointTCPPreferSACK tests TCP prefer_sack traceroute to GitHub
func TestPublicEndpointTCPPreferSACK(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "github.com",
		Port:              443,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            common.DefaultMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           publicEndpointTimeout,
		TCPMethod:         traceroute.TCPConfigPreferSACK,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 3,
		E2eQueries:        10,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "TCP prefer_sack traceroute to GitHub should not fail")
	require.NotNil(t, results, "Results should not be nil")

	validatePublicEndpointResults(t, results, "tcp", "github.com", 443)
}

// validateLocalhostResults validates traceroute results for localhost tests
func validateLocalhostResults(t *testing.T, results *result.Results, protocol string) {
	t.Helper()

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Logf("JMW Failed to marshal results to JSON: %v", err)
	} else {
		t.Logf("JMW Validating Traceroute Results:\n%s", string(jsonBytes))
	}

	// Validate basic parameters
	assert.Equal(t, protocol, results.Protocol, "Protocol should match")
	assert.Equal(t, "127.0.0.1", results.Destination.Hostname, "Hostname should be localhost")

	// Validate traceroute runs
	assert.NotEmpty(t, results.Traceroute.Runs, "Should have at least one traceroute run")
	assert.Equal(t, 3, len(results.Traceroute.Runs), "Should have 3 traceroute runs as requested")

	for i, run := range results.Traceroute.Runs {
		assert.NotEmpty(t, run.RunID, "Run %d should have a RunID", i)
		assert.NotEmpty(t, run.Hops, "Run %d should have at least one hop", i)

		// For localhost, we expect a very short path (typically 1 hop)
		assert.LessOrEqual(t, len(run.Hops), localhostMaxTTL, "Run %d should not exceed max TTL", i)

		// Validate hop information
		for j, hop := range run.Hops {
			assert.NotZero(t, hop.TTL, "Run %d, Hop %d should have a TTL", i, j)
			assert.LessOrEqual(t, hop.TTL, localhostMaxTTL, "Run %d, Hop %d TTL should not exceed max TTL", i, j)

			// At least some hops should be reachable
			if hop.Reachable {
				assert.NotNil(t, hop.IPAddress, "Run %d, Hop %d should have an IP address if reachable", i, j)
				assert.NotZero(t, hop.RTT, "Run %d, Hop %d should have RTT if reachable", i, j)
			}
		}

		// Validate source and destination
		assert.NotNil(t, run.Source.IPAddress, "Run %d should have source IP", i)
		assert.NotNil(t, run.Destination.IPAddress, "Run %d should have destination IP", i)
		assert.Equal(t, "127.0.0.1", run.Destination.IPAddress.String(), "Run %d destination should be localhost", i)
	}

	// Validate hop count stats
	assert.Greater(t, results.Traceroute.HopCount.Avg, 0.0, "Average hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Min, 0, "Min hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Max, 0, "Max hop count should be positive")
	assert.GreaterOrEqual(t, results.Traceroute.HopCount.Max, results.Traceroute.HopCount.Min, "Max hop count should be >= min")

	// Validate E2E probe results
	assert.NotEmpty(t, results.E2eProbe.RTTs, "Should have E2E probe RTTs")
	assert.Equal(t, 10, len(results.E2eProbe.RTTs), "Should have 10 E2E probes as requested")
	assert.Equal(t, 10, results.E2eProbe.PacketsSent, "Should have sent 10 E2E packets")

	// At least some E2E packets should be received for localhost
	assert.Greater(t, results.E2eProbe.PacketsReceived, 0, "Should have received some E2E packets")

	// Validate E2E RTT stats if packets were received
	if results.E2eProbe.PacketsReceived > 0 {
		assert.Greater(t, results.E2eProbe.RTT.Avg, 0.0, "E2E average RTT should be positive")
		assert.Greater(t, results.E2eProbe.RTT.Min, 0.0, "E2E min RTT should be positive")
		assert.Greater(t, results.E2eProbe.RTT.Max, 0.0, "E2E max RTT should be positive")
		assert.GreaterOrEqual(t, results.E2eProbe.RTT.Max, results.E2eProbe.RTT.Min, "E2E max RTT should be >= min")

		// Packet loss should be calculated
		assert.GreaterOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "Packet loss should be >= 0")
		assert.LessOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(1.0), "Packet loss should be <= 1.0")

		// For localhost, we expect low packet loss
		assert.Less(t, results.E2eProbe.PacketLossPercentage, float32(0.5), "Packet loss to localhost should be low")
	}
}

// validatePublicEndpointResults validates traceroute results for public endpoint tests
func validatePublicEndpointResults(t *testing.T, results *result.Results, protocol, hostname string, port int) {
	t.Helper()

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Logf("JMW Failed to marshal results to JSON: %v", err)
	} else {
		t.Logf("JMW Validating Traceroute Results:\n%s", string(jsonBytes))
	}

	// Validate basic parameters
	assert.Equal(t, protocol, results.Protocol, "Protocol should match")
	assert.Equal(t, hostname, results.Destination.Hostname, "Hostname should match")
	assert.Equal(t, port, results.Destination.Port, "Port should match")

	// Validate traceroute runs
	assert.NotEmpty(t, results.Traceroute.Runs, "Should have at least one traceroute run")
	assert.Equal(t, 3, len(results.Traceroute.Runs), "Should have 3 traceroute runs as requested")

	for i, run := range results.Traceroute.Runs {
		assert.NotEmpty(t, run.RunID, "Run %d should have a RunID", i)
		assert.NotEmpty(t, run.Hops, "Run %d should have at least one hop", i)

		// For public endpoints, we expect multiple hops
		assert.Greater(t, len(run.Hops), 1, "Run %d should have multiple hops for public endpoint", i)

		// Count reachable hops
		reachableCount := 0
		for j, hop := range run.Hops {
			assert.NotZero(t, hop.TTL, "Run %d, Hop %d should have a TTL", i, j)

			if hop.Reachable {
				reachableCount++
				assert.NotNil(t, hop.IPAddress, "Run %d, Hop %d should have an IP address if reachable", i, j)
				assert.Greater(t, hop.RTT, 0.0, "Run %d, Hop %d should have positive RTT if reachable", i, j)
			}
		}

		// We should have at least some reachable hops
		assert.Greater(t, reachableCount, 0, "Run %d should have at least one reachable hop", i)

		// Validate source and destination
		assert.NotNil(t, run.Source.IPAddress, "Run %d should have source IP", i)
		assert.NotNil(t, run.Destination.IPAddress, "Run %d should have destination IP", i)
		assert.Equal(t, uint16(port), run.Destination.Port, "Run %d destination port should match", i)
	}

	// Validate hop count stats
	assert.Greater(t, results.Traceroute.HopCount.Avg, 0.0, "Average hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Min, 0, "Min hop count should be positive")
	assert.Greater(t, results.Traceroute.HopCount.Max, 0, "Max hop count should be positive")
	assert.GreaterOrEqual(t, results.Traceroute.HopCount.Max, results.Traceroute.HopCount.Min, "Max hop count should be >= min")

	// Validate E2E probe results
	assert.NotEmpty(t, results.E2eProbe.RTTs, "Should have E2E probe RTTs")
	assert.Equal(t, 10, len(results.E2eProbe.RTTs), "Should have 10 E2E probes as requested")
	assert.Equal(t, 10, results.E2eProbe.PacketsSent, "Should have sent 10 E2E packets")

	// For public endpoints, some packet loss is acceptable
	assert.GreaterOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(0.0), "Packet loss should be >= 0")
	assert.LessOrEqual(t, results.E2eProbe.PacketLossPercentage, float32(1.0), "Packet loss should be <= 1.0")

	// If we received any packets, validate RTT stats
	if results.E2eProbe.PacketsReceived > 0 {
		assert.Greater(t, results.E2eProbe.RTT.Avg, 0.0, "E2E average RTT should be positive")
		assert.Greater(t, results.E2eProbe.RTT.Min, 0.0, "E2E min RTT should be positive")
		assert.Greater(t, results.E2eProbe.RTT.Max, 0.0, "E2E max RTT should be positive")
		assert.GreaterOrEqual(t, results.E2eProbe.RTT.Max, results.E2eProbe.RTT.Min, "E2E max RTT should be >= min")

		// For public endpoints, RTT should be reasonable but not necessarily very low
		assert.Less(t, results.E2eProbe.RTT.Avg, 5000.0, "E2E average RTT should be less than 5 seconds")
	}
}

// isAdmin checks if the current process has admin privileges on Windows
func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true // Not needed on non-Windows platforms
	}
	// For Windows, we'd need to check actual admin status
	// For now, just assume it's being run with proper privileges
	return true
}
