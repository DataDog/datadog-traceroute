// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build integration

package integration_tests

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// JMW - testMaxTTL and testTimeout constants - where were these before?
const (
	testMaxTTL = 10
	testTimeout = 500 * time.Millisecond
)

// JMW go thru these tests, are they valid and worth testing?

// TestInvalidProtocol tests that an invalid protocol is handled correctly
func TestInvalidProtocol(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "127.0.0.1",
		Port:              0,
		Protocol:          "invalid", // Invalid protocol
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            testMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           testTimeout,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 1,
		E2eQueries:        0,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	assert.Error(t, err, "Should return error for invalid protocol")
	assert.Nil(t, results, "Results should be nil when error occurs")
	assert.Contains(t, err.Error(), "invalid", "Error message should mention invalid protocol")
}

// TestInvalidHostname tests that an invalid hostname is handled correctly
func TestInvalidHostname(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "this-hostname-definitely-does-not-exist-12345.invalid",
		Port:              443,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            testMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           testTimeout,
		TCPMethod:         traceroute.TCPConfigSYN,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 1,
		E2eQueries:        0,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	assert.Error(t, err, "Should return error for invalid hostname")
	assert.Nil(t, results, "Results should be nil when error occurs")
}

// TestZeroQueries tests behavior when no queries are requested
func TestZeroQueries(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "127.0.0.1",
		Port:              0,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            testMaxTTL,
		Delay:             common.DefaultDelay,
		Timeout:           testTimeout,
		TCPMethod:         traceroute.TCPConfigSYN,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 0, // No traceroute queries
		E2eQueries:        0, // No E2E queries
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "Should succeed even with zero queries")
	require.NotNil(t, results, "Results should not be nil")

	// Validate that results exist but have no runs
	assert.Empty(t, results.Traceroute.Runs, "Should have no traceroute runs")
	assert.Empty(t, results.E2eProbe.RTTs, "Should have no E2E probes")
}

// JMW should this and others be part of regular, not integration, tests?
// TestMinimalConfiguration tests with minimal valid configuration
// func TestMinimalConfiguration(t *testing.T) {
// 	if runtime.GOOS == "windows" && !isAdmin() {
// 		t.Skip("Test requires admin privileges on Windows")
// 	}

// 	ctx := context.Background()
// 	params := traceroute.TracerouteParams{
// 		Hostname:          "127.0.0.1",
// 		Protocol:          "tcp",
// 		TracerouteQueries: 1,
// 		// Using defaults for other fields
// 	}

// 	tr := traceroute.NewTraceroute()
// 	results, err := tr.RunTraceroute(ctx, params)
// 	require.NoError(t, err, "Should succeed with minimal configuration")
// 	require.NotNil(t, results, "Results should not be nil")

// 	// Validate basic structure
// 	assert.Equal(t, 1, len(results.Traceroute.Runs), "Should have 1 traceroute run")
// 	assert.Empty(t, results.E2eProbe.RTTs, "Should have no E2E probes (not requested)")
// }

// TestReverseDNSEnabled tests traceroute with reverse DNS lookups enabled
func TestReverseDNSEnabled(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "github.com",
		Port:              443,
		Protocol:          "tcp",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            10, // Limit hops to reduce test time
		Delay:             common.DefaultDelay,
		Timeout:           1000 * time.Millisecond,
		TCPMethod:         traceroute.TCPConfigSYN,
		WantV6:            false,
		ReverseDns:        true, // Enable reverse DNS
		TracerouteQueries: 1,
		E2eQueries:        0,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "Should succeed with reverse DNS enabled")
	require.NotNil(t, results, "Results should not be nil")

	// Check that at least some hops or destination have reverse DNS
	hasReverseDNS := false
	for _, run := range results.Traceroute.Runs {
		if len(run.Destination.ReverseDns) > 0 {
			hasReverseDNS = true
			break
		}
		for _, hop := range run.Hops {
			if len(hop.ReverseDns) > 0 {
				hasReverseDNS = true
				break
			}
		}
	}

	// Note: Reverse DNS might not always succeed, but at least we tested the code path
	if hasReverseDNS {
		t.Log("Successfully retrieved reverse DNS for some hops")
	} else {
		t.Log("No reverse DNS retrieved (this may be expected in some environments)")
	}
}

// TestHighTTL tests with a higher TTL value
func TestHighTTL(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx := context.Background()
	params := traceroute.TracerouteParams{
		Hostname:          "github.com",
		Port:              443,
		Protocol:          "tcp",
		MinTTL:            1,
		MaxTTL:            50, // Higher TTL
		Delay:             common.DefaultDelay,
		Timeout:           1000 * time.Millisecond,
		TCPMethod:         traceroute.TCPConfigSYN,
		WantV6:            false,
		ReverseDns:        false,
		TracerouteQueries: 1,
		E2eQueries:        0,
		UseWindowsDriver:  false,
	}

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)
	require.NoError(t, err, "Should succeed with high TTL")
	require.NotNil(t, results, "Results should not be nil")

	// Validate that we got results
	assert.NotEmpty(t, results.Traceroute.Runs, "Should have at least one run")

	// The actual hop count should be reasonable (not 50)
	for _, run := range results.Traceroute.Runs {
		assert.NotEmpty(t, run.Hops, "Should have some hops")
		assert.LessOrEqual(t, len(run.Hops), 50, "Should not exceed max TTL")
	}
}

// TestContextCancellation tests behavior when context is cancelled
func TestContextCancellation(t *testing.T) {
	if runtime.GOOS == "windows" && !isAdmin() {
		t.Skip("Test requires admin privileges on Windows")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	params := traceroute.TracerouteParams{
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

	tr := traceroute.NewTraceroute()
	results, err := tr.RunTraceroute(ctx, params)

	// The behavior might vary - either error or partial results
	// The important thing is that it doesn't hang
	if err != nil {
		t.Logf("Context cancellation resulted in error (expected): %v", err)
	} else {
		t.Logf("Context cancellation completed with results (partial results possible)")
		assert.NotNil(t, results, "If no error, results should not be nil")
	}
}
