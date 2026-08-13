// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build e2etest

package e2etests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	cliBinaryPath         string
	cliBinaryOnce         sync.Once
	cliBinaryNeedsCleanup bool
)

// getCLIBinaryPath returns the path to the CLI binary, building it if necessary
func getCLIBinaryPath(t *testing.T) string {
	cliBinaryOnce.Do(func() {
		projectRoot := filepath.Join("..")

		binaryName := "datadog-traceroute"
		if runtime.GOOS == "windows" {
			binaryName = "datadog-traceroute.exe"
		}

		// check for pre-built binary (i.e. when running in CI)
		preBuiltBinaryPath := filepath.Join(projectRoot, binaryName)
		if _, err := os.Stat(preBuiltBinaryPath); err == nil {
			t.Logf("using pre-built binary: %s", binaryName)
			cliBinaryPath = preBuiltBinaryPath
			cliBinaryNeedsCleanup = false
			return
		}

		t.Logf("pre-built binary not found, building test binary: %s", binaryName)
		cliBinaryPath = filepath.Join(projectRoot, binaryName)

		t.Logf("running command: go build -o %s .", binaryName)
		buildCmd := exec.Command("go", "build", "-o", binaryName, ".")
		buildCmd.Dir = projectRoot
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build datadog-traceroute: %v\nOutput: %s", err, string(buildOutput))
		}

		cliBinaryNeedsCleanup = true
		// Note: Cleanup is handled in TestMain to ensure it runs after ALL tests complete,
		// not after individual subtests. This is necessary because the binary is shared
		// across multiple tests via sync.Once.
	})

	return cliBinaryPath
}

// cleanupCLI removes the built CLI binary if it was created during tests
func cleanupCLI() {
	if cliBinaryNeedsCleanup && cliBinaryPath != "" {
		if err := os.Remove(cliBinaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to remove CLI binary %s: %v\n", cliBinaryPath, err)
		}
	}
}

// getCLICommandAndArgs returns the command name and arguments for executing the CLI binary
// Returns the command name and args slice that can be used with exec.Command
func getCLICommandAndArgs(t *testing.T, config testConfig) (string, []string) {
	binaryPath := getCLIBinaryPath(t)

	args := []string{
		"--e2e-queries", strconv.Itoa(numE2eProbes),
		"--proto", strings.ToLower(string(config.protocol)),
		"--traceroute-queries", strconv.Itoa(numTraceroutes),
		"--reverse-dns",
		"--source-public-ip",
	}

	if config.port > 0 {
		args = append(args, "--port", strconv.Itoa(config.port))
	}
	if config.tcpMethod != "" {
		args = append(args, "--tcp-method", string(config.tcpMethod))
	}
	if testing.Verbose() {
		args = append(args, "--verbose")
	}

	args = append(args, config.hostname)

	// On Unix systems (not Windows), traceroute needs elevated privileges
	// Run with sudo when not on Windows
	var cmdName string
	var cmdArgs []string
	if runtime.GOOS != "windows" {
		// Prepend sudo to the command
		cmdName = "sudo"
		cmdArgs = append([]string{binaryPath}, args...)
		t.Logf("running command: sudo %s %v", binaryPath, args)
	} else {
		cmdName = binaryPath
		cmdArgs = args
		t.Logf("running command: %s %v", binaryPath, args)
	}

	return cmdName, cmdArgs
}

func testCLI(t *testing.T, config testConfig) {
	maxAttempts := config.getMaxAttempts(t)

	t.Logf("running with testConfig %+v expectDestinationReachable %v expectIntermediateHops=%v expectedError=%s maxAttempts=%d",
		config, config.expectDestinationReachable(t), config.expectIntermediateHops(t), config.expectError(t), maxAttempts)

	cmdName, cmdArgs := getCLICommandAndArgs(t, config)

	var lastRunErr error
	var stdout, stderr bytes.Buffer

	// Retry loop - only retries cmd.Run() failures
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			t.Logf("retrying command execution (attempt %d/%d)", attempt, maxAttempts)
			stdout.Reset()
			stderr.Reset()
		}

		// Create a fresh command for each attempt
		cmd := exec.Command(cmdName, cmdArgs...)

		// Capture stdout (JSON output) and stderr (logs) separately
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		lastRunErr = cmd.Run()

		// if stderr is not empty, log it for debugging
		if stderr.Len() > 0 {
			t.Logf("datadog-traceroute CLI stderr:\n%s", stderr.String())
		}

		// If command succeeded, break out of retry loop
		if lastRunErr == nil {
			break
		}

		// Command failed - log and potentially retry
		t.Logf("command failed on attempt %d: %v", attempt, lastRunErr)
	}

	// If we expect an error, check for it
	expectedError := config.expectError(t)
	if expectedError != "" {
		require.Error(t, lastRunErr, "CLI should fail for %s", config.testName())
		combinedOutput := stdout.String() + stderr.String()
		assert.Contains(t, combinedOutput, expectedError, "error message should contain expected string")
		return
	}

	if lastRunErr != nil {
		t.Fatalf("Failed to run datadog-traceroute after %d attempts: %v\nStderr: %s\nStdout: %s", maxAttempts, lastRunErr, stderr.String(), stdout.String())
	}

	var results result.Results
	err := json.Unmarshal(stdout.Bytes(), &results)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	validateResults(t, stdout.Bytes(), config)
}

// TestLocalhostCLI runs CLI tests to localhost
func TestLocalhostCLI(t *testing.T) {
	for _, config := range localhostTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testCLI(t, config)
		})
	}
}

// TestPublicTargetCLI runs CLI tests to a public target
func TestPublicTargetCLI(t *testing.T) {
	for _, config := range publicTargetTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testCLI(t, config)
		})
	}
}

// TestFakeNetworkCLI runs CLI tests to a local IP address with a fake network config
func TestFakeNetworkCLI(t *testing.T) {
	for _, config := range fakeNetworkTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testCLI(t, config)
		})
	}
}

func TestFakeNetworkCLITotalTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the controlled fake network is configured only in Linux CI")
	}

	tests := []struct {
		name     string
		protocol string
		timeout  *int
	}{
		{
			name:     "UDP_total_timeout_derives_probe_timeout",
			protocol: "udp",
		},
		{
			name:     "UDP_zero_probe_timeout_still_obeys_total_timeout",
			protocol: "udp",
			timeout:  intPtr(0),
		},
		{
			name:     "ICMP_total_timeout_derives_probe_timeout",
			protocol: "icmp",
		},
		{
			name:     "TCP_probe_timeout_longer_than_total_timeout",
			protocol: "tcp",
			timeout:  intPtr(10_000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{
				"--proto", tt.protocol,
				"--traceroute-queries", "1",
				"--e2e-queries", "0",
				"--total-timeout-ms", "100",
			}
			if tt.timeout != nil {
				args = append(args, "--timeout", strconv.Itoa(*tt.timeout))
			}
			args = append(args, fakeNetworkTimeoutTarget)

			binaryPath := getCLIBinaryPath(t)
			cmd := exec.Command("sudo", append([]string{binaryPath}, args...)...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			start := time.Now()
			err := cmd.Run()
			elapsed := time.Since(start)

			require.Error(t, err, "a deadline with no completed traceroute run must fail")
			assert.Empty(t, stdout.String(), "timeout errors must not emit partial JSON")
			assert.Contains(t, stderr.String(), "context deadline exceeded")
			assert.GreaterOrEqual(t, elapsed, 80*time.Millisecond)
			assert.Less(t, elapsed, 2*time.Second, "the total timeout must cap the real driver path")
		})
	}
}

func TestFakeNetworkCLIAgentShapedTotalTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the controlled fake network is configured only in Linux CI")
	}

	// Exercise the real CLI and UDP driver with the Agent-shaped defaults. The
	// deterministic silent-final behavior is tested at the library boundary because
	// selecting only the last concurrently scheduled packet in this network fixture
	// would require order-dependent firewall rules and make this E2E test flaky.
	const totalTimeout = 10 * time.Second
	args := []string{
		"--proto", "udp",
		"--max-ttl", strconv.Itoa(common.DefaultMaxTTL),
		"--traceroute-queries", strconv.Itoa(common.DefaultTracerouteQueries),
		"--e2e-queries", strconv.Itoa(common.DefaultNumE2eProbes),
		"--total-timeout-ms", strconv.FormatInt(totalTimeout.Milliseconds(), 10),
		fakeNetworkTarget,
	}

	binaryPath := getCLIBinaryPath(t)
	cmd := exec.Command("sudo", append([]string{binaryPath}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	require.NoError(t, err, "Agent-shaped run failed: %s", stderr.String())
	var results result.Results
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &results))
	assert.Len(t, results.Traceroute.Runs, common.DefaultTracerouteQueries)
	assert.Equal(t, common.DefaultNumE2eProbes, results.E2eProbe.PacketsSent)
	assert.Less(t, elapsed, totalTimeout+common.DefaultProbePollFrequency+2*time.Second,
		"the process should finish within TotalTimeout plus polling and startup tolerance")
}

func intPtr(value int) *int {
	return &value
}
