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
	if config.wantV6 {
		args = append(args, "--ipv6")
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

// TestLocalhostCLI runs CLI tests to localhost (IPv4 and IPv6)
func TestLocalhostCLI(t *testing.T) {
	for _, config := range localhostTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			if config.wantV6 && runtime.GOOS != "linux" {
				t.Skip("IPv6 tests currently only supported on Linux")
			}
			testCLI(t, config)
		})
	}
}

// TestPublicTargetCLI runs CLI tests to a public target (IPv4 and IPv6)
func TestPublicTargetCLI(t *testing.T) {
	for _, config := range publicTargetTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			if config.wantV6 && runtime.GOOS != "linux" {
				t.Skip("IPv6 tests currently only supported on Linux")
			}
			testCLI(t, config)
		})
	}
}

// TestFakeNetworkCLI runs CLI tests to a local IP address with a fake network config
func TestFakeNetworkCLI(t *testing.T) {
	for _, config := range fakeNetworkTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			if config.wantV6 && runtime.GOOS != "linux" {
				t.Skip("IPv6 tests currently only supported on Linux")
			}
			testCLI(t, config)
		})
	}
}
