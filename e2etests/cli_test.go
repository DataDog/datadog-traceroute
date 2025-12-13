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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getCLIBinaryPath returns the path to the CLI binary, building it if necessary
func getCLIBinaryPath(t *testing.T) string {
	cliBinaryOnce.Do(func() {
		projectRoot := filepath.Join("..")

		// Determine binary name based on OS
		binaryName := "datadog-traceroute"
		if runtime.GOOS == "windows" {
			binaryName = "datadog-traceroute.exe"
		}

		// Check for pre-built binary (CI scenario)
		preBuiltBinaryPath := filepath.Join(projectRoot, binaryName)
		if _, err := os.Stat(preBuiltBinaryPath); err == nil {
			t.Logf("Using pre-built binary from CI: %s", binaryName)
			cliBinaryPath = preBuiltBinaryPath
			cliBinaryNeedsCleanup = false
			return
		}

		testBinaryName := "datadog-traceroute"
		if runtime.GOOS == "windows" {
			testBinaryName = "datadog-traceroute.exe"
		}
		t.Logf("Pre-built binary not found, building test binary: %s", testBinaryName)
		cliBinaryPath = filepath.Join(projectRoot, testBinaryName)

		buildCmd := exec.Command("go", "build", "-o", testBinaryName, ".")
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
	fmt.Printf("JMW in cleanupCLIBinary cliBinaryNeedsCleanup=%v cliBinaryPath=%s\n", cliBinaryNeedsCleanup, cliBinaryPath) //JMW
	if cliBinaryNeedsCleanup && cliBinaryPath != "" {
		fmt.Printf("JMW Cleaning up CLI binary: %s\n", cliBinaryPath)
		os.Remove(cliBinaryPath)
	}
}

func testCLI(t *testing.T, config testConfig) {
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

	t.Logf("Running with testConfig %+v expectDestinationReachable %v expectIntermediateHops=%v expectedError=%s",
		config, config.expectDestinationReachable(t), config.expectIntermediateHops(t), config.expectError(t))

	// On Unix systems (not Windows), traceroute needs elevated privileges
	// Run with sudo when not on Windows
	var cmd *exec.Cmd
	if runtime.GOOS != "windows" {
		// Prepend sudo to the command
		sudoArgs := append([]string{binaryPath}, args...)
		t.Logf("Running command: sudo %s %v", binaryPath, args)
		cmd = exec.Command("sudo", sudoArgs...)
	} else {
		t.Logf("Running command: %s %v", binaryPath, args)
		cmd = exec.Command(binaryPath, args...)
	}

	// Capture stdout (JSON output) and stderr (logs) separately
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// if stderr is not empty, log it for debugging
	if stderr.Len() > 0 {
		t.Logf("datadog-traceroute stderr:\n%s", stderr.String())
	}

	// If we expect an error, check for it
	expectedError := config.expectError(t)
	if expectedError != "" {
		require.Error(t, err, "CLI should fail for %s", config.testName())
		combinedOutput := stdout.String() + stderr.String()
		assert.Contains(t, combinedOutput, expectedError, "error message should contain expected string")
		return
	}

	if err != nil {
		t.Fatalf("Failed to run datadog-traceroute: %v\nStderr: %s\nStdout: %s", err, stderr.String(), stdout.String())
	}

	var results result.Results
	err = json.Unmarshal(stdout.Bytes(), &results)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	validateResults(t, &results, config)
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
