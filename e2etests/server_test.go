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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getServerBinaryPath returns the path to the HTTP server binary, building it if necessary
func getServerBinaryPath(t *testing.T) string {
	t.Helper()

	serverBinaryOnce.Do(func() {
		projectRoot := filepath.Join("..")

		// Determine binary name based on OS
		binaryName := "datadog-traceroute-server"
		if runtime.GOOS == "windows" {
			binaryName = "datadog-traceroute-server.exe"
		}

		// Check for pre-built binary (CI scenario)
		preBuiltBinaryPath := filepath.Join(projectRoot, binaryName)
		if _, err := os.Stat(preBuiltBinaryPath); err == nil {
			t.Log("Using pre-built server binary from CI")
			serverBinaryPath = preBuiltBinaryPath
			serverBinaryNeedsCleanup = false
			return
		}

		t.Log("Pre-built server binary not found, building test server binary")
		testBinaryName := "datadog-traceroute-server"
		if runtime.GOOS == "windows" {
			testBinaryName = "datadog-traceroute-server.exe"
		}
		serverBinaryPath = filepath.Join(projectRoot, testBinaryName)

		buildCmd := exec.Command("go", "build", "-o", testBinaryName, "./cmd/traceroute-server")
		buildCmd.Dir = projectRoot
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build datadog-traceroute-server: %v\nOutput: %s", err, string(buildOutput))
		}

		serverBinaryNeedsCleanup = true
	})

	return serverBinaryPath
}

func cleanupServerBinary() {
	if serverBinaryNeedsCleanup && serverBinaryPath != "" {
		os.Remove(serverBinaryPath)
	}
}

// isServerRunning checks if a server is already running on the given address
func isServerRunning(addr string) bool {
	// Try to make a simple request to the traceroute endpoint with a minimal query
	// If it returns 400 (bad request) or 200, the server is running
	// We expect 400 because we're not providing required parameters
	resp, err := http.Get(fmt.Sprintf("http://%s/traceroute", addr))
	if err != nil {
		return false
	}
	resp.Body.Close()
	// Server is running if we get any HTTP response (200, 400, etc.)
	// Just not a connection error
	return true
}

// ensureServerRunning ensures the HTTP server is running on serverAddr
// It checks if a server is already running (e.g., in CI), and if not, starts one
func ensureServerRunning(t *testing.T) string {
	t.Helper()

	serverProcessOnce.Do(func() {
		// First check if server is already running (CI scenario)
		if isServerRunning(serverAddr) {
			t.Logf("HTTP server already running on %s", serverAddr)
			return
		}

		// Server not running, start it
		t.Logf("HTTP server not running, starting on %s", serverAddr)
		binaryPath := getServerBinaryPath(t)

		// On Unix systems (not Windows), traceroute needs elevated privileges
		// Run with sudo when not on Windows
		var cmd *exec.Cmd
		if runtime.GOOS != "windows" {
			// Prepend sudo to the command
			t.Logf("Running command: sudo %s --addr %s --log-level error", binaryPath, serverAddr)
			cmd = exec.Command("sudo", binaryPath, "--addr", serverAddr, "--log-level", "error")
		} else {
			t.Logf("Running command: %s --addr %s --log-level error", binaryPath, serverAddr)
			cmd = exec.Command(binaryPath, "--addr", serverAddr, "--log-level", "error")
		}

		// Capture stdout and stderr
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		// Start the server
		err := cmd.Start()
		if err != nil {
			t.Fatalf("Failed to start datadog-traceroute-server: %v", err)
		}

		serverProcess = cmd

		// Wait for server to be ready
		time.Sleep(500 * time.Millisecond)

		// Verify server is now running
		if !isServerRunning(serverAddr) {
			t.Fatalf("Server failed to start. Stderr: %s", stderr.String())
		}

		t.Logf("HTTP server started successfully on %s", serverAddr)
	})

	return serverAddr
}

//JMWFRI this isn't being clenaed up on my mac
func cleanupServerProcess() {
	if serverProcess != nil && serverProcess.Process != nil {
		serverProcess.Process.Kill()
		serverProcess.Wait()
	}
}

// testHTTPServer runs an HTTP server traceroute test with the given configuration
func testHTTPServer(t *testing.T, config testConfig) {
	t.Helper()

	// Ensure server is running (either already running in CI or start it once)
	testServerAddr := ensureServerRunning(t)

	// Build the HTTP request URL
	// JMW build the cli cmd and URL similarly
	url := fmt.Sprintf("http://%s/traceroute?target=%s&protocol=%s&tcp-method=%s&traceroute-queries=3&e2e-queries=10",
		testServerAddr, config.hostname, strings.ToLower(string(config.protocol)), string(config.tcpMethod))

	if config.port > 0 {
		url += fmt.Sprintf("&port=%d", config.port)
	}
	if config.tcpMethod != "" {
		url += fmt.Sprintf("&tcp-method=%s", string(config.tcpMethod))
	}

	// Make HTTP GET request
	t.Logf("Making HTTP GET request: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("Failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// If we expect an error, check for it in the HTTP response
	expectedError := config.expectError(t)
	if expectedError != "" {
		// The server should return a non-200 status code for errors
		assert.NotEqual(t, http.StatusOK, resp.StatusCode, "HTTP server should return error status for %s", config.testName())

		// Read the response body to check for the expected error message
		var buf bytes.Buffer
		_, err = buf.ReadFrom(resp.Body)
		require.NoError(t, err, "should be able to read error response body")

		assert.Contains(t, buf.String(), expectedError, "error response should contain expected string")
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP request failed with status %d", resp.StatusCode)
	}

	// Parse JSON response
	var results result.Results
	err = json.NewDecoder(resp.Body).Decode(&results)
	if err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	validateResults(t, &results, config)
}

// TestLocalhostHTTPServer runs HTTP server tests to localhost for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestLocalhostHTTPServer(t *testing.T) {
	testConfigs := []testConfig{
		{
			hostname: localhostTarget,
			port:     0,
			protocol: traceroute.ProtocolICMP,
		},
		{
			hostname: localhostTarget,
			port:     0,
			protocol: traceroute.ProtocolUDP,
		},
		{
			hostname:  localhostTarget,
			port:      0,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigSYN,
		},
		{
			hostname:  localhostTarget,
			port:      0,
			protocol:  traceroute.ProtocolTCP,
			tcpMethod: traceroute.TCPConfigPreferSACK,
		},
	}

	for _, config := range testConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testHTTPServer(t, config)
		})
	}
}

// TestPublicTargetHTTPServer runs HTTP server tests to a public target for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestPublicTargetHTTPServer(t *testing.T) {
	testConfigs := []testConfig{
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

	for _, config := range testConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testHTTPServer(t, config)
		})
	}
}

// TestFakeNetworkHTTPServer runs HTTP server tests to JMW for all protocols
// In CI this will run on Linux
func TestFakeNetworkHTTPServer(t *testing.T) {
	testConfigs := []testConfig{
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

	for _, config := range testConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testHTTPServer(t, config)
		})
	}
}
