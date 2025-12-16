// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build e2etest

package e2etests

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// HTTP server binary state for reuse across tests
	serverBinaryPath         string
	serverBinaryOnce         sync.Once
	serverBinaryNeedsCleanup bool

	// HTTP server process state for reuse across tests
	serverProcess      *exec.Cmd
	serverProcessOnce  sync.Once
	serverStartupError string        // Error message if server failed to start
	serverStdout       *bytes.Buffer // Server stdout for debugging
	serverStderr       *bytes.Buffer // Server stderr for debugging
	serverAddr         = "127.0.0.1:3765"
)

// getServerBinaryPath returns the path to the HTTP server binary, building it if necessary
func getServerBinaryPath(t *testing.T) string {
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
			t.Logf("using pre-built HTTP server binary: %s", binaryName)
			serverBinaryPath = preBuiltBinaryPath
			serverBinaryNeedsCleanup = false
			return
		}

		testBinaryName := "datadog-traceroute-server"
		if runtime.GOOS == "windows" {
			testBinaryName = "datadog-traceroute-server.exe"
		}
		t.Logf("pre-built server binary not found, building test server binary: %s", testBinaryName)
		serverBinaryPath = filepath.Join(projectRoot, testBinaryName)

		t.Logf("running command: go build -o %s ./cmd/traceroute-server", testBinaryName)
		buildCmd := exec.Command("go", "build", "-o", testBinaryName, "./cmd/traceroute-server")
		buildCmd.Dir = projectRoot
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build %s: %v\nOutput: %s", testBinaryName, err, string(buildOutput))
		}

		serverBinaryNeedsCleanup = true
		// Note: Cleanup is handled in TestMain to ensure it runs after ALL tests complete,
		// not after individual subtests. This is necessary because the binary is shared
		// across multiple tests via sync.Once.
	})

	return serverBinaryPath
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
	serverProcessOnce.Do(func() {
		// First check if server is already running (i.e. when running in CI)
		if isServerRunning(serverAddr) {
			t.Logf("HTTP server is already running on %s", serverAddr)
			return
		}

		t.Logf("HTTP server not running, starting on %s", serverAddr)
		binaryPath := getServerBinaryPath(t)

		var cmd *exec.Cmd
		if runtime.GOOS != "windows" {
			t.Logf("running command: sudo %s --addr %s --log-level debug", binaryPath, serverAddr)
			cmd = exec.Command("sudo", binaryPath, "--addr", serverAddr, "--log-level", "debug")
		} else {
			t.Logf("running command: %s --addr %s --log-level debug", binaryPath, serverAddr)
			cmd = exec.Command(binaryPath, "--addr", serverAddr, "--log-level", "debug")
		}

		serverStdout = &bytes.Buffer{}
		serverStderr = &bytes.Buffer{}
		cmd.Stdout = serverStdout
		cmd.Stderr = serverStderr

		err := cmd.Start()
		if err != nil {
			t.Fatalf("failed to start HTTP server: %v", err)
		}

		t.Logf("HTTP server process started with PID: %d", cmd.Process.Pid)

		serverProcess = cmd
		// Note: Server process cleanup is handled in TestMain to ensure it runs after
		// ALL tests complete, not after individual subtests.

		// Wait for server to be ready using testify's Eventually
		// This will retry for up to 5 seconds with 500ms between attempts
		serverReady := assert.Eventually(t, func() bool {
			return isServerRunning(serverAddr)
		}, 5*time.Second, 500*time.Millisecond, "server did not become ready within timeout")

		if !serverReady {
			// Check process state
			var processInfo string
			if cmd.ProcessState != nil {
				processInfo = fmt.Sprintf("process exited: %s", cmd.ProcessState.String())
			} else {
				processInfo = "process still running but server not responding"
			}

			// Collect all available output
			stderr := ""
			if serverStderr != nil {
				stderr = serverStderr.String()
			}

			// Store the error so we can fail tests gracefully without preventing TestMain cleanup
			serverStartupError = fmt.Sprintf("server failed to start.\nProcess info: %s\nstderr: %s",
				processInfo, stderr)
			t.Fatal(serverStartupError)
			return
		}

		t.Logf("HTTP server successfully started on %s", serverAddr)
	})

	// Check if server startup failed (will be set inside sync.Once if it failed)
	if serverStartupError != "" {
		t.Fatalf("Server startup failed: %s", serverStartupError)
	}

	return serverAddr
}

// cleanupHTTPServer stops the HTTP server process and cleans up the binary if needed
func cleanupHTTPServer() {
	if serverBinaryNeedsCleanup && serverBinaryPath != "" {
		if err := os.Remove(serverBinaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to remove server binary %s: %v\n", serverBinaryPath, err)
		}
	}

	if serverProcess != nil && serverProcess.Process != nil {
		// On Linux and MacOS the process was started with sudo, so the PID we have is for the sudo process, so we
		// use pkill to kill the server by name.
		if runtime.GOOS != "windows" {
			pkillCmd := exec.Command("sudo", "pkill", "-9", "-x", "datadog-traceroute-server")
			if err := pkillCmd.Run(); err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					fmt.Fprintf(os.Stderr, "Warning: Failed to run pkill: %v\n", err)
				}
			}
		} else {
			// On Windows, just use the regular Kill() method
			if err := serverProcess.Process.Kill(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to kill server process: %v\n", err)
			}
		}
	}
}

// getURL builds the HTTP request URL for the given test configuration
func getURL(serverAddr string, config testConfig) string {
	url := fmt.Sprintf("http://%s/traceroute?target=%s&protocol=%s&tcp-method=%s&traceroute-queries=%d&e2e-queries=%d&reverse-dns=true&source-public-ip=true",
		serverAddr, config.hostname, strings.ToLower(string(config.protocol)), string(config.tcpMethod), numTraceroutes, numE2eProbes)

	if config.port > 0 {
		url += fmt.Sprintf("&port=%d", config.port)
	}
	if config.tcpMethod != "" {
		url += fmt.Sprintf("&tcp-method=%s", string(config.tcpMethod))
	}

	return url
}

// testHTTPServer runs an HTTP server traceroute test with the given configuration
func testHTTPServer(t *testing.T, config testConfig) {
	// Ensure server is running (either already running in CI or start it once)
	testServerAddr := ensureServerRunning(t)
	maxAttempts := config.getMaxAttempts(t)

	// Build the HTTP request URL
	url := getURL(testServerAddr, config)

	t.Logf("Making HTTP GET request: %s (maxAttempts=%d)", url, maxAttempts)

	var resp *http.Response
	var lastStatusCode int
	expectedError := config.expectError(t)

	// Retry loop - only retries on non-OK status codes
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			t.Logf("Retrying HTTP request (attempt %d/%d)", attempt, maxAttempts)
		}

		var err error
		resp, err = http.Get(url)

		// If HTTP request failed (connection error), fail immediately - don't retry
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}

		// Got a response - check status code
		lastStatusCode = resp.StatusCode

		// If we expect an error response, any status is acceptable (will validate later)
		if expectedError != "" || resp.StatusCode == http.StatusOK {
			break
		}

		// Got non-OK status and we didn't expect an error - retry
		t.Logf("HTTP request returned status %d on attempt %d", resp.StatusCode, attempt)

		// log response body for debugging
		var buf bytes.Buffer
		_, err = buf.ReadFrom(resp.Body)
		if err != nil {
			t.Logf("Failed to read response body on attempt %d: %v", attempt, err)
		} else {
			t.Logf("HTTP response body on attempt %d:\n%s", attempt, buf.String())
		}

		resp.Body.Close()

		// If this was the last attempt, prepare to fail
		if attempt == maxAttempts {
			// Will be handled below
			break
		}
	}

	// Check if we exhausted retries with non-OK status
	if expectedError == "" && lastStatusCode != http.StatusOK {
		resp.Body.Close()
		// Include server logs in the error message for debugging
		errMsg := fmt.Sprintf("HTTP request returned status %d after %d attempts", lastStatusCode, maxAttempts)
		if serverStderr != nil && serverStderr.Len() > 0 {
			errMsg += fmt.Sprintf("\nServer stderr: %s", serverStderr.String())
		}
		if serverStdout != nil && serverStdout.Len() > 0 {
			errMsg += fmt.Sprintf("\nServer stdout: %s", serverStdout.String())
		}
		t.Fatalf("%s", errMsg)
	}
	defer resp.Body.Close()

	if serverStderr != nil && serverStderr.Len() > 0 {
		t.Logf("datadog-traceroute HTTP server stderr:\n%s", serverStderr.String())
	}

	// If we expect an error, check for it in the HTTP response
	if expectedError != "" {
		assert.NotEqual(t, http.StatusOK, resp.StatusCode, "HTTP server should return error status for %s", config.testName())

		var buf bytes.Buffer
		_, err := buf.ReadFrom(resp.Body)
		require.NoError(t, err, "should be able to read error response body")

		assert.Contains(t, buf.String(), expectedError, "error response should contain expected string")
		return
	}

	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	require.NoError(t, err, "should be able to read response body")

	validateResults(t, buf.Bytes(), config)
}

// TestLocalhostHTTPServer runs HTTP server tests to localhost
func TestLocalhostHTTPServer(t *testing.T) {
	for _, config := range localhostTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testHTTPServer(t, config)
		})
	}
}

// TestPublicTargetHTTPServer runs HTTP server tests to a public target
func TestPublicTargetHTTPServer(t *testing.T) {
	for _, config := range publicTargetTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testHTTPServer(t, config)
		})
	}
}

// TestFakeNetworkHTTPServer runs HTTP server tests to a local IP address with a fake network config
func TestFakeNetworkHTTPServer(t *testing.T) {
	for _, config := range fakeNetworkTestConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testHTTPServer(t, config)
		})
	}
}
