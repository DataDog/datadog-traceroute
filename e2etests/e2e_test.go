// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build e2etest

package e2etests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	localhostTarget = "127.0.0.1"

	publicTarget = "github.com"
	publicPort   = 443

	// JMW fakeNetworkTarget --> fakeNetworkDestination? OR fakeNetworkTarget?
	fakeNetworkTarget = "198.51.100.2"
)

var (
	// CLI binary state for reuse across tests
	cliBinaryPath         string
	cliBinaryOnce         sync.Once
	cliBinaryNeedsCleanup bool

	// HTTP server binary state for reuse across tests
	serverBinaryPath         string
	serverBinaryOnce         sync.Once
	serverBinaryNeedsCleanup bool

	// HTTP server process state for reuse across tests
	serverProcess     *exec.Cmd
	serverProcessOnce sync.Once
	serverAddr        = "127.0.0.1:3765"
)

// isGitHubRunner returns true if running on GitHub Actions
// Checks both GITHUB_ACTIONS and CI environment variables since sudo may not preserve GITHUB_ACTIONS
func isGitHubRunner() bool {
	githubActions := os.Getenv("GITHUB_ACTIONS")
	ci := os.Getenv("CI")
	githubWorkflow := os.Getenv("GITHUB_WORKFLOW")

	// GITHUB_ACTIONS is the most specific, but may be lost with sudo
	// CI is set by most CI systems including GitHub Actions
	// GITHUB_WORKFLOW is another GitHub-specific variable that might be preserved
	result := githubActions == "true" || (ci == "true" && githubWorkflow != "")

	// Debug log to help diagnose environment detection issues
	fmt.Printf("DEBUG isGitHubRunner: GITHUB_ACTIONS=%q, CI=%q, GITHUB_WORKFLOW=%q, result=%v\n",
		githubActions, ci, githubWorkflow, result)

	return result
}

// reachabilityKey defines the conditions for looking up test expectations on GitHub runners
type reachabilityKey struct {
	os        string
	hostname  string
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

// testExpectations defines what to expect from a test run
type testExpectations struct {
	destinationReachable bool
	intermediateHops     bool
	expectedError        string
}

// reachabilityMap defines test expectations for different combinations when running on GitHub
// The key combines: OS, hostname, protocol, and TCP method
var reachabilityMap = map[reachabilityKey]testExpectations{
	{"linux", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"linux", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"linux", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"linux", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"linux", fakeNetworkTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"linux", fakeNetworkTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"linux", fakeNetworkTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true, expectedError: ""},

	{"darwin", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"darwin", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true, expectedError: ""},

	{"darwin", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: true, intermediateHops: true, expectedError: ""},
	{"darwin", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: true, expectedError: ""},

	{"windows", localhostTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", localhostTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"windows", localhostTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},

	{"windows", publicTarget, traceroute.ProtocolICMP, ""}:                            {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"windows", publicTarget, traceroute.ProtocolUDP, ""}:                             {destinationReachable: false, intermediateHops: false, expectedError: ""},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSYN}:        {destinationReachable: true, intermediateHops: false, expectedError: ""},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigSACK}:       {destinationReachable: false, intermediateHops: false, expectedError: "SACK not supported for this target/source"},
	{"windows", publicTarget, traceroute.ProtocolTCP, traceroute.TCPConfigPreferSACK}: {destinationReachable: true, intermediateHops: false, expectedError: ""},
}

// TestMain runs before all tests and cleans up after all tests complete
func TestMain(m *testing.M) {
	// Run all tests
	exitCode := m.Run()

	// Cleanup binaries if they were built
	cleanupCLIBinary()
	cleanupServerBinary()
	cleanupServerProcess()

	// Exit with the test result code
	os.Exit(exitCode)
}

// testConfig holds configuration for running traceroute tests
type testConfig struct {
	hostname  string
	port      int
	protocol  traceroute.Protocol
	tcpMethod traceroute.TCPMethod
}

// expectIntermediateHops returns whether to expect intermediate hops based on
// the target, protocol, OS, and whether running on GitHub Actions
func (tc *testConfig) expectIntermediateHops(t *testing.T) bool {
	t.Helper()

	// Not on GitHub runner: expect intermediate hops for all OSes and protocols, except for localhost target
	if !isGitHubRunner() {
		if tc.hostname == localhostTarget {
			return false
		}
		return true
	}

	// On GitHub: look up in the reachability map
	expectations := tc.getGitHubExpectations(t)
	return expectations.intermediateHops
}

// expectDestinationReachable returns whether to expect the destination to be reachable
// based on the target, protocol, OS, and whether running on GitHub Actions
func (tc *testConfig) expectDestinationReachable(t *testing.T) bool {
	t.Helper()

	// Not on GitHub: always reachable except for TCP SACK on Linux and Windows
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				return false
			}
		}
		return true
	}

	// On GitHub: look up in the reachability map
	expectations := tc.getGitHubExpectations(t)
	return expectations.destinationReachable
}

// expectError returns the expected error message for this test configuration
// Returns empty string if no error is expected
func (tc *testConfig) expectError(t *testing.T) string {
	t.Helper()

	var expectedError string

	// Not on GitHub: TCP SACK fails on Linux and Windows with known error
	if !isGitHubRunner() {
		if tc.protocol == traceroute.ProtocolTCP && tc.tcpMethod == traceroute.TCPConfigSACK {
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				expectedError = "SACK not supported for this target/source"
			}
		}
	} else {
		// On GitHub: look up in the reachability map
		expectations := tc.getGitHubExpectations(t)
		expectedError = expectations.expectedError
	}

	t.Logf("expectError: config={hostname=%s, protocol=%s, tcpMethod=%s}, onGitHub=%v, OS=%s, expectedError=%q",
		tc.hostname, tc.protocol, tc.tcpMethod, isGitHubRunner(), runtime.GOOS, expectedError)

	return expectedError
}

// getGitHubExpectations returns the test expectations for GitHub runner environments
// Fails the test if the configuration is not found in the map
func (tc *testConfig) getGitHubExpectations(t *testing.T) testExpectations {
	t.Helper()

	key := reachabilityKey{
		os:        runtime.GOOS,
		hostname:  tc.hostname,
		protocol:  tc.protocol,
		tcpMethod: tc.tcpMethod,
	}

	expectations, found := reachabilityMap[key]
	if !found {
		t.Fatalf("Missing test configuration in reachabilityMap for: OS=%s, hostname=%s, protocol=%s, tcpMethod=%s",
			runtime.GOOS, tc.hostname, tc.protocol, tc.tcpMethod)
	}

	t.Logf("getGitHubExpectations: key={OS=%s, hostname=%s, protocol=%s, tcpMethod=%s}, expectations={destinationReachable=%v, intermediateHops=%v, expectedError=%q}",
		key.os, key.hostname, key.protocol, key.tcpMethod,
		expectations.destinationReachable, expectations.intermediateHops, expectations.expectedError)

	return expectations
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
		Protocol:          strings.ToLower(string(config.protocol)),
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

	// If we expect an error, check for it
	expectedError := config.expectError(t)
	if expectedError != "" {
		require.Error(t, err, "%s traceroute to %s should fail", config.testName(), config.hostname)
		assert.Contains(t, err.Error(), expectedError, "error message should contain expected string")
		return
	}

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
			config.hostname = localhostTarget
			config.port = 0
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
			config.hostname = publicTarget
			config.port = publicPort
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
			config.hostname = publicTarget
			config.port = publicPort
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
			config.hostname = publicTarget
			config.port = publicPort
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
			config.hostname = publicTarget
			config.port = publicPort
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
			config.hostname = fakeNetworkTarget
			config.port = 0
			testCommon(t, config)
		})
	}
}

// getCLIBinaryPath returns the path to the CLI binary, building it if necessary
func getCLIBinaryPath(t *testing.T) string {
	t.Helper()

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

		testBinaryName := "datadog-traceroute-test"
		if runtime.GOOS == "windows" {
			testBinaryName = "datadog-traceroute-test.exe"
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
	if cliBinaryNeedsCleanup && cliBinaryPath != "" {
		os.Remove(cliBinaryPath)
	}
}

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
		testBinaryName := "datadog-traceroute-server-test"
		if runtime.GOOS == "windows" {
			testBinaryName = "datadog-traceroute-server-test.exe"
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
	conn, err := http.Get(fmt.Sprintf("http://%s/health", addr))
	if err != nil {
		return false
	}
	conn.Body.Close()
	return conn.StatusCode == http.StatusOK
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

		cmd := exec.Command(binaryPath, "--addr", serverAddr, "--log-level", "error")

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

func cleanupServerProcess() {
	if serverProcess != nil && serverProcess.Process != nil {
		serverProcess.Process.Kill()
		serverProcess.Wait()
	}
}

// JMWTHU split intop two files, cli_test.go and http_test.go
func testCLI(t *testing.T, config testConfig) {
	//JMWt.Helper()

	binaryPath := getCLIBinaryPath(t)

	args := []string{
		"--e2e-queries", "10",
		//"--max-ttl", "5", //JMWRM?
		"--proto", strings.ToLower(string(config.protocol)),
		//"--timeout", "500", //JMWRM?
		"--traceroute-queries", "3",
		// JMW more args?
	}
	//JMW--reverse-dns              Enrich IPs with Reverse DNS names
	//JMW--skip-private-hops        Skip private hops
	//JMW--source-public-ip         Enrich with Source Public IP
	//JMW--windows-driver           Use Windows driver for traceroute (Windows only)

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

// TestLocalhostCLI runs CLI tests to localhost for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestLocalhostCLI(t *testing.T) {
	testConfigs := []testConfig{
		{
			hostname: localhostTarget,
			protocol: traceroute.ProtocolICMP,
		},
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
	}

	for _, config := range testConfigs {
		t.Run(config.testName(), func(t *testing.T) {
			testCLI(t, config)
		})
	}
}

// TestPublicEndpointCLI runs CLI tests to a public endpoint for all protocols
// In CI this will run on Linux, MacOS, and Windows
func TestPublicTargetCLI(t *testing.T) {
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
			testCLI(t, config)
		})
	}
}

// TestFakeNetworkCLI runs CLI tests to JMW a public endpoint for all protocols
// In CI this will run on Linux
func TestFakeNetworkCLI(t *testing.T) {
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
			testCLI(t, config)
		})
	}
}

// testHTTPServer runs an HTTP server traceroute test with the given configuration
func testHTTPServer(t *testing.T, config testConfig) {
	t.Helper()

	// Ensure server is running (either already running in CI or start it once)
	testServerAddr := ensureServerRunning(t)

	// Build the HTTP request URL
	url := fmt.Sprintf("http://%s/traceroute?target=%s&protocol=%s&max-ttl=5&traceroute-queries=3&e2e-queries=10&timeout=500",
		testServerAddr, config.hostname, strings.ToLower(string(config.protocol)))

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

// validateResults validates traceroute results
func validateResults(t *testing.T, results *result.Results, config testConfig) {
	t.Helper()

	t.Logf("Validating results with testConfig %+v expectDestinationReachable %v expectIntermediateHops=%v expectedError=%s",
		config, config.expectDestinationReachable(t), config.expectIntermediateHops(t), config.expectError(t))

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
		if config.expectIntermediateHops(t) {
			minReachableHops = 2
		}
		assert.GreaterOrEqual(t, reachableCount, minReachableHops, "run %d should have at least %d reachable hop(s)", i, minReachableHops)

		// Validate that the last hop is the destination and is reachable (if we expect it to be)
		if config.expectDestinationReachable(t) {
			lastHop := run.Hops[len(run.Hops)-1]
			assert.True(t, lastHop.Reachable, "run %d last hop should be reachable", i)
			assert.NotNil(t, lastHop.IPAddress, "run %d last hop should have an IP address", i)
			assert.Greater(t, lastHop.RTT, 0.0, "run %d last hop should have positive RTT", i)

			// Verify the last hop IP matches the run's destination IP
			assert.True(t, lastHop.IPAddress.Equal(run.Destination.IPAddress),
				"run %d last hop IP should match run destination IP", i)
		}

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
