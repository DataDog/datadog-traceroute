//! End-to-end tests for datadog-traceroute CLI and HTTP server.
//!
//! These tests run the actual traceroute binary and HTTP server against real targets
//! and comprehensively verify all output fields match expected behavior.
//!
//! Test categories:
//! - CLI tests: test_localhost_* and test_public_* (via CLI binary)
//! - Server tests: test_server_* (via HTTP API)

use serde::Deserialize;
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// Test targets
const LOCALHOST_TARGET: &str = "127.0.0.1";
const PUBLIC_TARGET: &str = "github.com";
const PUBLIC_PORT: u16 = 443;

// Test parameters
const NUM_TRACEROUTE_QUERIES: usize = 3;
const DEFAULT_UDP_PORT: u16 = 33434;
const DEFAULT_TCP_PORT: u16 = 33434; // CLI default, not SSH (22) or HTTPS (443)

// Server test configuration
const SERVER_PORT: u16 = 13765; // Use non-standard port to avoid conflicts
const SERVER_STARTUP_DELAY_MS: u64 = 500;

/// Results structure matching the JSON output.
#[derive(Debug, Deserialize)]
struct Results {
    protocol: String,
    #[allow(dead_code)]
    source: Option<PublicIpInfo>,
    destination: ResultDestination,
    traceroute: TracerouteResults,
    #[allow(dead_code)]
    e2e_probe: Option<E2eProbeResults>,
}

#[derive(Debug, Deserialize)]
struct PublicIpInfo {
    #[allow(dead_code)]
    public_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResultDestination {
    hostname: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct TracerouteResults {
    runs: Vec<TracerouteRun>,
    hop_count: Option<Stats>,
}

#[derive(Debug, Deserialize)]
struct TracerouteRun {
    run_id: String,
    source: SourceInfo,
    destination: DestinationInfo,
    hops: Vec<TracerouteHop>,
}

#[derive(Debug, Deserialize)]
struct SourceInfo {
    ip_address: Option<IpAddr>,
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct DestinationInfo {
    ip_address: Option<IpAddr>,
    port: Option<u16>,
    #[serde(default)]
    #[allow(dead_code)]
    reverse_dns: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct TracerouteHop {
    ttl: u8,
    ip_address: Option<IpAddr>,
    rtt: Option<f64>,
    reachable: bool,
    #[serde(default)]
    #[allow(dead_code)]
    reverse_dns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Stats {
    avg: f64,
    min: f64,
    max: f64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct E2eProbeResults {
    rtts: Vec<f64>,
    packets_sent: u32,
    packets_received: u32,
    packet_loss_percentage: f32,
    jitter: Option<f64>,
    rtt: Option<Stats>,
}

/// Test configuration.
#[derive(Debug, Clone)]
struct TestConfig {
    hostname: String,
    port: Option<u16>,
    protocol: String,
    tcp_method: Option<String>,
    num_queries: usize,
}

impl TestConfig {
    fn test_name(&self) -> String {
        let mut name = self.protocol.clone();
        if let Some(ref method) = self.tcp_method {
            name.push('_');
            name.push_str(method);
        }
        name
    }

    fn expected_port(&self) -> u16 {
        self.port.unwrap_or(match self.protocol.as_str() {
            "tcp" => DEFAULT_TCP_PORT,
            _ => DEFAULT_UDP_PORT,
        })
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            hostname: LOCALHOST_TARGET.to_string(),
            port: None,
            protocol: "udp".to_string(),
            tcp_method: None,
            num_queries: NUM_TRACEROUTE_QUERIES,
        }
    }
}

// =============================================================================
// Binary and Server Helpers
// =============================================================================

/// Get the CLI binary path.
fn get_cli_binary() -> String {
    // Check EXECUTABLE environment variable first (set by CI)
    if let Ok(executable) = std::env::var("EXECUTABLE") {
        if std::path::Path::new(&executable).exists() {
            return executable;
        }
    }

    let binary_name = if cfg!(target_os = "windows") {
        "datadog-traceroute.exe"
    } else {
        "datadog-traceroute"
    };

    // Get workspace root from CARGO_MANIFEST_DIR (which points to the crate dir)
    // We need to go up to the workspace root
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent() // crates/
        .and_then(|p| p.parent()) // rust/
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Try release build first
    let release_path = workspace_root.join("target/release").join(binary_name);
    if release_path.exists() {
        return release_path.to_string_lossy().to_string();
    }

    // Try debug build
    let debug_path = workspace_root.join("target/debug").join(binary_name);
    if debug_path.exists() {
        return debug_path.to_string_lossy().to_string();
    }

    // Also try relative paths (for when running from workspace root)
    let release_path = format!("target/release/{}", binary_name);
    if std::path::Path::new(&release_path).exists() {
        return release_path;
    }

    let debug_path = format!("target/debug/{}", binary_name);
    if std::path::Path::new(&debug_path).exists() {
        return debug_path;
    }

    panic!(
        "CLI binary not found. Please build with 'cargo build' or 'cargo build --release' first. \
         Searched in workspace root: {:?}, EXECUTABLE env: {:?}",
        workspace_root,
        std::env::var("EXECUTABLE").ok()
    );
}

/// Get the server binary path.
fn get_server_binary() -> String {
    // Check SERVER_EXECUTABLE environment variable first (set by CI)
    if let Ok(executable) = std::env::var("SERVER_EXECUTABLE") {
        if std::path::Path::new(&executable).exists() {
            return executable;
        }
    }

    let binary_name = if cfg!(target_os = "windows") {
        "datadog-traceroute-server.exe"
    } else {
        "datadog-traceroute-server"
    };

    // Get workspace root from CARGO_MANIFEST_DIR (which points to the crate dir)
    // We need to go up to the workspace root
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent() // crates/
        .and_then(|p| p.parent()) // rust/
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Try release build first
    let release_path = workspace_root.join("target/release").join(binary_name);
    if release_path.exists() {
        return release_path.to_string_lossy().to_string();
    }

    // Try debug build
    let debug_path = workspace_root.join("target/debug").join(binary_name);
    if debug_path.exists() {
        return debug_path.to_string_lossy().to_string();
    }

    // Also try relative paths (for when running from workspace root)
    let release_path = format!("target/release/{}", binary_name);
    if std::path::Path::new(&release_path).exists() {
        return release_path;
    }

    let debug_path = format!("target/debug/{}", binary_name);
    if std::path::Path::new(&debug_path).exists() {
        return debug_path;
    }

    panic!(
        "Server binary not found. Please build with 'cargo build' or 'cargo build --release' first. \
         Searched in workspace root: {:?}, SERVER_EXECUTABLE env: {:?}",
        workspace_root,
        std::env::var("SERVER_EXECUTABLE").ok()
    );
}

/// Start the HTTP server and return the child process.
fn start_server(port: u16) -> Result<Child, String> {
    let binary = get_server_binary();
    let addr = format!("127.0.0.1:{}", port);

    let (cmd, args) = if cfg!(target_os = "windows") {
        (binary.clone(), vec!["--addr".to_string(), addr])
    } else {
        ("sudo".to_string(), vec![binary, "--addr".to_string(), addr])
    };

    let child = Command::new(&cmd)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start server: {}", e))?;

    // Give the server time to start
    std::thread::sleep(Duration::from_millis(SERVER_STARTUP_DELAY_MS));

    Ok(child)
}

/// Stop the HTTP server.
fn stop_server(mut child: Child) {
    if cfg!(target_os = "windows") {
        let _ = child.kill();
    } else {
        // On Unix, we need to kill the sudo process which will kill the server
        let _ = Command::new("sudo")
            .args(["kill", &child.id().to_string()])
            .output();
    }
    let _ = child.wait();
}

// =============================================================================
// CLI Runner
// =============================================================================

/// Run traceroute CLI and parse the output.
fn run_traceroute_cli(config: &TestConfig) -> Result<Results, String> {
    let binary = get_cli_binary();

    let mut args = vec![
        "--verbose".to_string(), // Enable debug logging
        "--traceroute-queries".to_string(),
        config.num_queries.to_string(),
        "--proto".to_string(),
        config.protocol.to_lowercase(),
    ];

    if let Some(port) = config.port {
        args.push("--port".to_string());
        args.push(port.to_string());
    }

    if let Some(ref method) = config.tcp_method {
        args.push("--tcp-method".to_string());
        args.push(method.clone());
    }

    args.push(config.hostname.clone());

    // On Unix, we need sudo for raw socket access
    let (cmd, final_args) = if cfg!(target_os = "windows") {
        (binary.clone(), args)
    } else {
        let mut sudo_args = vec![binary.clone()];
        sudo_args.extend(args);
        ("sudo".to_string(), sudo_args)
    };

    eprintln!("Running: {} {:?}", cmd, final_args);

    // Use spawn + wait_with_output to avoid blocking forever
    // Add a timeout to prevent hanging indefinitely
    let mut child = Command::new(&cmd)
        .args(&final_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn command: {}", e))?;

    eprintln!("Process spawned with PID: {:?}", child.id());

    // Wait for the process with a timeout
    use std::time::Duration;
    let timeout = Duration::from_secs(120); // 2 minute timeout per CLI invocation
    let start = std::time::Instant::now();

    let output = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process has exited
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_end(&mut stderr);
                }
                break std::process::Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                // Process still running
                if start.elapsed() > timeout {
                    eprintln!("Process timed out after {:?}, killing...", timeout);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("Process timed out after {:?}", timeout));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!("Error waiting for process: {}", e));
            }
        }
    };

    // Always print stderr for debugging
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("CLI stderr:\n{}", stderr);
    }

    if !output.status.success() {
        return Err(format!(
            "Command failed with status {}:\n{}",
            output.status, stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse JSON output: {}\nOutput: {}", e, stdout))
}

// =============================================================================
// Server Runner
// =============================================================================

/// Run traceroute via HTTP server API.
fn run_traceroute_server(config: &TestConfig, server_port: u16) -> Result<Results, String> {
    let mut url = format!(
        "http://127.0.0.1:{}/traceroute?target={}&protocol={}&queries={}",
        server_port, config.hostname, config.protocol, config.num_queries
    );

    if let Some(port) = config.port {
        url.push_str(&format!("&port={}", port));
    }

    // Use curl for HTTP request (available on all platforms)
    let output = Command::new("curl")
        .args(["-s", "-f", &url])
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "HTTP request failed:\nstderr: {}\nstdout: {}",
            stderr, stdout
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse JSON response: {}\nResponse: {}", e, stdout))
}

// =============================================================================
// Comprehensive Validation
// =============================================================================

/// Comprehensive validation of traceroute results.
fn validate_results(results: &Results, config: &TestConfig, expect_destination_reachable: bool) {
    validate_protocol(results, config);
    validate_destination(results, config);
    validate_traceroute_runs(results, config, expect_destination_reachable);
    validate_hop_count_stats(results, config);
}

/// Validate protocol field.
fn validate_protocol(results: &Results, config: &TestConfig) {
    assert_eq!(
        results.protocol.to_lowercase(),
        config.protocol.to_lowercase(),
        "Protocol should match config"
    );

    // Protocol should be one of the valid values
    let valid_protocols = ["udp", "tcp", "icmp"];
    assert!(
        valid_protocols.contains(&results.protocol.to_lowercase().as_str()),
        "Protocol '{}' should be one of {:?}",
        results.protocol,
        valid_protocols
    );
}

/// Validate destination fields.
fn validate_destination(results: &Results, config: &TestConfig) {
    // Hostname should match exactly
    assert_eq!(
        results.destination.hostname, config.hostname,
        "Destination hostname should match config"
    );

    // Port should match expected port
    let expected_port = config.expected_port();
    assert_eq!(
        results.destination.port, expected_port,
        "Destination port should match expected port"
    );
}

/// Validate all traceroute runs.
fn validate_traceroute_runs(
    results: &Results,
    config: &TestConfig,
    expect_destination_reachable: bool,
) {
    // Should have correct number of runs
    assert_eq!(
        results.traceroute.runs.len(),
        config.num_queries,
        "Should have {} traceroute runs",
        config.num_queries
    );

    for (run_idx, run) in results.traceroute.runs.iter().enumerate() {
        validate_run(run, run_idx, config, expect_destination_reachable);
    }
}

/// Validate a single traceroute run.
fn validate_run(
    run: &TracerouteRun,
    run_idx: usize,
    config: &TestConfig,
    expect_destination_reachable: bool,
) {
    // Validate run_id (should be a valid UUID format)
    validate_run_id(&run.run_id, run_idx);

    // Validate source info
    validate_source_info(&run.source, run_idx);

    // Validate destination info
    validate_destination_info(&run.destination, run_idx, config);

    // Validate hops
    validate_hops(&run.hops, run_idx, config, expect_destination_reachable);
}

/// Validate run_id is a valid UUID format.
fn validate_run_id(run_id: &str, run_idx: usize) {
    assert!(
        !run_id.is_empty(),
        "Run {} run_id should not be empty",
        run_idx
    );

    // UUID format: 8-4-4-4-12 hex characters
    let uuid_regex =
        regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .unwrap();
    assert!(
        uuid_regex.is_match(run_id),
        "Run {} run_id '{}' should be a valid UUID format",
        run_idx,
        run_id
    );
}

/// Validate source info fields.
fn validate_source_info(source: &SourceInfo, run_idx: usize) {
    // Source IP should be present
    assert!(
        source.ip_address.is_some(),
        "Run {} should have source IP address",
        run_idx
    );

    // Source port should be present and valid (1-65535)
    assert!(
        source.port.is_some(),
        "Run {} should have source port",
        run_idx
    );
    let port = source.port.unwrap();
    assert!(
        port > 0,
        "Run {} source port {} should be > 0",
        run_idx,
        port
    );
}

/// Validate destination info fields.
fn validate_destination_info(dest: &DestinationInfo, run_idx: usize, config: &TestConfig) {
    // Destination IP should be present (resolved from hostname)
    assert!(
        dest.ip_address.is_some(),
        "Run {} should have destination IP address",
        run_idx
    );

    // Destination port should match config
    let expected_port = config.expected_port();
    assert!(
        dest.port.is_some(),
        "Run {} should have destination port",
        run_idx
    );
    assert_eq!(
        dest.port.unwrap(),
        expected_port,
        "Run {} destination port should match config",
        run_idx
    );
}

/// Validate hops in a run.
fn validate_hops(
    hops: &[TracerouteHop],
    run_idx: usize,
    config: &TestConfig,
    expect_destination_reachable: bool,
) {
    // Should have at least one hop
    assert!(
        !hops.is_empty(),
        "Run {} should have at least one hop",
        run_idx
    );

    // Validate each hop
    let mut expected_ttl = 1u8;
    for (hop_idx, hop) in hops.iter().enumerate() {
        validate_hop(hop, run_idx, hop_idx, expected_ttl);
        expected_ttl += 1;
    }

    // For localhost, check destination reachability
    if expect_destination_reachable && config.hostname == LOCALHOST_TARGET {
        let last_hop = hops.last().unwrap();
        assert!(
            last_hop.reachable,
            "Run {} last hop should be reachable for localhost",
            run_idx
        );
    }
}

/// Validate a single hop.
fn validate_hop(hop: &TracerouteHop, run_idx: usize, hop_idx: usize, expected_ttl: u8) {
    // TTL should be sequential starting from 1
    assert_eq!(
        hop.ttl, expected_ttl,
        "Run {}, hop {} TTL should be {} (sequential)",
        run_idx, hop_idx, expected_ttl
    );

    // If reachable, should have IP and positive RTT
    if hop.reachable {
        assert!(
            hop.ip_address.is_some(),
            "Run {}, hop {} (TTL {}) is reachable but has no IP address",
            run_idx,
            hop_idx,
            hop.ttl
        );

        // RTT should be present and non-negative
        assert!(
            hop.rtt.is_some(),
            "Run {}, hop {} (TTL {}) is reachable but has no RTT",
            run_idx,
            hop_idx,
            hop.ttl
        );
        let rtt = hop.rtt.unwrap();
        assert!(
            rtt >= 0.0,
            "Run {}, hop {} (TTL {}) RTT {} should be non-negative",
            run_idx,
            hop_idx,
            hop.ttl,
            rtt
        );
    }
}

/// Validate hop_count statistics when multiple runs.
fn validate_hop_count_stats(results: &Results, config: &TestConfig) {
    if config.num_queries > 1 {
        // With multiple runs, hop_count stats should be present
        assert!(
            results.traceroute.hop_count.is_some(),
            "hop_count stats should be present with {} runs",
            config.num_queries
        );

        let stats = results.traceroute.hop_count.as_ref().unwrap();

        // min <= avg <= max
        assert!(
            stats.min <= stats.avg,
            "hop_count min ({}) should be <= avg ({})",
            stats.min,
            stats.avg
        );
        assert!(
            stats.avg <= stats.max,
            "hop_count avg ({}) should be <= max ({})",
            stats.avg,
            stats.max
        );

        // All values should be non-negative
        assert!(
            stats.min >= 0.0,
            "hop_count min ({}) should be non-negative",
            stats.min
        );
        assert!(
            stats.avg >= 0.0,
            "hop_count avg ({}) should be non-negative",
            stats.avg
        );
        assert!(
            stats.max >= 0.0,
            "hop_count max ({}) should be non-negative",
            stats.max
        );
    }
}

// =============================================================================
// CLI Tests - Localhost
// =============================================================================

#[test]
#[ignore] // Requires root privileges
fn test_localhost_icmp() {
    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        protocol: "icmp".to_string(),
        ..Default::default()
    };

    let results = run_traceroute_cli(&config)
        .expect(&format!("CLI test {} should succeed", config.test_name()));
    validate_results(&results, &config, true);
}

#[test]
#[ignore] // Requires root privileges
fn test_localhost_udp() {
    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        protocol: "udp".to_string(),
        ..Default::default()
    };

    let results = run_traceroute_cli(&config)
        .expect(&format!("CLI test {} should succeed", config.test_name()));
    validate_results(&results, &config, true);
}

#[test]
#[ignore] // Requires root privileges
fn test_localhost_tcp_syn() {
    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        protocol: "tcp".to_string(),
        tcp_method: Some("syn".to_string()),
        ..Default::default()
    };

    let results = run_traceroute_cli(&config)
        .expect(&format!("CLI test {} should succeed", config.test_name()));
    validate_results(&results, &config, true);
}

// =============================================================================
// CLI Tests - Public Target
// =============================================================================

#[test]
#[ignore] // Requires root privileges and network access
fn test_public_icmp() {
    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "icmp".to_string(),
        ..Default::default()
    };

    let results = run_traceroute_cli(&config)
        .expect(&format!("CLI test {} should succeed", config.test_name()));
    // Public targets may not always be reachable
    validate_results(&results, &config, false);
}

#[test]
#[ignore] // Requires root privileges and network access
fn test_public_udp() {
    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "udp".to_string(),
        ..Default::default()
    };

    let results = run_traceroute_cli(&config)
        .expect(&format!("CLI test {} should succeed", config.test_name()));
    validate_results(&results, &config, false);
}

#[test]
#[ignore] // Requires root privileges and network access
fn test_public_tcp_syn() {
    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "tcp".to_string(),
        tcp_method: Some("syn".to_string()),
        ..Default::default()
    };

    let results = run_traceroute_cli(&config)
        .expect(&format!("CLI test {} should succeed", config.test_name()));
    // TCP SYN should reach github.com:443
    validate_results(&results, &config, true);
}

// =============================================================================
// Server Tests - Localhost
// =============================================================================

#[test]
#[ignore] // Requires root privileges
fn test_server_localhost_icmp() {
    let server = start_server(SERVER_PORT).expect("Server should start");

    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        protocol: "icmp".to_string(),
        num_queries: 2, // Fewer queries for faster server tests
        ..Default::default()
    };

    let result = run_traceroute_server(&config, SERVER_PORT);
    stop_server(server);

    let results = result.expect(&format!(
        "Server test {} should succeed",
        config.test_name()
    ));
    validate_results(&results, &config, true);
}

#[test]
#[ignore] // Requires root privileges
fn test_server_localhost_udp() {
    let server = start_server(SERVER_PORT + 1).expect("Server should start");

    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        protocol: "udp".to_string(),
        num_queries: 2,
        ..Default::default()
    };

    let result = run_traceroute_server(&config, SERVER_PORT + 1);
    stop_server(server);

    let results = result.expect(&format!(
        "Server test {} should succeed",
        config.test_name()
    ));
    validate_results(&results, &config, true);
}

#[test]
#[ignore] // Requires root privileges
fn test_server_localhost_tcp() {
    let server = start_server(SERVER_PORT + 2).expect("Server should start");

    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        protocol: "tcp".to_string(),
        num_queries: 2,
        ..Default::default()
    };

    let result = run_traceroute_server(&config, SERVER_PORT + 2);
    stop_server(server);

    let results = result.expect(&format!(
        "Server test {} should succeed",
        config.test_name()
    ));
    validate_results(&results, &config, true);
}

// =============================================================================
// Server Tests - Public Target
// =============================================================================

#[test]
#[ignore] // Requires root privileges and network access
fn test_server_public_icmp() {
    let server = start_server(SERVER_PORT + 3).expect("Server should start");

    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "icmp".to_string(),
        num_queries: 2,
        ..Default::default()
    };

    let result = run_traceroute_server(&config, SERVER_PORT + 3);
    stop_server(server);

    let results = result.expect(&format!(
        "Server test {} should succeed",
        config.test_name()
    ));
    validate_results(&results, &config, false);
}

#[test]
#[ignore] // Requires root privileges and network access
fn test_server_public_udp() {
    let server = start_server(SERVER_PORT + 4).expect("Server should start");

    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "udp".to_string(),
        num_queries: 2,
        ..Default::default()
    };

    let result = run_traceroute_server(&config, SERVER_PORT + 4);
    stop_server(server);

    let results = result.expect(&format!(
        "Server test {} should succeed",
        config.test_name()
    ));
    validate_results(&results, &config, false);
}

#[test]
#[ignore] // Requires root privileges and network access
fn test_server_public_tcp() {
    let server = start_server(SERVER_PORT + 5).expect("Server should start");

    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "tcp".to_string(),
        num_queries: 2,
        ..Default::default()
    };

    let result = run_traceroute_server(&config, SERVER_PORT + 5);
    stop_server(server);

    let results = result.expect(&format!(
        "Server test {} should succeed",
        config.test_name()
    ));
    validate_results(&results, &config, true);
}

// =============================================================================
// Server Health Check Test
// =============================================================================

#[test]
#[ignore] // Requires root privileges
fn test_server_health_endpoint() {
    let server = start_server(SERVER_PORT + 6).expect("Server should start");

    let url = format!("http://127.0.0.1:{}/health", SERVER_PORT + 6);
    let output = Command::new("curl")
        .args(["-s", "-f", &url])
        .output()
        .expect("curl should succeed");

    stop_server(server);

    assert!(output.status.success(), "Health endpoint should return 200");
    let body = String::from_utf8_lossy(&output.stdout);
    assert_eq!(body.trim(), "ok", "Health endpoint should return 'ok'");
}

// =============================================================================
// Unit Tests (no root required)
// =============================================================================

#[test]
fn test_json_parsing_full() {
    let json = r#"{
        "protocol": "udp",
        "source": {"public_ip": "1.2.3.4"},
        "destination": {"hostname": "example.com", "port": 33434},
        "traceroute": {
            "runs": [{
                "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "source": {"ip_address": "192.168.1.1", "port": 12345},
                "destination": {"ip_address": "8.8.8.8", "port": 33434, "reverse_dns": []},
                "hops": [
                    {"ttl": 1, "ip_address": "192.168.1.254", "rtt": 1.5, "reachable": true, "reverse_dns": []},
                    {"ttl": 2, "ip_address": "10.0.0.1", "rtt": 5.2, "reachable": true, "reverse_dns": []},
                    {"ttl": 3, "ip_address": null, "rtt": null, "reachable": false, "reverse_dns": []},
                    {"ttl": 4, "ip_address": "8.8.8.8", "rtt": 15.3, "reachable": true, "reverse_dns": ["dns.google"]}
                ]
            }],
            "hop_count": null
        }
    }"#;

    let results: Results = serde_json::from_str(json).expect("Failed to parse JSON");

    // Validate parsed fields
    assert_eq!(results.protocol, "udp");
    assert_eq!(results.destination.hostname, "example.com");
    assert_eq!(results.destination.port, 33434);
    assert_eq!(results.traceroute.runs.len(), 1);

    let run = &results.traceroute.runs[0];
    assert_eq!(run.run_id, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    assert!(run.source.ip_address.is_some());
    assert_eq!(run.source.port, Some(12345));
    assert!(run.destination.ip_address.is_some());
    assert_eq!(run.destination.port, Some(33434));

    // Validate hops
    assert_eq!(run.hops.len(), 4);
    assert_eq!(run.hops[0].ttl, 1);
    assert!(run.hops[0].reachable);
    assert!(run.hops[0].rtt.is_some());
    assert_eq!(run.hops[2].ttl, 3);
    assert!(!run.hops[2].reachable);
    assert!(run.hops[2].ip_address.is_none());
}

#[test]
fn test_json_parsing_with_hop_count_stats() {
    let json = r#"{
        "protocol": "tcp",
        "destination": {"hostname": "test.com", "port": 443},
        "traceroute": {
            "runs": [
                {
                    "run_id": "11111111-1111-1111-1111-111111111111",
                    "source": {"ip_address": "192.168.1.1", "port": 10000},
                    "destination": {"ip_address": "1.2.3.4", "port": 443},
                    "hops": [{"ttl": 1, "ip_address": "192.168.1.1", "rtt": 1.0, "reachable": true}]
                },
                {
                    "run_id": "22222222-2222-2222-2222-222222222222",
                    "source": {"ip_address": "192.168.1.1", "port": 10001},
                    "destination": {"ip_address": "1.2.3.4", "port": 443},
                    "hops": [{"ttl": 1, "ip_address": "192.168.1.1", "rtt": 2.0, "reachable": true}]
                }
            ],
            "hop_count": {"avg": 5.5, "min": 4.0, "max": 7.0}
        }
    }"#;

    let results: Results = serde_json::from_str(json).expect("Failed to parse JSON");

    assert_eq!(results.traceroute.runs.len(), 2);
    assert!(results.traceroute.hop_count.is_some());

    let stats = results.traceroute.hop_count.as_ref().unwrap();
    assert_eq!(stats.avg, 5.5);
    assert_eq!(stats.min, 4.0);
    assert_eq!(stats.max, 7.0);
}

#[test]
fn test_validate_uuid_format() {
    // Valid UUIDs
    let valid_uuids = [
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ];

    let uuid_regex =
        regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .unwrap();

    for uuid in &valid_uuids {
        assert!(uuid_regex.is_match(uuid), "UUID '{}' should be valid", uuid);
    }

    // Invalid UUIDs
    let invalid_uuids = [
        "",
        "not-a-uuid",
        "a1b2c3d4-e5f6-7890-abcd",                    // Too short
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890-extra", // Too long
        "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",       // Uppercase (should be lowercase)
    ];

    for uuid in &invalid_uuids {
        assert!(
            !uuid_regex.is_match(uuid),
            "UUID '{}' should be invalid",
            uuid
        );
    }
}
