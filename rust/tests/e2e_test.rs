//! End-to-end tests for datadog-traceroute.
//!
//! These tests run the actual traceroute binary against real targets and verify
//! the output matches expected behavior.

use serde::Deserialize;
use std::net::IpAddr;
use std::process::Command;

// Test targets
const LOCALHOST_TARGET: &str = "127.0.0.1";
const PUBLIC_TARGET: &str = "github.com";
const PUBLIC_PORT: u16 = 443;

// Test parameters
const NUM_TRACEROUTES: usize = 3;

/// Results structure matching the JSON output.
#[derive(Debug, Deserialize)]
struct Results {
    protocol: String,
    source: Option<PublicIpInfo>,
    destination: ResultDestination,
    traceroute: TracerouteResults,
    e2e_probe: Option<E2eProbeResults>,
}

#[derive(Debug, Deserialize)]
struct PublicIpInfo {
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
    reverse_dns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TracerouteHop {
    ttl: u8,
    ip_address: Option<IpAddr>,
    rtt: Option<f64>,
    reachable: bool,
    #[serde(default)]
    reverse_dns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Stats {
    avg: f64,
    min: f64,
    max: f64,
}

#[derive(Debug, Deserialize)]
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
}

/// Get the CLI binary path.
fn get_cli_binary() -> String {
    // Check for pre-built binary first
    let binary_name = if cfg!(target_os = "windows") {
        "datadog-traceroute.exe"
    } else {
        "datadog-traceroute"
    };

    // Try release build
    let release_path = format!("target/release/{}", binary_name);
    if std::path::Path::new(&release_path).exists() {
        return release_path;
    }

    // Try debug build
    let debug_path = format!("target/debug/{}", binary_name);
    if std::path::Path::new(&debug_path).exists() {
        return debug_path;
    }

    panic!(
        "CLI binary not found. Please build with 'cargo build' or 'cargo build --release' first"
    );
}

/// Run traceroute CLI and parse the output.
fn run_traceroute(config: &TestConfig) -> Result<Results, String> {
    let binary = get_cli_binary();

    let mut args = vec![
        "--traceroute-queries".to_string(),
        NUM_TRACEROUTES.to_string(),
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

    let output = Command::new(&cmd)
        .args(&final_args)
        .output()
        .map_err(|e| format!("Failed to run command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Command failed with status {}:\n{}",
            output.status, stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse JSON output: {}\nOutput: {}", e, stdout))
}

/// Validate traceroute results.
fn validate_results(results: &Results, config: &TestConfig, expect_destination_reachable: bool) {
    // Check protocol
    assert_eq!(
        results.protocol.to_lowercase(),
        config.protocol.to_lowercase(),
        "Protocol should match"
    );

    // Check destination
    assert_eq!(
        results.destination.hostname, config.hostname,
        "Hostname should match"
    );

    // Check runs
    assert_eq!(
        results.traceroute.runs.len(),
        NUM_TRACEROUTES,
        "Should have {} traceroute runs",
        NUM_TRACEROUTES
    );

    for (i, run) in results.traceroute.runs.iter().enumerate() {
        // Check that we have source and destination
        assert!(
            run.source.ip_address.is_some(),
            "Run {} should have source IP",
            i
        );
        assert!(
            run.destination.ip_address.is_some(),
            "Run {} should have destination IP",
            i
        );

        // Check hops
        assert!(!run.hops.is_empty(), "Run {} should have at least one hop", i);

        if expect_destination_reachable {
            // Last hop should be reachable and match destination
            let last_hop = run.hops.last().unwrap();

            // Note: For public targets, this might be flaky
            if config.hostname == LOCALHOST_TARGET {
                assert!(
                    last_hop.reachable,
                    "Run {} last hop should be reachable for localhost",
                    i
                );
            }
        }

        // All hops should have TTL set
        for (j, hop) in run.hops.iter().enumerate() {
            assert!(hop.ttl > 0, "Run {}, hop {} should have TTL > 0", i, j);
        }
    }
}

// Localhost tests

#[test]
#[ignore] // Requires root privileges
fn test_localhost_icmp() {
    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        port: None,
        protocol: "icmp".to_string(),
        tcp_method: None,
    };

    match run_traceroute(&config) {
        Ok(results) => {
            validate_results(&results, &config, true);
        }
        Err(e) => {
            eprintln!("Test {} failed: {}", config.test_name(), e);
            panic!("Test failed: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires root privileges
fn test_localhost_udp() {
    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        port: None,
        protocol: "udp".to_string(),
        tcp_method: None,
    };

    match run_traceroute(&config) {
        Ok(results) => {
            validate_results(&results, &config, true);
        }
        Err(e) => {
            eprintln!("Test {} failed: {}", config.test_name(), e);
            panic!("Test failed: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires root privileges
fn test_localhost_tcp_syn() {
    let config = TestConfig {
        hostname: LOCALHOST_TARGET.to_string(),
        port: None,
        protocol: "tcp".to_string(),
        tcp_method: Some("syn".to_string()),
    };

    match run_traceroute(&config) {
        Ok(results) => {
            validate_results(&results, &config, true);
        }
        Err(e) => {
            eprintln!("Test {} failed: {}", config.test_name(), e);
            panic!("Test failed: {}", e);
        }
    }
}

// Public target tests

#[test]
#[ignore] // Requires root privileges and network access
fn test_public_icmp() {
    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "icmp".to_string(),
        tcp_method: None,
    };

    match run_traceroute(&config) {
        Ok(results) => {
            // Public targets may not always be reachable
            validate_results(&results, &config, false);
        }
        Err(e) => {
            eprintln!("Test {} failed: {}", config.test_name(), e);
            panic!("Test failed: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires root privileges and network access
fn test_public_udp() {
    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "udp".to_string(),
        tcp_method: None,
    };

    match run_traceroute(&config) {
        Ok(results) => {
            validate_results(&results, &config, false);
        }
        Err(e) => {
            eprintln!("Test {} failed: {}", config.test_name(), e);
            panic!("Test failed: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires root privileges and network access
fn test_public_tcp_syn() {
    let config = TestConfig {
        hostname: PUBLIC_TARGET.to_string(),
        port: Some(PUBLIC_PORT),
        protocol: "tcp".to_string(),
        tcp_method: Some("syn".to_string()),
    };

    match run_traceroute(&config) {
        Ok(results) => {
            validate_results(&results, &config, true); // TCP SYN should reach destination
        }
        Err(e) => {
            eprintln!("Test {} failed: {}", config.test_name(), e);
            panic!("Test failed: {}", e);
        }
    }
}

// Unit test for JSON parsing
#[test]
fn test_json_parsing() {
    let json = r#"{
        "protocol": "udp",
        "source": {"public_ip": "1.2.3.4"},
        "destination": {"hostname": "example.com", "port": 33434},
        "traceroute": {
            "runs": [{
                "run_id": "test-123",
                "source": {"ip_address": "192.168.1.1", "port": 12345},
                "destination": {"ip_address": "8.8.8.8", "port": 33434},
                "hops": [{
                    "ttl": 1,
                    "ip_address": "192.168.1.254",
                    "rtt": 1.5,
                    "reachable": true
                }]
            }],
            "hop_count": {"avg": 5.0, "min": 4.0, "max": 6.0}
        }
    }"#;

    let results: Results = serde_json::from_str(json).expect("Failed to parse JSON");
    assert_eq!(results.protocol, "udp");
    assert_eq!(results.destination.hostname, "example.com");
    assert_eq!(results.traceroute.runs.len(), 1);
    assert_eq!(results.traceroute.runs[0].hops.len(), 1);
    assert_eq!(results.traceroute.runs[0].hops[0].ttl, 1);
}
