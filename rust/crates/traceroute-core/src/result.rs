//! Result types for traceroute output.
//!
//! These types match the JSON output format of the Go implementation
//! to maintain API compatibility.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A single hop in a traceroute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    /// The TTL for this hop.
    pub ttl: u8,
    /// The IP address that responded (None if no response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<IpAddr>,
    /// Round-trip time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt: Option<f64>,
    /// Whether this hop was reachable.
    pub reachable: bool,
    /// Reverse DNS names for this hop.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_dns: Vec<String>,
}

/// Source information for a traceroute run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Source IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<IpAddr>,
    /// Source port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Destination information for a traceroute run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationInfo {
    /// Destination IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<IpAddr>,
    /// Destination port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Reverse DNS names for the destination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_dns: Vec<String>,
}

/// A single traceroute run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteRun {
    /// Unique identifier for this run.
    pub run_id: String,
    /// Source information.
    pub source: SourceInfo,
    /// Destination information.
    pub destination: DestinationInfo,
    /// The hops discovered in this run.
    pub hops: Vec<TracerouteHop>,
}

/// Statistics for numeric values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    /// Average value.
    pub avg: f64,
    /// Minimum value.
    pub min: f64,
    /// Maximum value.
    pub max: f64,
}

/// Aggregated traceroute results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResults {
    /// Individual traceroute runs.
    pub runs: Vec<TracerouteRun>,
    /// Hop count statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_count: Option<Stats>,
}

/// End-to-end probe results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eProbeResults {
    /// Individual RTT measurements.
    pub rtts: Vec<f64>,
    /// Number of packets sent.
    pub packets_sent: u32,
    /// Number of packets received.
    pub packets_received: u32,
    /// Packet loss percentage.
    pub packet_loss_percentage: f32,
    /// Jitter (RTT variance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter: Option<f64>,
    /// RTT statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt: Option<Stats>,
}

/// Public IP information for the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIpInfo {
    /// The public IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
}

/// High-level destination info for the results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultDestination {
    /// Target hostname.
    pub hostname: String,
    /// Target port.
    pub port: u16,
}

/// Complete traceroute results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Results {
    /// Protocol used.
    pub protocol: String,
    /// Source public IP information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PublicIpInfo>,
    /// Destination information.
    pub destination: ResultDestination,
    /// Traceroute results.
    pub traceroute: TracerouteResults,
    /// End-to-end probe results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2e_probe: Option<E2eProbeResults>,
}

impl Results {
    /// Serializes the results to JSON with indentation.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serializes the results to compact JSON.
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_results_serialization() {
        let results = Results {
            protocol: "udp".to_string(),
            source: Some(PublicIpInfo {
                public_ip: Some("1.2.3.4".to_string()),
            }),
            destination: ResultDestination {
                hostname: "example.com".to_string(),
                port: 33434,
            },
            traceroute: TracerouteResults {
                runs: vec![],
                hop_count: None,
            },
            e2e_probe: None,
        };

        let json = results.to_json().unwrap();
        assert!(json.contains("\"protocol\": \"udp\""));
        assert!(json.contains("\"hostname\": \"example.com\""));
    }
}
