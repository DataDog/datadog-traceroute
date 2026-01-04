//! Core types for traceroute operations.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Response from a single probe.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// The TTL that was used for this probe.
    pub ttl: u8,
    /// The IP address that responded.
    pub ip: IpAddr,
    /// Round-trip time for this probe.
    pub rtt: Duration,
    /// Whether this response came from the destination.
    pub is_dest: bool,
}

/// Parameters for traceroute execution.
#[derive(Debug, Clone)]
pub struct TracerouteParams {
    /// Minimum TTL to start with.
    pub min_ttl: u8,
    /// Maximum TTL to probe.
    pub max_ttl: u8,
    /// Timeout for each probe.
    pub timeout: Duration,
    /// How often to poll for responses in parallel mode.
    pub poll_frequency: Duration,
    /// Delay between sending probes.
    pub send_delay: Duration,
}

impl Default for TracerouteParams {
    fn default() -> Self {
        Self {
            min_ttl: 1,
            max_ttl: 30,
            timeout: Duration::from_millis(3000),
            poll_frequency: Duration::from_millis(100),
            send_delay: Duration::from_millis(50),
        }
    }
}

impl TracerouteParams {
    /// Validates the parameters.
    pub fn validate(&self) -> Result<(), crate::TracerouteError> {
        if self.min_ttl > self.max_ttl {
            return Err(crate::TracerouteError::InvalidTtlRange {
                min_ttl: self.min_ttl,
                max_ttl: self.max_ttl,
            });
        }
        Ok(())
    }

    /// Calculate the maximum timeout for parallel execution.
    pub fn max_timeout(&self) -> Duration {
        let num_ttls = (self.max_ttl - self.min_ttl + 1) as u32;
        self.send_delay * num_ttls + self.timeout
    }
}

/// Protocol to use for traceroute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Udp,
    Tcp,
    Icmp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp => write!(f, "udp"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Icmp => write!(f, "icmp"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = crate::TracerouteError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            "icmp" => Ok(Protocol::Icmp),
            _ => Err(crate::TracerouteError::UnknownProtocol(s.to_string())),
        }
    }
}

/// TCP method to use for TCP traceroute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpMethod {
    /// Standard TCP SYN traceroute.
    #[default]
    Syn,
    /// TCP SACK-based traceroute.
    Sack,
    /// Try SACK first, fall back to SYN if not supported.
    PreferSack,
    /// Use socket options (Windows-specific fallback).
    SynSocket,
}

impl std::fmt::Display for TcpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpMethod::Syn => write!(f, "syn"),
            TcpMethod::Sack => write!(f, "sack"),
            TcpMethod::PreferSack => write!(f, "prefer_sack"),
            TcpMethod::SynSocket => write!(f, "syn_socket"),
        }
    }
}

impl std::str::FromStr for TcpMethod {
    type Err = crate::TracerouteError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "syn" => Ok(TcpMethod::Syn),
            "sack" => Ok(TcpMethod::Sack),
            "prefer_sack" => Ok(TcpMethod::PreferSack),
            "syn_socket" => Ok(TcpMethod::SynSocket),
            _ => Err(crate::TracerouteError::UnknownProtocol(format!(
                "unknown TCP method: {}",
                s
            ))),
        }
    }
}

/// High-level traceroute configuration.
#[derive(Debug, Clone)]
pub struct TracerouteConfig {
    /// Target hostname or IP address.
    pub hostname: String,
    /// Destination port.
    pub port: u16,
    /// Protocol to use.
    pub protocol: Protocol,
    /// Traceroute parameters.
    pub params: TracerouteParams,
    /// TCP method (only used when protocol is TCP).
    pub tcp_method: TcpMethod,
    /// Whether to use IPv6.
    pub want_v6: bool,
    /// Whether to perform reverse DNS lookups.
    pub reverse_dns: bool,
    /// Whether to collect source public IP.
    pub collect_source_public_ip: bool,
    /// Number of traceroute queries to run.
    pub traceroute_queries: usize,
    /// Number of end-to-end probes to run.
    pub e2e_queries: usize,
    /// Whether to use the Windows driver (Windows only).
    pub use_windows_driver: bool,
    /// Whether to skip private hops in output.
    pub skip_private_hops: bool,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            port: 33434,
            protocol: Protocol::Udp,
            params: TracerouteParams::default(),
            tcp_method: TcpMethod::Syn,
            want_v6: false,
            reverse_dns: false,
            collect_source_public_ip: false,
            traceroute_queries: 3,
            e2e_queries: 50,
            use_windows_driver: false,
            skip_private_hops: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traceroute_params_validate() {
        let valid = TracerouteParams {
            min_ttl: 1,
            max_ttl: 30,
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let invalid = TracerouteParams {
            min_ttl: 30,
            max_ttl: 1,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("udp".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("ICMP".parse::<Protocol>().unwrap(), Protocol::Icmp);
        assert!("invalid".parse::<Protocol>().is_err());
    }
}
