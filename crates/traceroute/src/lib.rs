use datadog_traceroute_result::Results;
use std::error::Error;
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TracerouteParams {
    pub hostname: String,
    pub port: u16,
    pub protocol: String,
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub delay_ms: u64,
    pub timeout: Duration,
    pub tcp_method: String,
    pub want_v6: bool,
    pub tcp_syn_paris_traceroute_mode: bool,
    pub reverse_dns: bool,
    pub collect_source_public_ip: bool,
    pub traceroute_queries: usize,
    pub e2e_queries: usize,
    pub use_windows_driver: bool,
    pub skip_private_hops: bool,
}

#[derive(Debug, Default)]
pub struct Traceroute;

impl Traceroute {
    pub fn new() -> Self {
        Self
    }

    pub fn run_traceroute(&self, _params: TracerouteParams) -> Result<Results, TracerouteError> {
        Err(TracerouteError::new(
            "traceroute core is not yet implemented",
        ))
    }
}

#[derive(Debug)]
pub struct TracerouteError {
    message: String,
}

impl TracerouteError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TracerouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for TracerouteError {}
