use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

pub const DEFAULT_NETWORK_PATH_TIMEOUT_MS: u64 = 3000;
pub const DEFAULT_PORT: u16 = 33434;
pub const DEFAULT_TRACEROUTE_QUERIES: usize = 3;
pub const DEFAULT_NUM_E2E_PROBES: usize = 50;
pub const DEFAULT_MIN_TTL: u8 = 1;
pub const DEFAULT_MAX_TTL: u8 = 30;
pub const DEFAULT_DELAY_MS: u64 = 50;
pub const DEFAULT_PROTOCOL: &str = "udp";
pub const DEFAULT_TCP_METHOD: &str = "syn";
pub const DEFAULT_WANT_V6: bool = false;
pub const DEFAULT_REVERSE_DNS: bool = false;
pub const DEFAULT_COLLECT_SOURCE_PUBLIC_IP: bool = false;
pub const DEFAULT_USE_WINDOWS_DRIVER: bool = false;
pub const DEFAULT_SKIP_PRIVATE_HOPS: bool = false;

#[derive(Debug)]
pub struct ReceiveProbeNoPktError {
    message: String,
}

impl ReceiveProbeNoPktError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ReceiveProbeNoPktError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReceiveProbe() didn't find any new packets: {}", self.message)
    }
}

impl Error for ReceiveProbeNoPktError {}

#[derive(Debug)]
pub struct BadPacketError {
    message: String,
}

impl BadPacketError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for BadPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse packet: {}", self.message)
    }
}

impl Error for BadPacketError {}

#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub ttl: u8,
    pub ip: IpAddr,
    pub rtt: Duration,
    pub is_dest: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TracerouteDriverInfo {
    pub supports_parallel: bool,
}

pub trait TracerouteDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo;
    fn send_probe(&mut self, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>>;
    fn receive_probe(&mut self, timeout: Duration) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>>;
}

#[derive(Debug, Clone, Copy)]
pub struct TracerouteParams {
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub traceroute_timeout: Duration,
    pub poll_frequency: Duration,
    pub send_delay: Duration,
}

impl TracerouteParams {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_ttl > self.max_ttl {
            return Err("min TTL must be less than or equal to max TTL".to_string());
        }
        if self.min_ttl < 1 {
            return Err("min TTL must be at least 1".to_string());
        }
        Ok(())
    }

    pub fn validate_probe(&self, probe: &ProbeResponse) -> Result<(), String> {
        if probe.ttl < self.min_ttl || probe.ttl > self.max_ttl {
            return Err(format!(
                "ReceiveProbe() received an invalid TTL: expected TTL in [{}, {}], got {}",
                self.min_ttl, self.max_ttl, probe.ttl
            ));
        }
        Ok(())
    }

    pub fn probe_count(&self) -> usize {
        if self.min_ttl > self.max_ttl {
            return 0;
        }
        (self.max_ttl - self.min_ttl + 1) as usize
    }
}

pub fn convert_duration_to_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

pub fn is_probe_retryable(err: &(dyn Error + 'static)) -> bool {
    err.is::<ReceiveProbeNoPktError>() || err.is::<BadPacketError>()
}
