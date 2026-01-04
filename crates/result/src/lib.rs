use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Results {
    pub protocol: String,
    pub source: Source,
    pub destination: Destination,
    pub traceroute: Traceroute,
    pub e2e_probe: E2eProbe,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct E2eProbe {
    pub rtts: Vec<f64>,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percentage: f32,
    pub jitter: f64,
    pub rtt: E2eProbeRtt,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct E2eProbeRtt {
    pub avg: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopCountStats {
    pub avg: f64,
    pub min: usize,
    pub max: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Traceroute {
    pub runs: Vec<TracerouteRun>,
    pub hop_count: HopCountStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracerouteRun {
    pub run_id: String,
    pub source: TracerouteSource,
    pub destination: TracerouteDestination,
    pub hops: Vec<TracerouteHop>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub ttl: u16,
    pub ip_address: SerdeIpAddr,
    pub rtt: f64,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_dns: Vec<String>,

    #[serde(skip)]
    pub is_dest: bool,
    #[serde(skip)]
    pub port: u16,
    #[serde(skip)]
    pub icmp_type: u8,
    #[serde(skip)]
    pub icmp_code: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracerouteSource {
    pub ip_address: SerdeIpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracerouteDestination {
    pub ip_address: SerdeIpAddr,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_dns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Destination {
    pub hostname: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Source {
    pub public_ip: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SerdeIpAddr(pub Option<IpAddr>);

impl SerdeIpAddr {
    pub fn empty() -> Self {
        Self(None)
    }
}

impl Serialize for SerdeIpAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            Some(ip) => serializer.serialize_str(&ip.to_string()),
            None => serializer.serialize_str(""),
        }
    }
}

impl<'de> Deserialize<'de> for SerdeIpAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Self(None));
        }
        let ip = s
            .parse::<IpAddr>()
            .map_err(serde::de::Error::custom)?;
        Ok(Self(Some(ip)))
    }
}

impl Results {
    pub fn normalize(&mut self) {
        self.normalize_traceroute_runs();
        self.normalize_traceroute_hops();
        self.normalize_traceroute_hops_count();
        self.normalize_e2e_probe();
    }

    pub fn remove_private_hops(&mut self) {
        for run in &mut self.traceroute.runs {
            for hop in &mut run.hops {
                if hop.ip_address.0.map(is_private_ip).unwrap_or(false) {
                    *hop = TracerouteHop {
                        ttl: hop.ttl,
                        ..TracerouteHop::default()
                    };
                }
            }
        }
    }

    fn normalize_traceroute_runs(&mut self) {
        for run in &mut self.traceroute.runs {
            run.run_id = Uuid::new_v4().to_string();
        }
    }

    fn normalize_traceroute_hops(&mut self) {
        for run in &mut self.traceroute.runs {
            for hop in &mut run.hops {
                if hop.ip_address.0.is_some() {
                    hop.reachable = true;
                }
            }
        }
    }

    fn normalize_traceroute_hops_count(&mut self) {
        if self.traceroute.runs.is_empty() {
            return;
        }

        let mut hop_counts = Vec::with_capacity(self.traceroute.runs.len());
        for run in &self.traceroute.runs {
            let mut hop_count = run.hops.len();
            for (idx, hop) in run.hops.iter().enumerate().rev() {
                if hop.ip_address.0.is_some() {
                    hop_count = idx + 1;
                    break;
                }
            }
            hop_counts.push(hop_count);
        }

        let total: usize = hop_counts.iter().sum();
        let avg = total as f64 / hop_counts.len() as f64;
        let min = hop_counts.iter().copied().min().unwrap_or(0);
        let max = hop_counts.iter().copied().max().unwrap_or(0);

        self.traceroute.hop_count.avg = avg;
        self.traceroute.hop_count.min = min;
        self.traceroute.hop_count.max = max;
    }

    fn normalize_e2e_probe(&mut self) {
        if self.e2e_probe.rtts.is_empty() {
            return;
        }

        self.e2e_probe.packets_sent = self.e2e_probe.rtts.len();

        let mut valid_rtts = Vec::new();
        let mut packets_received = 0;
        for rtt in &self.e2e_probe.rtts {
            if *rtt > 0.0 {
                packets_received += 1;
                valid_rtts.push(*rtt);
            }
        }

        self.e2e_probe.packets_received = packets_received;

        if self.e2e_probe.packets_sent > 0 {
            self.e2e_probe.packet_loss_percentage =
                (self.e2e_probe.packets_sent - self.e2e_probe.packets_received) as f32
                    / self.e2e_probe.packets_sent as f32;
        }

        if !valid_rtts.is_empty() {
            let mut total = 0.0;
            let mut min = valid_rtts[0];
            let mut max = valid_rtts[0];
            for rtt in &valid_rtts {
                total += *rtt;
                if *rtt < min {
                    min = *rtt;
                }
                if *rtt > max {
                    max = *rtt;
                }
            }
            self.e2e_probe.rtt.avg = total / valid_rtts.len() as f64;
            self.e2e_probe.rtt.min = min;
            self.e2e_probe.rtt.max = max;
        }

        self.e2e_probe.jitter = calculate_jitter(&valid_rtts);
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

fn calculate_jitter(rtts: &[f64]) -> f64 {
    if rtts.len() < 2 {
        return 0.0;
    }
    let mut sum_diffs = 0.0;
    for i in 1..rtts.len() {
        sum_diffs += (rtts[i] - rtts[i - 1]).abs();
    }
    sum_diffs / (rtts.len() as f64 - 1.0)
}
