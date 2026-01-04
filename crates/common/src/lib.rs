use datadog_traceroute_result::{SerdeIpAddr, TracerouteHop};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

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

pub fn to_hops(
    params: TracerouteParams,
    probes: &[Option<ProbeResponse>],
) -> Result<Vec<TracerouteHop>, String> {
    let mut hops = Vec::with_capacity(probes.len());
    for (idx, probe) in probes.iter().enumerate() {
        let expected_ttl = params.min_ttl as u16 + idx as u16;
        match probe {
            Some(p) => {
                if p.ttl as u16 != expected_ttl {
                    return Err(format!(
                        "probe TTL mismatch: expected {}, got {}",
                        expected_ttl, p.ttl
                    ));
                }
                hops.push(TracerouteHop {
                    ttl: expected_ttl,
                    ip_address: SerdeIpAddr(Some(p.ip)),
                    rtt: convert_duration_to_ms(p.rtt),
                    reachable: false,
                    reverse_dns: Vec::new(),
                    is_dest: p.is_dest,
                    port: 0,
                    icmp_type: 0,
                    icmp_code: 0,
                });
            }
            None => {
                hops.push(TracerouteHop {
                    ttl: expected_ttl,
                    ..TracerouteHop::default()
                });
            }
        }
    }
    Ok(hops)
}

#[derive(Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TracerouteSerialParams {
    pub params: TracerouteParams,
}

#[derive(Debug, Clone, Copy)]
pub struct TracerouteParallelParams {
    pub params: TracerouteParams,
}

impl TracerouteParallelParams {
    pub fn max_timeout(&self) -> Duration {
        self.params.traceroute_timeout + self.params.send_delay * self.params.probe_count() as u32
    }
}

pub fn traceroute_serial(
    driver: &mut dyn TracerouteDriver,
    params: TracerouteSerialParams,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Option<ProbeResponse>>, Box<dyn Error + Send + Sync>> {
    params
        .params
        .validate()
        .map_err(|err| format!("invalid traceroute params: {}", err))?;

    let mut results = vec![None; params.params.max_ttl as usize + 1];

    for ttl in params.params.min_ttl..=params.params.max_ttl {
        if cancel.map(|c| c.is_cancelled()).unwrap_or(false) {
            break;
        }

        let send_deadline = Instant::now() + params.params.send_delay;
        let probe_deadline = Instant::now() + params.params.traceroute_timeout;

        driver.send_probe(ttl)?;

        let mut probe: Option<ProbeResponse> = None;
        while Instant::now() < probe_deadline {
            if cancel.map(|c| c.is_cancelled()).unwrap_or(false) {
                break;
            }

            match driver.receive_probe(params.params.poll_frequency) {
                Ok(response) => {
                    params
                        .params
                        .validate_probe(&response)
                        .map_err(|err| format!("invalid probe: {}", err))?;
                    probe = Some(response);
                    break;
                }
                Err(err) => {
                    if is_probe_retryable(err.as_ref()) {
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        if let Some(found) = probe {
            results[found.ttl as usize] = Some(found.clone());
            if found.is_dest {
                break;
            }
        }

        let now = Instant::now();
        if send_deadline > now {
            thread::sleep(send_deadline - now);
        }
    }

    Ok(clip_results(params.params.min_ttl, results))
}

pub fn traceroute_parallel(
    driver: Box<dyn TracerouteDriver + Send>,
    params: TracerouteParallelParams,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Option<ProbeResponse>>, Box<dyn Error + Send + Sync>> {
    params
        .params
        .validate()
        .map_err(|err| format!("invalid traceroute params: {}", err))?;

    if !driver.get_driver_info().supports_parallel {
        return Err("tried to call TracerouteParallel on a driver that doesn't support parallel".into());
    }

    let results: Arc<Mutex<Vec<Option<ProbeResponse>>>> =
        Arc::new(Mutex::new(vec![None; params.params.max_ttl as usize + 1]));
    let driver = Arc::new(Mutex::new(driver));
    let sent_once = Arc::new(AtomicBool::new(false));
    let stop_send = Arc::new(AtomicBool::new(false));

    let max_deadline = Instant::now() + params.max_timeout();

    let sender_driver = Arc::clone(&driver);
    let sender_sent_once = Arc::clone(&sent_once);
    let sender_stop = Arc::clone(&stop_send);
    let sender_cancel = cancel.map(|c| c.clone());
    let sender_params = params;

    let sender = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        for ttl in sender_params.params.min_ttl..=sender_params.params.max_ttl {
            if sender_stop.load(Ordering::SeqCst) {
                break;
            }
            if sender_cancel.as_ref().map(|c| c.is_cancelled()).unwrap_or(false) {
                break;
            }
            {
                let mut locked = sender_driver
                    .lock()
                    .map_err(|_| "driver mutex poisoned")?;
                locked.send_probe(ttl)?;
            }
            sender_sent_once.store(true, Ordering::SeqCst);
            thread::sleep(sender_params.params.send_delay);
        }
        Ok(())
    });

    let receiver_driver = Arc::clone(&driver);
    let receiver_results = Arc::clone(&results);
    let receiver_sent_once = Arc::clone(&sent_once);
    let receiver_stop = Arc::clone(&stop_send);
    let receiver_cancel = cancel.map(|c| c.clone());
    let receiver_params = params;

    let receiver = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        while Instant::now() < max_deadline {
            if receiver_cancel
                .as_ref()
                .map(|c| c.is_cancelled())
                .unwrap_or(false)
            {
                break;
            }
            if !receiver_sent_once.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
                continue;
            }

            let response = {
                let mut locked = receiver_driver
                    .lock()
                    .map_err(|_| "driver mutex poisoned")?;
                locked.receive_probe(receiver_params.params.poll_frequency)
            };

            match response {
                Ok(probe) => {
                    receiver_params
                        .params
                        .validate_probe(&probe)
                        .map_err(|err| format!("invalid probe: {}", err))?;
                    let mut results = receiver_results
                        .lock()
                        .map_err(|_| "results mutex poisoned")?;
                    let slot = &mut results[probe.ttl as usize];
                    let should_update = match slot {
                        None => true,
                        Some(existing) => !existing.is_dest && probe.is_dest,
                    };
                    if should_update {
                        *slot = Some(probe.clone());
                    }
                    if probe.is_dest {
                        receiver_stop.store(true, Ordering::SeqCst);
                    }
                }
                Err(err) => {
                    if is_probe_retryable(err.as_ref()) {
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Ok(())
    });

    let sender_result = sender.join().map_err(|_| "sender thread panicked")?;
    let receiver_result = receiver.join().map_err(|_| "receiver thread panicked")?;

    sender_result?;
    receiver_result?;

    let results = Arc::try_unwrap(results)
        .map_err(|_| "failed to unwrap results")?
        .into_inner()
        .map_err(|_| "results mutex poisoned")?;
    Ok(clip_results(params.params.min_ttl, results))
}

fn clip_results(
    min_ttl: u8,
    mut results: Vec<Option<ProbeResponse>>,
) -> Vec<Option<ProbeResponse>> {
    let dest_idx = results
        .iter()
        .position(|probe| probe.as_ref().map(|p| p.is_dest).unwrap_or(false));
    if let Some(idx) = dest_idx {
        results.truncate(idx + 1);
    }
    results
        .into_iter()
        .skip(min_ttl as usize)
        .collect::<Vec<_>>()
}
