use datadog_traceroute_common::DEFAULT_PORT;
use datadog_traceroute_result::{Destination, Results, TracerouteRun};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
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
pub struct TracerouteRunner {
    public_ip_fetcher: Arc<dyn PublicIpFetcher + Send + Sync>,
}

impl TracerouteRunner {
    pub fn new() -> Self {
        Self {
            public_ip_fetcher: Arc::new(NoopPublicIpFetcher),
        }
    }

    pub fn with_public_ip_fetcher(
        public_ip_fetcher: Arc<dyn PublicIpFetcher + Send + Sync>,
    ) -> Self {
        Self { public_ip_fetcher }
    }

    pub fn run_traceroute(&self, params: TracerouteParams) -> Result<Results, TracerouteError> {
        let destination_port = if params.port == 0 {
            DEFAULT_PORT
        } else {
            params.port
        };

        let mut results = self.run_traceroute_multi(params.clone(), destination_port)?;
        results.protocol = params.protocol.clone();
        results.destination = Destination {
            hostname: params.hostname,
            port: destination_port,
        };

        if params.reverse_dns {
            // TODO: reverse DNS enrichment should be done by reversedns crate.
        }

        results.normalize();
        if params.skip_private_hops {
            results.remove_private_hops();
        }

        Ok(results)
    }

    fn run_traceroute_multi(
        &self,
        params: TracerouteParams,
        destination_port: u16,
    ) -> Result<Results, TracerouteError> {
        let results = Arc::new(Mutex::new(Results::default()));
        let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for _ in 0..params.traceroute_queries {
            let params_clone = params.clone();
            let results_clone = Arc::clone(&results);
            let errors_clone = Arc::clone(&errors);
            let handle = thread::spawn(move || {
                match run_traceroute_once(&params_clone, destination_port) {
                    Ok(run) => {
                        let mut results = results_clone.lock().expect("results mutex poisoned");
                        results.traceroute.runs.push(run);
                    }
                    Err(err) => {
                        let mut errors = errors_clone.lock().expect("errors mutex poisoned");
                        errors.push(err.to_string());
                    }
                }
            });
            handles.push(handle);
        }

        if params.e2e_queries > 0 {
            let max_delay = Duration::from_secs(1);
            let mut delay =
                params.timeout * params.max_ttl as u32 / params.e2e_queries as u32;
            if delay > max_delay {
                delay = max_delay;
            }

            for idx in 0..params.e2e_queries {
                let params_clone = params.clone();
                let results_clone = Arc::clone(&results);
                let errors_clone = Arc::clone(&errors);
                let handle = thread::spawn(move || {
                    match run_e2e_probe_once(&params_clone, destination_port) {
                        Ok(rtt) => {
                            let mut results =
                                results_clone.lock().expect("results mutex poisoned");
                            results.e2e_probe.rtts.push(rtt);
                        }
                        Err(err) => {
                            let mut results =
                                results_clone.lock().expect("results mutex poisoned");
                            results.e2e_probe.rtts.push(0.0);
                            let mut errors = errors_clone.lock().expect("errors mutex poisoned");
                            errors.push(err.to_string());
                        }
                    }
                });
                handles.push(handle);

                if idx + 1 < params.e2e_queries {
                    thread::sleep(delay);
                }
            }
        }

        if params.collect_source_public_ip {
            let results_clone = Arc::clone(&results);
            let fetcher = Arc::clone(&self.public_ip_fetcher);
            let handle = thread::spawn(move || {
                if let Ok(Some(ip)) = fetcher.get_ip() {
                    let mut results = results_clone.lock().expect("results mutex poisoned");
                    results.source.public_ip = ip.to_string();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().map_err(|_| {
                TracerouteError::new("thread panicked while running traceroute")
            })?;
        }

        let errors = errors.lock().expect("errors mutex poisoned");
        if !errors.is_empty() {
            return Err(TracerouteError::from_messages(errors.clone()));
        }

        let results = Arc::try_unwrap(results)
            .map_err(|_| TracerouteError::new("failed to unwrap results"))?
            .into_inner()
            .map_err(|_| TracerouteError::new("results mutex poisoned"))?;

        Ok(results)
    }
}

pub trait PublicIpFetcher {
    fn get_ip(&self) -> Result<Option<IpAddr>, Box<dyn Error + Send + Sync>>;
}

struct NoopPublicIpFetcher;

impl PublicIpFetcher for NoopPublicIpFetcher {
    fn get_ip(&self) -> Result<Option<IpAddr>, Box<dyn Error + Send + Sync>> {
        Ok(None)
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

    pub fn from_messages(messages: Vec<String>) -> Self {
        Self {
            message: format!("multiple errors: {}", messages.join("; ")),
        }
    }
}

impl fmt::Display for TracerouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for TracerouteError {}

fn run_traceroute_once(
    _params: &TracerouteParams,
    _destination_port: u16,
) -> Result<TracerouteRun, TracerouteError> {
    Err(TracerouteError::new(
        "protocol drivers not yet implemented",
    ))
}

fn run_e2e_probe_once(
    params: &TracerouteParams,
    destination_port: u16,
) -> Result<f64, TracerouteError> {
    let mut probe_params = params.clone();
    probe_params.min_ttl = probe_params.max_ttl;
    if probe_params.protocol == "tcp"
        && (probe_params.tcp_method == "sack" || probe_params.tcp_method == "prefer_sack")
    {
        probe_params.tcp_method = "syn".to_string();
    }

    let run = run_traceroute_once(&probe_params, destination_port)?;
    match run.hops.iter().find(|hop| hop.is_dest) {
        Some(hop) => Ok(hop.rtt),
        None => Ok(0.0),
    }
}
