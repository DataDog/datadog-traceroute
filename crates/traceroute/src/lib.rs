use datadog_traceroute_common::{
    DEFAULT_PORT, TracerouteParallelParams, TracerouteParams as CommonParams,
    TracerouteSerialParams, to_hops, traceroute_parallel, traceroute_serial,
};
use datadog_traceroute_icmp::{IcmpDriver, IcmpParams};
use datadog_traceroute_packets::{
    FilterConfig, PacketFilterSpec, PacketFilterType, new_source_sink,
};
use datadog_traceroute_result::{
    Destination, Results, SerdeIpAddr, TracerouteDestination, TracerouteRun, TracerouteSource,
};
use datadog_traceroute_sack::{NotSupportedError, SackDriver, SackParams};
use datadog_traceroute_tcp::{TcpDriver, TcpParams};
use datadog_traceroute_udp::{UdpDriver, UdpParams};
use std::error::Error;
use std::fmt;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
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

pub struct TracerouteRunner {
    public_ip_fetcher: Arc<dyn PublicIpFetcher + Send + Sync>,
    run_once: RunTracerouteOnceFn,
}

impl TracerouteRunner {
    pub fn new() -> Self {
        Self {
            public_ip_fetcher: Arc::new(NoopPublicIpFetcher),
            run_once: Arc::new(run_traceroute_once),
        }
    }

    pub fn with_public_ip_fetcher(
        public_ip_fetcher: Arc<dyn PublicIpFetcher + Send + Sync>,
    ) -> Self {
        Self {
            public_ip_fetcher,
            run_once: Arc::new(run_traceroute_once),
        }
    }

    #[cfg(test)]
    fn with_run_once(
        public_ip_fetcher: Arc<dyn PublicIpFetcher + Send + Sync>,
        run_once: RunTracerouteOnceFn,
    ) -> Self {
        Self {
            public_ip_fetcher,
            run_once,
        }
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
            let run_once = Arc::clone(&self.run_once);
            let handle = thread::spawn(move || match run_once(params_clone, destination_port) {
                Ok(run) => {
                    let mut results = results_clone.lock().expect("results mutex poisoned");
                    results.traceroute.runs.push(run);
                }
                Err(err) => {
                    let mut errors = errors_clone.lock().expect("errors mutex poisoned");
                    errors.push(err.to_string());
                }
            });
            handles.push(handle);
        }

        if params.e2e_queries > 0 {
            let max_delay = Duration::from_secs(1);
            let mut delay = params.timeout * params.max_ttl as u32 / params.e2e_queries as u32;
            if delay > max_delay {
                delay = max_delay;
            }

            for idx in 0..params.e2e_queries {
                let params_clone = params.clone();
                let results_clone = Arc::clone(&results);
                let errors_clone = Arc::clone(&errors);
                let run_once = Arc::clone(&self.run_once);
                let handle = thread::spawn(move || {
                    match run_e2e_probe_once(&params_clone, destination_port, run_once) {
                        Ok(rtt) => {
                            let mut results = results_clone.lock().expect("results mutex poisoned");
                            results.e2e_probe.rtts.push(rtt);
                        }
                        Err(err) => {
                            let mut results = results_clone.lock().expect("results mutex poisoned");
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
            handle
                .join()
                .map_err(|_| TracerouteError::new("thread panicked while running traceroute"))?;
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

impl Default for TracerouteRunner {
    fn default() -> Self {
        Self::new()
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

fn has_port(host: &str) -> bool {
    if host.starts_with('[') {
        host.contains("]:")
    } else {
        host.matches(':').count() == 1
    }
}

fn parse_target(
    raw: &str,
    default_port: u16,
    want_v6: bool,
) -> Result<SocketAddr, TracerouteError> {
    let mut raw = raw.to_string();
    if !has_port(&raw) {
        let host = raw.trim_matches(['[', ']'].as_ref());
        if host.contains(':') {
            raw = format!("[{}]:{}", host, default_port);
        } else {
            raw = format!("{}:{}", host, default_port);
        }
    }

    let addrs: Vec<SocketAddr> = raw
        .to_socket_addrs()
        .map_err(|err| TracerouteError::new(format!("failed to resolve host {}: {}", raw, err)))?
        .collect();
    if addrs.is_empty() {
        return Err(TracerouteError::new(format!(
            "failed to resolve host {}: no addresses",
            raw
        )));
    }

    if want_v6 {
        if let Some(addr) = addrs.iter().copied().find(SocketAddr::is_ipv6) {
            return Ok(addr);
        }
    } else if let Some(addr) = addrs.iter().copied().find(SocketAddr::is_ipv4) {
        return Ok(addr);
    }

    Ok(addrs[0])
}

fn local_addr_for_target(target: SocketAddr) -> std::io::Result<(SocketAddr, UdpSocket)> {
    let bind_addr = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(target)?;
    let local = socket.local_addr()?;
    Ok((local, socket))
}

fn reserve_local_port(local_ip: IpAddr) -> std::io::Result<(u16, TcpListener)> {
    let listener = TcpListener::bind(SocketAddr::new(local_ip, 0))?;
    let port = listener.local_addr()?.port();
    Ok((port, listener))
}

fn common_params(params: &TracerouteParams, delay: Duration) -> CommonParams {
    CommonParams {
        min_ttl: params.min_ttl,
        max_ttl: params.max_ttl,
        traceroute_timeout: params.timeout,
        poll_frequency: Duration::from_millis(100),
        send_delay: delay,
    }
}

fn build_run(
    hops: Vec<datadog_traceroute_result::TracerouteHop>,
    source: SocketAddr,
    destination: SocketAddr,
) -> TracerouteRun {
    TracerouteRun {
        source: TracerouteSource {
            ip_address: SerdeIpAddr(Some(source.ip())),
            port: source.port(),
        },
        destination: TracerouteDestination {
            ip_address: SerdeIpAddr(Some(destination.ip())),
            port: destination.port(),
            reverse_dns: Vec::new(),
        },
        hops,
        ..TracerouteRun::default()
    }
}

fn run_udp_traceroute(
    params: &TracerouteParams,
    destination_port: u16,
) -> Result<TracerouteRun, Box<dyn Error + Send + Sync>> {
    let target = parse_target(&params.hostname, destination_port, params.want_v6)?;
    let (local_addr, udp_socket) = local_addr_for_target(target)?;

    let mut handle = new_source_sink(target.ip(), params.use_windows_driver)?;
    if handle.must_close_port {
        drop(udp_socket);
    }

    let filter = PacketFilterSpec {
        filter_type: PacketFilterType::Icmp,
        filter_config: FilterConfig {
            src: local_addr,
            dst: target,
        },
    };
    handle.source.set_packet_filter(filter)?;

    let driver = UdpDriver::new(
        UdpParams {
            target: target.ip(),
            target_port: target.port(),
            local_ip: local_addr.ip(),
            local_port: local_addr.port(),
            min_ttl: params.min_ttl,
            max_ttl: params.max_ttl,
            loosen_icmp_src: false,
        },
        handle.sink,
        handle.source,
    );

    let params_common = common_params(params, Duration::from_millis(params.delay_ms));
    let parallel = TracerouteParallelParams {
        params: params_common,
    };
    let responses = traceroute_parallel(Box::new(driver), parallel, None)?;
    let hops = to_hops(parallel.params, &responses)?;
    Ok(build_run(hops, local_addr, target))
}

fn run_icmp_traceroute(
    params: &TracerouteParams,
) -> Result<TracerouteRun, Box<dyn Error + Send + Sync>> {
    let target = parse_target(&params.hostname, 80, params.want_v6)?;
    let (local_addr, _udp_socket) = local_addr_for_target(target)?;

    let mut handle = new_source_sink(target.ip(), params.use_windows_driver)?;
    let filter = PacketFilterSpec {
        filter_type: PacketFilterType::Icmp,
        filter_config: FilterConfig {
            src: local_addr,
            dst: SocketAddr::new(target.ip(), 0),
        },
    };
    handle.source.set_packet_filter(filter)?;

    let driver = IcmpDriver::new(
        IcmpParams {
            target: target.ip(),
            min_ttl: params.min_ttl,
            max_ttl: params.max_ttl,
        },
        local_addr.ip(),
        handle.sink,
        handle.source,
    );

    let params_common = common_params(params, Duration::from_millis(params.delay_ms));
    let parallel = TracerouteParallelParams {
        params: params_common,
    };
    let responses = traceroute_parallel(Box::new(driver), parallel, None)?;
    let hops = to_hops(parallel.params, &responses)?;
    Ok(build_run(hops, local_addr, SocketAddr::new(target.ip(), 0)))
}

fn run_tcp_syn_traceroute(
    params: &TracerouteParams,
    target: SocketAddr,
) -> Result<TracerouteRun, Box<dyn Error + Send + Sync>> {
    let (local_addr, _udp_socket) = local_addr_for_target(target)?;
    let (local_port, tcp_listener) = reserve_local_port(local_addr.ip())?;

    let mut handle = new_source_sink(target.ip(), params.use_windows_driver)?;
    if handle.must_close_port {
        drop(tcp_listener);
    }

    let filter = PacketFilterSpec {
        filter_type: PacketFilterType::Tcp,
        filter_config: FilterConfig {
            src: target,
            dst: SocketAddr::new(local_addr.ip(), local_port),
        },
    };
    handle.source.set_packet_filter(filter)?;

    let driver = TcpDriver::new(
        TcpParams {
            target: target.ip(),
            dest_port: target.port(),
            local_ip: local_addr.ip(),
            local_port,
            min_ttl: params.min_ttl,
            max_ttl: params.max_ttl,
            paris_traceroute_mode: params.tcp_syn_paris_traceroute_mode,
            loosen_icmp_src: false,
        },
        handle.sink,
        handle.source,
    );

    let params_common = common_params(params, Duration::from_millis(params.delay_ms));
    let serial = TracerouteSerialParams {
        params: params_common,
    };
    let mut driver = driver;
    let responses = traceroute_serial(&mut driver, serial, None)?;
    let hops = to_hops(serial.params, &responses)?;
    Ok(build_run(
        hops,
        SocketAddr::new(local_addr.ip(), local_port),
        target,
    ))
}

fn run_tcp_sack_traceroute(
    params: &TracerouteParams,
    target: SocketAddr,
) -> Result<TracerouteRun, Box<dyn Error + Send + Sync>> {
    let (local_addr, _udp_socket) = local_addr_for_target(target)?;
    let mut handle = new_source_sink(target.ip(), params.use_windows_driver)?;

    if handle.must_close_port {
        return Err(Box::new(NotSupportedError::new(
            "SACK traceroute is not supported on this platform",
        )));
    }

    let synack_filter = PacketFilterSpec {
        filter_type: PacketFilterType::SynAck,
        filter_config: FilterConfig {
            src: target,
            dst: SocketAddr::new(local_addr.ip(), 0),
        },
    };
    handle.source.set_packet_filter(synack_filter)?;

    let mut driver = SackDriver::new(
        SackParams {
            target,
            min_ttl: params.min_ttl,
            max_ttl: params.max_ttl,
            handshake_timeout: params.timeout,
            loosen_icmp_src: true,
        },
        local_addr.ip(),
        handle.sink,
        handle.source,
    )?;

    let stream = TcpStream::connect_timeout(&target, params.timeout).map_err(|err| {
        Box::new(NotSupportedError::new(format!(
            "sack traceroute failed to dial: {}",
            err
        ))) as Box<dyn Error + Send + Sync>
    })?;

    let local_tcp = stream.local_addr()?;
    if local_tcp.ip() != local_addr.ip() {
        return Err(format!(
            "tcp conn negotiated a different local addr than expected: {} != {}",
            local_tcp.ip(),
            local_addr.ip()
        )
        .into());
    }

    driver.read_handshake(local_tcp.port())?;

    let tcp_filter = PacketFilterSpec {
        filter_type: PacketFilterType::Tcp,
        filter_config: FilterConfig {
            src: target,
            dst: local_tcp,
        },
    };
    driver.set_packet_filter(tcp_filter)?;

    let params_common = common_params(params, Duration::from_millis(10));
    let parallel = TracerouteParallelParams {
        params: params_common,
    };
    let responses = traceroute_parallel(Box::new(driver), parallel, None)?;
    let hops = to_hops(parallel.params, &responses)?;
    Ok(build_run(hops, local_tcp, target))
}

fn run_tcp_traceroute(
    params: &TracerouteParams,
    destination_port: u16,
) -> Result<TracerouteRun, TracerouteError> {
    let target = parse_target(&params.hostname, destination_port, params.want_v6)?;
    let method = if params.tcp_method.is_empty() {
        "syn"
    } else {
        params.tcp_method.as_str()
    };

    match method {
        "syn" => run_tcp_syn_traceroute(params, target)
            .map_err(|err| TracerouteError::new(format!("tcp syn traceroute failed: {}", err))),
        "sack" => run_tcp_sack_traceroute(params, target)
            .map_err(|err| TracerouteError::new(format!("sack traceroute failed: {}", err))),
        "prefer_sack" => match run_tcp_sack_traceroute(params, target) {
            Ok(run) => Ok(run),
            Err(err) => {
                if err.is::<NotSupportedError>() {
                    run_tcp_syn_traceroute(params, target).map_err(|err| {
                        TracerouteError::new(format!(
                            "sack not supported, tcp syn traceroute failed: {}",
                            err
                        ))
                    })
                } else {
                    Err(TracerouteError::new(format!(
                        "sack traceroute failed fatally, not falling back: {}",
                        err
                    )))
                }
            }
        },
        _ => Err(TracerouteError::new(format!(
            "unexpected tcp method: {}",
            params.tcp_method
        ))),
    }
}

fn run_traceroute_once(
    params: TracerouteParams,
    destination_port: u16,
) -> Result<TracerouteRun, TracerouteError> {
    match params.protocol.as_str() {
        "udp" => run_udp_traceroute(&params, destination_port)
            .map_err(|err| TracerouteError::new(format!("udp traceroute failed: {}", err))),
        "icmp" => run_icmp_traceroute(&params)
            .map_err(|err| TracerouteError::new(format!("icmp traceroute failed: {}", err))),
        "tcp" => run_tcp_traceroute(&params, destination_port),
        _ => Err(TracerouteError::new(format!(
            "unknown protocol: {}",
            params.protocol
        ))),
    }
}

fn run_e2e_probe_once(
    params: &TracerouteParams,
    destination_port: u16,
    run_once: RunTracerouteOnceFn,
) -> Result<f64, TracerouteError> {
    let mut probe_params = params.clone();
    probe_params.min_ttl = probe_params.max_ttl;
    if probe_params.protocol == "tcp"
        && (probe_params.tcp_method == "sack" || probe_params.tcp_method == "prefer_sack")
    {
        probe_params.tcp_method = "syn".to_string();
    }

    let run = run_once(probe_params, destination_port)?;
    match run.hops.iter().find(|hop| hop.is_dest) {
        Some(hop) => Ok(hop.rtt),
        None => Ok(0.0),
    }
}

type RunTracerouteOnceFn =
    Arc<dyn Fn(TracerouteParams, u16) -> Result<TracerouteRun, TracerouteError> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;
    use datadog_traceroute_result::{SerdeIpAddr, TracerouteHop};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct TestPublicIpFetcher {
        ip: Option<IpAddr>,
    }

    impl PublicIpFetcher for TestPublicIpFetcher {
        fn get_ip(&self) -> Result<Option<IpAddr>, Box<dyn Error + Send + Sync>> {
            Ok(self.ip)
        }
    }

    fn make_run(dest_ip: IpAddr, rtt: f64) -> TracerouteRun {
        TracerouteRun {
            hops: vec![
                TracerouteHop {
                    ttl: 1,
                    ip_address: SerdeIpAddr(Some(dest_ip)),
                    rtt,
                    reachable: false,
                    reverse_dns: Vec::new(),
                    is_dest: true,
                    port: 0,
                    icmp_type: 0,
                    icmp_code: 0,
                },
                TracerouteHop {
                    ttl: 2,
                    ..TracerouteHop::default()
                },
            ],
            ..TracerouteRun::default()
        }
    }

    #[test]
    fn run_traceroute_multi_collects_runs() {
        let counter = Arc::new(AtomicUsize::new(0));
        let run_once: RunTracerouteOnceFn = Arc::new({
            let counter = Arc::clone(&counter);
            move |_params: TracerouteParams, _port| {
                let idx = counter.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(make_run(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, idx as u8)),
                    10.0,
                ))
            }
        });

        let params = TracerouteParams {
            hostname: "example.com".to_string(),
            port: 0,
            protocol: "udp".to_string(),
            min_ttl: 1,
            max_ttl: 3,
            delay_ms: 0,
            timeout: Duration::from_millis(100),
            tcp_method: "syn".to_string(),
            want_v6: false,
            tcp_syn_paris_traceroute_mode: false,
            reverse_dns: false,
            collect_source_public_ip: false,
            traceroute_queries: 2,
            e2e_queries: 0,
            use_windows_driver: false,
            skip_private_hops: false,
        };

        let runner =
            TracerouteRunner::with_run_once(Arc::new(TestPublicIpFetcher { ip: None }), run_once);

        let results = runner.run_traceroute(params).expect("traceroute failed");
        assert_eq!(results.traceroute.runs.len(), 2);
    }

    #[test]
    fn run_traceroute_multi_collects_e2e_rtts() {
        let run_once: RunTracerouteOnceFn = Arc::new(|_params: TracerouteParams, _port| {
            Ok(make_run(IpAddr::V4(Ipv4Addr::LOCALHOST), 12.5))
        });

        let params = TracerouteParams {
            hostname: "example.com".to_string(),
            port: 0,
            protocol: "udp".to_string(),
            min_ttl: 1,
            max_ttl: 3,
            delay_ms: 0,
            timeout: Duration::from_millis(100),
            tcp_method: "syn".to_string(),
            want_v6: false,
            tcp_syn_paris_traceroute_mode: false,
            reverse_dns: false,
            collect_source_public_ip: false,
            traceroute_queries: 0,
            e2e_queries: 3,
            use_windows_driver: false,
            skip_private_hops: false,
        };

        let runner =
            TracerouteRunner::with_run_once(Arc::new(TestPublicIpFetcher { ip: None }), run_once);

        let results = runner.run_traceroute(params).expect("traceroute failed");
        assert_eq!(results.e2e_probe.rtts.len(), 3);
        for rtt in results.e2e_probe.rtts {
            assert_eq!(rtt, 12.5);
        }
    }

    #[test]
    fn e2e_forces_tcp_syn_when_sack() {
        let seen_methods = Arc::new(Mutex::new(Vec::new()));
        let run_once: RunTracerouteOnceFn = Arc::new({
            let seen_methods = Arc::clone(&seen_methods);
            move |params: TracerouteParams, _port| {
                seen_methods
                    .lock()
                    .expect("methods mutex")
                    .push(params.tcp_method);
                Ok(make_run(IpAddr::V4(Ipv4Addr::LOCALHOST), 5.0))
            }
        });

        let params = TracerouteParams {
            hostname: "example.com".to_string(),
            port: 0,
            protocol: "tcp".to_string(),
            min_ttl: 1,
            max_ttl: 3,
            delay_ms: 0,
            timeout: Duration::from_millis(100),
            tcp_method: "sack".to_string(),
            want_v6: false,
            tcp_syn_paris_traceroute_mode: false,
            reverse_dns: false,
            collect_source_public_ip: false,
            traceroute_queries: 0,
            e2e_queries: 1,
            use_windows_driver: false,
            skip_private_hops: false,
        };

        let runner =
            TracerouteRunner::with_run_once(Arc::new(TestPublicIpFetcher { ip: None }), run_once);

        runner.run_traceroute(params).expect("traceroute failed");
        let methods = seen_methods.lock().expect("methods mutex");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0], "syn");
    }

    #[test]
    fn public_ip_is_collected() {
        let run_once: RunTracerouteOnceFn = Arc::new(|_params: TracerouteParams, _port| {
            Ok(make_run(IpAddr::V4(Ipv4Addr::LOCALHOST), 5.0))
        });

        let params = TracerouteParams {
            hostname: "example.com".to_string(),
            port: 0,
            protocol: "udp".to_string(),
            min_ttl: 1,
            max_ttl: 3,
            delay_ms: 0,
            timeout: Duration::from_millis(100),
            tcp_method: "syn".to_string(),
            want_v6: false,
            tcp_syn_paris_traceroute_mode: false,
            reverse_dns: false,
            collect_source_public_ip: true,
            traceroute_queries: 0,
            e2e_queries: 0,
            use_windows_driver: false,
            skip_private_hops: false,
        };

        let runner = TracerouteRunner::with_run_once(
            Arc::new(TestPublicIpFetcher {
                ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            }),
            run_once,
        );

        let results = runner.run_traceroute(params).expect("traceroute failed");
        assert_eq!(results.source.public_ip, "8.8.8.8");
    }

    #[test]
    fn errors_are_aggregated() {
        let run_once: RunTracerouteOnceFn =
            Arc::new(|_params: TracerouteParams, _port| Err(TracerouteError::new("failed run")));

        let params = TracerouteParams {
            hostname: "example.com".to_string(),
            port: 0,
            protocol: "udp".to_string(),
            min_ttl: 1,
            max_ttl: 3,
            delay_ms: 0,
            timeout: Duration::from_millis(100),
            tcp_method: "syn".to_string(),
            want_v6: false,
            tcp_syn_paris_traceroute_mode: false,
            reverse_dns: false,
            collect_source_public_ip: false,
            traceroute_queries: 2,
            e2e_queries: 0,
            use_windows_driver: false,
            skip_private_hops: false,
        };

        let runner =
            TracerouteRunner::with_run_once(Arc::new(TestPublicIpFetcher { ip: None }), run_once);

        let err = runner.run_traceroute(params).expect_err("expected error");
        assert!(err.to_string().contains("failed run"));
    }
}
