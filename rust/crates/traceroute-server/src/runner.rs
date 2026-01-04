//! Traceroute runner for HTTP server.

use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use traceroute_core::{
    execution::traceroute_serial, DestinationInfo, ProbeResponse, Protocol, ResultDestination,
    Results, SourceInfo, Stats, TracerouteConfig, TracerouteDriver, TracerouteError, TracerouteHop,
    TracerouteResults, TracerouteRun,
};
use traceroute_icmp::IcmpDriver;
use traceroute_packets::new_source_sink;
use traceroute_tcp::TcpDriver;
use traceroute_udp::UdpDriver;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Get the local IP address for connecting to the target.
fn get_local_addr(target: IpAddr) -> Result<IpAddr, TracerouteError> {
    let socket = match target {
        IpAddr::V4(_) => std::net::UdpSocket::bind("0.0.0.0:0"),
        IpAddr::V6(_) => std::net::UdpSocket::bind("[::]:0"),
    }
    .map_err(|e| TracerouteError::SocketCreation(e))?;

    let port = 33434;
    socket
        .connect(SocketAddr::new(target, port))
        .map_err(|e| TracerouteError::SocketCreation(e))?;

    socket
        .local_addr()
        .map(|addr| addr.ip())
        .map_err(|e| TracerouteError::SocketCreation(e))
}

/// Allocate a local port.
fn allocate_port(is_v6: bool) -> Result<u16, TracerouteError> {
    let socket = if is_v6 {
        std::net::UdpSocket::bind("[::]:0")
    } else {
        std::net::UdpSocket::bind("0.0.0.0:0")
    }
    .map_err(|e| TracerouteError::SocketCreation(e))?;

    socket
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| TracerouteError::SocketCreation(e))
}

/// Resolve a hostname to an IP address.
pub async fn resolve_hostname(hostname: &str, want_v6: bool) -> Result<IpAddr, TracerouteError> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| TracerouteError::Internal(format!("Failed to create DNS resolver: {}", e)))?;

    let lookup = resolver.lookup_ip(hostname).await.map_err(|e| {
        TracerouteError::Internal(format!("Failed to resolve hostname '{}': {}", hostname, e))
    })?;

    for ip in lookup.iter() {
        match (ip, want_v6) {
            (IpAddr::V6(_), true) => return Ok(ip),
            (IpAddr::V4(_), false) => return Ok(ip),
            _ => continue,
        }
    }

    lookup
        .iter()
        .next()
        .ok_or_else(|| TracerouteError::Internal(format!("No addresses found for '{}'", hostname)))
}

/// Run a single traceroute.
async fn run_traceroute_once(
    config: &TracerouteConfig,
    target_ip: IpAddr,
    src_ip: IpAddr,
    src_port: u16,
) -> Result<Vec<Option<ProbeResponse>>, TracerouteError> {
    let handle = new_source_sink(target_ip, config.use_windows_driver).await?;

    let mut driver: Box<dyn TracerouteDriver> = match config.protocol {
        Protocol::Udp => Box::new(UdpDriver::new(
            src_ip,
            src_port,
            target_ip,
            config.port,
            handle.source,
            handle.sink,
        )),
        Protocol::Tcp => Box::new(TcpDriver::new(
            src_ip,
            src_port,
            target_ip,
            config.port,
            handle.source,
            handle.sink,
            true,
            config.params.max_ttl,
        )),
        Protocol::Icmp => Box::new(IcmpDriver::new(
            src_ip,
            target_ip,
            handle.source,
            handle.sink,
            config.params.min_ttl,
            config.params.max_ttl,
        )),
    };

    let results = traceroute_serial(driver.as_mut(), &config.params).await?;
    driver.close().await?;

    Ok(results)
}

/// Convert probe responses to TracerouteHop.
fn responses_to_hops(responses: Vec<Option<ProbeResponse>>, min_ttl: u8) -> Vec<TracerouteHop> {
    responses
        .into_iter()
        .enumerate()
        .map(|(i, response)| {
            let ttl = min_ttl + i as u8;
            match response {
                Some(probe) => TracerouteHop {
                    ttl,
                    ip_address: Some(probe.ip),
                    rtt: Some(probe.rtt.as_secs_f64() * 1000.0),
                    reachable: true,
                    reverse_dns: Vec::new(),
                },
                None => TracerouteHop {
                    ttl,
                    ip_address: None,
                    rtt: None,
                    reachable: false,
                    reverse_dns: Vec::new(),
                },
            }
        })
        .collect()
}

/// Run traceroute with given config.
pub async fn run_traceroute(config: TracerouteConfig) -> Result<Results, TracerouteError> {
    info!(
        target = %config.hostname,
        protocol = %config.protocol,
        port = config.port,
        "Starting traceroute"
    );

    let target_ip = resolve_hostname(&config.hostname, config.want_v6).await?;
    debug!("Resolved {} to {}", config.hostname, target_ip);

    let src_ip = get_local_addr(target_ip)?;
    debug!("Using local IP: {}", src_ip);

    let mut runs = Vec::new();
    let mut errors = Vec::new();

    for i in 0..config.traceroute_queries {
        debug!(
            "Running traceroute query {}/{}",
            i + 1,
            config.traceroute_queries
        );

        let src_port = allocate_port(target_ip.is_ipv6())?;

        match run_traceroute_once(&config, target_ip, src_ip, src_port).await {
            Ok(responses) => {
                let hops = responses_to_hops(responses, config.params.min_ttl);

                let run = TracerouteRun {
                    run_id: Uuid::new_v4().to_string(),
                    source: SourceInfo {
                        ip_address: Some(src_ip),
                        port: Some(src_port),
                    },
                    destination: DestinationInfo {
                        ip_address: Some(target_ip),
                        port: Some(config.port),
                        reverse_dns: Vec::new(),
                    },
                    hops,
                };
                runs.push(run);
            }
            Err(e) => {
                warn!("Traceroute query {} failed: {}", i + 1, e);
                errors.push(e);
            }
        }
    }

    if runs.is_empty() && !errors.is_empty() {
        return Err(errors.remove(0));
    }

    let hop_count = if runs.len() > 1 {
        let counts: Vec<f64> = runs
            .iter()
            .map(|r| r.hops.iter().filter(|h| h.reachable).count() as f64)
            .collect();
        let avg = counts.iter().sum::<f64>() / counts.len() as f64;
        let min = counts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = counts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        Some(Stats { avg, min, max })
    } else {
        None
    };

    Ok(Results {
        protocol: config.protocol.to_string(),
        source: None,
        destination: ResultDestination {
            hostname: config.hostname,
            port: config.port,
        },
        traceroute: TracerouteResults { runs, hop_count },
        e2e_probe: None,
    })
}
