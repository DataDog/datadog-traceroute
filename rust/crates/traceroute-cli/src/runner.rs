//! Traceroute runner that orchestrates the entire traceroute process.

use hickory_resolver::TokioResolver;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use traceroute_core::{
    execution::traceroute_serial, DestinationInfo, ProbeResponse, Protocol, PublicIpInfo,
    ResultDestination, Results, SourceInfo, Stats, TcpMethod, TracerouteConfig, TracerouteDriver,
    TracerouteError, TracerouteHop, TracerouteParams, TracerouteResults, TracerouteRun,
};
use traceroute_icmp::IcmpDriver;
use traceroute_packets::new_source_sink;
use traceroute_tcp::TcpDriver;
use traceroute_udp::UdpDriver;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Get the local IP address for connecting to the target.
fn get_local_addr(target: IpAddr) -> Result<IpAddr, TracerouteError> {
    // Create a socket to determine the local IP address
    let socket = match target {
        IpAddr::V4(_) => std::net::UdpSocket::bind("0.0.0.0:0"),
        IpAddr::V6(_) => std::net::UdpSocket::bind("[::]:0"),
    }
    .map_err(|e| TracerouteError::SocketCreation(e))?;

    // Connect to the target to determine our local address
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
    // First check if it's already an IP address
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    let resolver = TokioResolver::from_system_conf().map_err(|e| {
        TracerouteError::Internal(format!("Failed to create DNS resolver: {}", e))
    })?;

    let lookup = resolver.lookup_ip(hostname).await.map_err(|e| {
        TracerouteError::Internal(format!("Failed to resolve hostname '{}': {}", hostname, e))
    })?;

    // Find the appropriate IP version
    for ip in lookup.iter() {
        match (ip, want_v6) {
            (IpAddr::V6(_), true) => return Ok(ip),
            (IpAddr::V4(_), false) => return Ok(ip),
            _ => continue,
        }
    }

    // Fall back to first address
    lookup
        .iter()
        .next()
        .ok_or_else(|| TracerouteError::Internal(format!("No addresses found for '{}'", hostname)))
}

/// Run a single traceroute and return the results.
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
        Protocol::Tcp => {
            match config.tcp_method {
                TcpMethod::Syn | TcpMethod::SynSocket => {
                    // For SYN mode, use the TcpDriver
                    Box::new(TcpDriver::new(
                        src_ip,
                        src_port,
                        target_ip,
                        config.port,
                        handle.source,
                        handle.sink,
                        true, // paris_mode
                        config.params.max_ttl,
                    ))
                }
                TcpMethod::Sack | TcpMethod::PreferSack => {
                    // For SACK mode, we need to first do a TCP handshake
                    // For now, fall back to SYN mode
                    warn!(
                        "SACK mode not fully implemented, falling back to SYN mode"
                    );
                    Box::new(TcpDriver::new(
                        src_ip,
                        src_port,
                        target_ip,
                        config.port,
                        handle.source,
                        handle.sink,
                        true,
                        config.params.max_ttl,
                    ))
                }
            }
        }
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
fn responses_to_hops(
    responses: Vec<Option<ProbeResponse>>,
    min_ttl: u8,
) -> Vec<TracerouteHop> {
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

/// Performs reverse DNS lookups for all hops.
async fn enrich_with_reverse_dns(hops: &mut [TracerouteHop]) {
    let resolver = match TokioResolver::from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to create DNS resolver for reverse lookup: {}", e);
            return;
        }
    };

    for hop in hops.iter_mut() {
        if let Some(ip) = hop.ip_address {
            match resolver.reverse_lookup(ip).await {
                Ok(names) => {
                    hop.reverse_dns = names.iter().map(|n| n.to_string()).collect();
                }
                Err(_) => {
                    // Reverse DNS not available for this IP
                }
            }
        }
    }
}

/// Check if an IP address is private.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Remove private hops from the results.
fn remove_private_hops(hops: &mut Vec<TracerouteHop>) {
    hops.retain(|hop| {
        if let Some(ip) = hop.ip_address {
            !is_private_ip(ip)
        } else {
            true // Keep unreachable hops
        }
    });
}

/// Fetch public IP address.
async fn fetch_public_ip() -> Option<String> {
    let urls = [
        "https://api.ipify.org",
        "https://ipinfo.io/ip",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    for url in &urls {
        match reqwest::get(*url).await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    let ip = text.trim().to_string();
                    if !ip.is_empty() {
                        return Some(ip);
                    }
                }
            }
            Err(_) => continue,
        }
    }

    None
}

/// Run the full traceroute with all options.
pub async fn run_traceroute(config: TracerouteConfig) -> Result<Results, TracerouteError> {
    info!(
        target = %config.hostname,
        protocol = %config.protocol,
        port = config.port,
        "Starting traceroute"
    );

    // Resolve hostname to IP
    let target_ip = resolve_hostname(&config.hostname, config.want_v6).await?;
    debug!("Resolved {} to {}", config.hostname, target_ip);

    // Get local IP address
    let src_ip = get_local_addr(target_ip)?;
    debug!("Using local IP: {}", src_ip);

    // Collect runs
    let mut runs = Vec::new();
    let mut errors = Vec::new();

    for i in 0..config.traceroute_queries {
        debug!("Running traceroute query {}/{}", i + 1, config.traceroute_queries);

        // Allocate a new port for each run
        let src_port = allocate_port(target_ip.is_ipv6())?;

        match run_traceroute_once(&config, target_ip, src_ip, src_port).await {
            Ok(responses) => {
                let mut hops = responses_to_hops(responses, config.params.min_ttl);

                // Perform reverse DNS lookups if requested
                if config.reverse_dns {
                    enrich_with_reverse_dns(&mut hops).await;
                }

                // Remove private hops if requested
                if config.skip_private_hops {
                    remove_private_hops(&mut hops);
                }

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

    // Calculate hop count statistics
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

    // Collect public IP if requested
    let source = if config.collect_source_public_ip {
        let public_ip = fetch_public_ip().await;
        Some(PublicIpInfo { public_ip })
    } else {
        None
    };

    Ok(Results {
        protocol: config.protocol.to_string(),
        source,
        destination: ResultDestination {
            hostname: config.hostname,
            port: config.port,
        },
        traceroute: TracerouteResults {
            runs,
            hop_count,
        },
        e2e_probe: None, // TODO: Implement E2E probes
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[tokio::test]
    async fn test_resolve_ip_address() {
        let result = resolve_hostname("8.8.8.8", false).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
