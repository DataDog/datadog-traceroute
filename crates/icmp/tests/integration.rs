#![cfg(any(target_os = "linux", target_os = "macos"))]

use datadog_traceroute_common::{ProbeResponse, TracerouteDriver};
use datadog_traceroute_icmp::{IcmpDriver, IcmpParams};
use datadog_traceroute_packets::{
    FilterConfig, PacketFilterSpec, PacketFilterType, new_source_sink,
};
use libc::geteuid;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if unsafe { geteuid() } != 0 {
        eprintln!("skipping: requires root for raw sockets");
        return false;
    }
    true
}

fn local_addr_for_target(target: IpAddr) -> std::io::Result<IpAddr> {
    let socket = match target {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
        IpAddr::V6(_) => UdpSocket::bind("[::]:0")?,
    };
    socket.connect(SocketAddr::new(target, 53))?;
    Ok(socket.local_addr()?.ip())
}

fn run_icmp_probe(target: IpAddr) -> std::io::Result<ProbeResponse> {
    let local_ip = local_addr_for_target(target)?;
    let mut handle = new_source_sink(target, false)?;
    let filter = PacketFilterSpec {
        filter_type: PacketFilterType::Icmp,
        filter_config: FilterConfig {
            src: SocketAddr::new(local_ip, 0),
            dst: SocketAddr::new(target, 0),
        },
    };
    handle.source.set_packet_filter(filter)?;

    let params = IcmpParams {
        target,
        min_ttl: 1,
        max_ttl: 3,
    };
    let mut driver = IcmpDriver::new(params, local_ip, handle.sink, handle.source);
    driver.send_probe(1).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("send probe failed: {}", err),
        )
    })?;

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match driver.receive_probe(Duration::from_millis(200)) {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                if Instant::now() > deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("no ICMP response received: {}", err),
                    ));
                }
            }
        }
    }
}

#[test]
#[ignore]
fn icmp_probe_ipv4() {
    if !require_root() {
        return;
    }
    let target = std::env::var("DD_TRACEROUTE_TARGET")
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or_else(|| IpAddr::from([8, 8, 8, 8]));
    let resp = run_icmp_probe(target).expect("icmp probe v4");
    print_probe_json("icmp", target, resp);
}

#[test]
#[ignore]
fn icmp_probe_ipv6() {
    if !require_root() {
        return;
    }
    let Some(value) = std::env::var("DD_TRACEROUTE_TARGET_V6").ok() else {
        return;
    };
    let target: IpAddr = value.parse().expect("valid IPv6 target");
    let resp = run_icmp_probe(target).expect("icmp probe v6");
    print_probe_json("icmp", target, resp);
}

fn print_probe_json(protocol: &str, target: IpAddr, resp: ProbeResponse) {
    let rtt_ms = resp.rtt.as_secs_f64() * 1000.0;
    println!(
        "{{\"protocol\":\"{}\",\"target\":\"{}\",\"ttl\":{},\"ip\":\"{}\",\"rtt_ms\":{:.3},\"is_dest\":{}}}",
        protocol, target, resp.ttl, resp.ip, rtt_ms, resp.is_dest
    );
}
