#![cfg(any(target_os = "linux", target_os = "macos"))]

use datadog_traceroute_common::TracerouteDriver;
use datadog_traceroute_icmp::{IcmpDriver, IcmpParams};
use datadog_traceroute_packets::{
    FilterConfig, PacketFilterSpec, PacketFilterType, new_source_sink,
};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn local_addr_for_target(target: IpAddr) -> std::io::Result<IpAddr> {
    let socket = match target {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
        IpAddr::V6(_) => UdpSocket::bind("[::]:0")?,
    };
    socket.connect(SocketAddr::new(target, 53))?;
    Ok(socket.local_addr()?.ip())
}

fn run_icmp_probe(target: IpAddr) -> std::io::Result<()> {
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
            Ok(_) => return Ok(()),
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
    let target = std::env::var("DD_TRACEROUTE_TARGET")
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or_else(|| IpAddr::from([8, 8, 8, 8]));
    run_icmp_probe(target).expect("icmp probe v4");
}

#[test]
#[ignore]
fn icmp_probe_ipv6() {
    let Some(value) = std::env::var("DD_TRACEROUTE_TARGET_V6").ok() else {
        return;
    };
    let target: IpAddr = value.parse().expect("valid IPv6 target");
    run_icmp_probe(target).expect("icmp probe v6");
}
