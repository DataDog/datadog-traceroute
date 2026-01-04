//! UDP traceroute driver.

use datadog_traceroute_common::{
    BadPacketError, ProbeResponse, ReceiveProbeNoPktError, TracerouteDriver, TracerouteDriverInfo,
};
use datadog_traceroute_packets::{
    FrameParser, LayerType, PacketSink, PacketSource, parse_udp_first_bytes, read_and_parse,
};
use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAGIC: &[u8] = b"NSMNC";
const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy)]
pub struct UdpParams {
    pub target: IpAddr,
    pub target_port: u16,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub loosen_icmp_src: bool,
}

#[derive(Debug, Clone, Copy)]
struct ProbeData {
    send_time: Instant,
    ttl: u8,
}

pub struct UdpDriver {
    params: UdpParams,
    sink: Box<dyn PacketSink + Send>,
    source: Box<dyn PacketSource + Send>,
    buffer: Vec<u8>,
    parser: FrameParser,
    sent_probes: Mutex<HashMap<u16, ProbeData>>,
}

impl UdpDriver {
    pub fn new(
        params: UdpParams,
        sink: Box<dyn PacketSink + Send>,
        source: Box<dyn PacketSource + Send>,
    ) -> Self {
        Self {
            params,
            sink,
            source,
            buffer: vec![0u8; 1024],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(HashMap::new()),
        }
    }

    pub fn close(&mut self) {
        let _ = self.source.close();
        let _ = self.sink.close();
    }

    fn store_probe(&self, probe_id: u16, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut sent = self
            .sent_probes
            .lock()
            .map_err(|_| "sent_probes mutex poisoned")?;
        if sent.contains_key(&probe_id) {
            return Err(format!("udp driver tried to reuse probe id {}", probe_id).into());
        }
        sent.insert(
            probe_id,
            ProbeData {
                send_time: Instant::now(),
                ttl,
            },
        );
        Ok(())
    }

    fn find_probe(&self, probe_id: u16) -> Option<ProbeData> {
        let sent = self.sent_probes.lock().ok()?;
        sent.get(&probe_id).copied()
    }

    fn handle_icmp(&self) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        if !self.parser.is_ttl_exceeded() && !self.parser.is_destination_unreachable() {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "udp packet did not match traceroute",
            )));
        }
        let ip_pair = self.parser.get_ip_pair()?;
        let icmp_info = self.parser.get_icmp_info().map_err(|err| {
            BadPacketError::new(format!("udp driver failed to get ICMP info: {}", err))
        })?;

        let udp_info = parse_udp_first_bytes(&icmp_info.payload).map_err(|err| {
            BadPacketError::new(format!("udp driver failed to parse UDP info: {}", err))
        })?;

        let icmp_src = SocketAddr::new(icmp_info.icmp_pair.src_addr, udp_info.src_port);
        let icmp_dst = SocketAddr::new(icmp_info.icmp_pair.dst_addr, udp_info.dst_port);
        let local = SocketAddr::new(self.params.local_ip, self.params.local_port);
        let target = SocketAddr::new(self.params.target, self.params.target_port);

        if icmp_dst != target {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "udp icmp payload destination mismatch",
            )));
        }
        if !self.params.loosen_icmp_src && icmp_src != local {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "udp icmp payload source mismatch",
            )));
        }

        let probe_id = icmp_info.wrapped_packet_id;
        let probe = self.find_probe(probe_id).ok_or_else(|| {
            Box::new(ReceiveProbeNoPktError::new("udp probe not found"))
                as Box<dyn Error + Send + Sync>
        })?;

        let rtt = probe.send_time.elapsed();
        Ok(ProbeResponse {
            ttl: probe.ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: ip_pair.src_addr == self.params.target,
        })
    }
}

impl TracerouteDriver for UdpDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            supports_parallel: true,
        }
    }

    fn send_probe(&mut self, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>> {
        if ttl < self.params.min_ttl || ttl > self.params.max_ttl {
            return Err(format!("udp driver asked to send invalid TTL {}", ttl).into());
        }
        let (probe_id, packet) = build_udp_packet(
            self.params.local_ip,
            self.params.local_port,
            self.params.target,
            self.params.target_port,
            ttl,
        )?;
        self.store_probe(probe_id, ttl)?;
        let addr = SocketAddr::new(self.params.target, self.params.target_port);
        self.sink.write_to(&packet, addr)?;
        Ok(())
    }

    fn receive_probe(
        &mut self,
        timeout: Duration,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        self.source.set_read_deadline(Instant::now() + timeout)?;
        read_and_parse(&mut *self.source, &mut self.buffer, &mut self.parser)?;

        match self.parser.get_transport_layer() {
            LayerType::Icmpv4 | LayerType::Icmpv6 => self.handle_icmp(),
            _ => Err(Box::new(ReceiveProbeNoPktError::new(
                "udp packet did not match traceroute",
            ))),
        }
    }
}

fn build_udp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    ttl: u8,
) -> Result<(u16, Vec<u8>), Box<dyn Error + Send + Sync>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_udp_ipv4(src, src_port, dst, dst_port, ttl),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_udp_ipv6(src, src_port, dst, dst_port, ttl),
        _ => Err("source/destination IP family mismatch".into()),
    }
}

fn build_udp_ipv4(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    ttl: u8,
) -> Result<(u16, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let id = 41821u16.wrapping_add(ttl as u16);
    let mut payload = vec![0u8; 8];
    payload[..MAGIC.len()].copy_from_slice(MAGIC);
    payload[6] = (id >> 8) as u8;
    payload[7] = id as u8;

    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let mut udp = vec![0u8; UDP_HEADER_LEN];
    udp[..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());

    let checksum = udp_checksum_ipv4(src, dst, &udp, &payload);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let total_len = (IPV4_HEADER_LEN + udp.len() + payload.len()) as u16;
    let mut ip = vec![0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = ttl;
    ip[9] = IPPROTO_UDP;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum16(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(ip.len() + udp.len() + payload.len());
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&udp);
    packet.extend_from_slice(&payload);
    Ok((id, packet))
}

fn build_udp_ipv6(
    src: Ipv6Addr,
    src_port: u16,
    dst: Ipv6Addr,
    dst_port: u16,
    ttl: u8,
) -> Result<(u16, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let payload_len = MAGIC.len() + ttl as usize;
    let mut payload = Vec::with_capacity(payload_len);
    while payload.len() < payload_len {
        payload.extend_from_slice(MAGIC);
    }
    payload.truncate(payload_len);

    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let mut udp = vec![0u8; UDP_HEADER_LEN];
    udp[..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());

    let checksum = udp_checksum_ipv6(src, dst, &udp, &payload);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut ip = vec![0u8; IPV6_HEADER_LEN];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&udp_len.to_be_bytes());
    ip[6] = IPPROTO_UDP;
    ip[7] = ttl;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());

    let mut packet = Vec::with_capacity(ip.len() + udp.len() + payload.len());
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&udp);
    packet.extend_from_slice(&payload);
    let probe_id = udp_len;
    Ok((probe_id, packet))
}

fn udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8], payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len() + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IPPROTO_UDP);
    pseudo.extend_from_slice(&(udp.len() as u16 + payload.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

fn udp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8], payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len() + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    let len = (udp.len() + payload.len()) as u32;
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(IPPROTO_UDP);
    pseudo.extend_from_slice(udp);
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&tail) = chunks.remainder().first() {
        sum += (tail as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSource {
        packets: Vec<Vec<u8>>,
        idx: usize,
    }

    impl MockSource {
        fn new(packets: Vec<Vec<u8>>) -> Self {
            Self { packets, idx: 0 }
        }
    }

    impl PacketSource for MockSource {
        fn set_read_deadline(&mut self, _deadline: Instant) -> std::io::Result<()> {
            Ok(())
        }

        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.idx >= self.packets.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no packets",
                ));
            }
            let packet = &self.packets[self.idx];
            self.idx += 1;
            let n = packet.len().min(buf.len());
            buf[..n].copy_from_slice(&packet[..n]);
            Ok(n)
        }

        fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn set_packet_filter(
            &mut self,
            _spec: datadog_traceroute_packets::PacketFilterSpec,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MockSink;

    impl PacketSink for MockSink {
        fn write_to(&mut self, _buf: &[u8], _addr: SocketAddr) -> std::io::Result<()> {
            Ok(())
        }

        fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = (IPV4_HEADER_LEN + payload.len()) as u16;
        let mut ip = vec![0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        let checksum = checksum16(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip.extend_from_slice(payload);
        ip
    }

    fn build_inner_ipv4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        id: u16,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = (IPV4_HEADER_LEN + payload.len()) as u16;
        let mut ip = vec![0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[4..6].copy_from_slice(&id.to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        let checksum = checksum16(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip.extend_from_slice(payload);
        ip
    }

    fn build_icmpv4(type_code: u8, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + payload.len()];
        icmp[0] = type_code;
        icmp[1] = 0;
        icmp[8..].copy_from_slice(payload);
        icmp
    }

    fn build_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; IPV6_HEADER_LEN];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        ip[6] = next_header;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&src.octets());
        ip[24..40].copy_from_slice(&dst.octets());
        ip.extend_from_slice(payload);
        ip
    }

    fn build_icmpv6(type_code: u8, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0u8; 4 + payload.len()];
        icmp[0] = type_code;
        icmp[1] = 0;
        icmp[4..].copy_from_slice(payload);
        icmp
    }

    #[test]
    fn udp_driver_handles_v4_time_exceeded_and_unreachable() {
        let params = UdpParams {
            target: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            target_port: 33434,
            local_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            local_port: 1234,
            min_ttl: 1,
            max_ttl: 3,
            loosen_icmp_src: false,
        };
        let mut driver = UdpDriver::new(
            params,
            Box::new(MockSink),
            Box::new(MockSource::new(Vec::new())),
        );
        driver.send_probe(1).expect("send probe");
        driver.send_probe(2).expect("send probe");

        let id1 = 41821u16 + 1;
        let mut udp = vec![0u8; 8];
        udp[..2].copy_from_slice(&1234u16.to_be_bytes());
        udp[2..4].copy_from_slice(&33434u16.to_be_bytes());
        let inner = build_inner_ipv4(
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(1, 2, 3, 4),
            id1,
            IPPROTO_UDP,
            &udp,
        );
        let icmp = build_icmpv4(11, &inner);
        let packet = build_ipv4_packet(
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(5, 6, 7, 8),
            1,
            &icmp,
        );

        let id2 = 41821u16 + 2;
        let inner2 = build_inner_ipv4(
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(1, 2, 3, 4),
            id2,
            IPPROTO_UDP,
            &udp,
        );
        let icmp2 = build_icmpv4(3, &inner2);
        let packet2 = build_ipv4_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1,
            &icmp2,
        );

        driver.source = Box::new(MockSource::new(vec![packet, packet2]));
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 1);
        assert!(!resp.is_dest);
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 2);
        assert!(resp.is_dest);
    }

    #[test]
    fn udp_driver_handles_v6_time_exceeded_and_unreachable() {
        let params = UdpParams {
            target: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            target_port: 33434,
            local_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            local_port: 1234,
            min_ttl: 1,
            max_ttl: 3,
            loosen_icmp_src: false,
        };
        let mut driver = UdpDriver::new(
            params,
            Box::new(MockSink),
            Box::new(MockSource::new(Vec::new())),
        );
        driver.send_probe(1).expect("send probe");
        driver.send_probe(2).expect("send probe");

        let udp_len_one = (UDP_HEADER_LEN + MAGIC.len() + 1) as u16;
        let mut udp_one = vec![0u8; 8];
        udp_one[..2].copy_from_slice(&1234u16.to_be_bytes());
        udp_one[2..4].copy_from_slice(&33434u16.to_be_bytes());
        udp_one[4..6].copy_from_slice(&udp_len_one.to_be_bytes());
        let udp_payload_one = vec![0u8; udp_len_one as usize - UDP_HEADER_LEN];
        let udp_packet_one = [udp_one.as_slice(), udp_payload_one.as_slice()].concat();

        let inner = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            IPPROTO_UDP,
            &udp_packet_one,
        );
        let mut icmp_payload = vec![0u8; 4];
        icmp_payload.extend_from_slice(&inner);
        let icmp = build_icmpv6(3, &icmp_payload);
        let packet = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            58,
            &icmp,
        );

        let udp_len_two = (UDP_HEADER_LEN + MAGIC.len() + 2) as u16;
        let mut udp_two = vec![0u8; 8];
        udp_two[..2].copy_from_slice(&1234u16.to_be_bytes());
        udp_two[2..4].copy_from_slice(&33434u16.to_be_bytes());
        udp_two[4..6].copy_from_slice(&udp_len_two.to_be_bytes());
        let udp_payload_two = vec![0u8; udp_len_two as usize - UDP_HEADER_LEN];
        let udp_packet_two = [udp_two.as_slice(), udp_payload_two.as_slice()].concat();

        let inner2 = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            IPPROTO_UDP,
            &udp_packet_two,
        );
        let mut icmp_payload2 = vec![0u8; 4];
        icmp_payload2.extend_from_slice(&inner2);
        let icmp2 = build_icmpv6(1, &icmp_payload2);
        let packet2 = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            58,
            &icmp2,
        );

        driver.source = Box::new(MockSource::new(vec![packet, packet2]));
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 1);
        assert!(!resp.is_dest);
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 2);
        assert!(resp.is_dest);
    }
}
