//! TCP SYN traceroute driver.

use datadog_traceroute_common::{
    BadPacketError, ProbeResponse, ReceiveProbeNoPktError, TracerouteDriver, TracerouteDriverInfo,
};
use datadog_traceroute_packets::{
    FrameParser, LayerType, PacketSink, PacketSource, TcpPacket, alloc_packet_id,
    parse_tcp_first_bytes, read_and_parse,
};
use std::collections::VecDeque;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IPPROTO_TCP: u8 = 6;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy)]
pub struct TcpParams {
    pub target: IpAddr,
    pub dest_port: u16,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub paris_traceroute_mode: bool,
    pub loosen_icmp_src: bool,
}

#[derive(Debug, Clone, Copy)]
struct ProbeData {
    send_time: Instant,
    ttl: u8,
    packet_id: u16,
    seq: u32,
}

pub struct TcpDriver {
    params: TcpParams,
    sink: Box<dyn PacketSink + Send>,
    source: Box<dyn PacketSource + Send>,
    buffer: Vec<u8>,
    parser: FrameParser,
    sent_probes: Mutex<VecDeque<ProbeData>>,
    base_packet_id: u16,
    base_seq: u32,
}

impl TcpDriver {
    pub fn new(
        params: TcpParams,
        sink: Box<dyn PacketSink + Send>,
        source: Box<dyn PacketSource + Send>,
    ) -> Self {
        let (base_packet_id, base_seq) = if params.paris_traceroute_mode {
            (41821, 0)
        } else {
            (alloc_packet_id(params.max_ttl), random_u32())
        };
        Self {
            params,
            sink,
            source,
            buffer: vec![0u8; 1024],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(VecDeque::new()),
            base_packet_id,
            base_seq,
        }
    }

    pub fn close(&mut self) {
        let _ = self.source.close();
        let _ = self.sink.close();
    }

    fn store_probe(&self, probe: ProbeData) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut sent = self
            .sent_probes
            .lock()
            .map_err(|_| "sent_probes mutex poisoned")?;
        sent.push_back(probe);
        Ok(())
    }

    fn last_probe(&self) -> Result<ProbeData, Box<dyn Error + Send + Sync>> {
        let sent = self
            .sent_probes
            .lock()
            .map_err(|_| "sent_probes mutex poisoned")?;
        sent.back().copied().ok_or_else(|| "no probes sent".into())
    }

    fn find_probe(&self, packet_id: u16, seq: u32) -> Option<ProbeData> {
        let sent = self.sent_probes.lock().ok()?;
        sent.iter()
            .rev()
            .find(|probe| {
                if packet_id == 0 {
                    probe.seq == seq
                } else {
                    probe.packet_id == packet_id && probe.seq == seq
                }
            })
            .copied()
    }

    fn expected_ip_pair(&self) -> (IpAddr, IpAddr) {
        (self.params.target, self.params.local_ip)
    }

    fn handle_tcp(&self, tcp: &TcpPacket) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let (src, dst) = self.expected_ip_pair();
        let ip_pair = self.parser.get_ip_pair()?;
        if ip_pair.src_addr != src || ip_pair.dst_addr != dst {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp packet ip pair mismatch",
            )));
        }
        if tcp.src_port != self.params.dest_port || tcp.dst_port != self.params.local_port {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp packet port mismatch",
            )));
        }

        let is_synack = tcp.syn && tcp.ack_flag;
        let is_rst = tcp.rst;
        let is_rstack = tcp.rst && tcp.ack_flag;
        if !is_synack && !is_rst && !is_rstack {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp packet did not match traceroute",
            )));
        }

        let last_probe = self.last_probe()?;
        if (is_synack || is_rstack) && !self.params.paris_traceroute_mode {
            let expected_seq = tcp.ack.wrapping_sub(1);
            if last_probe.seq != expected_seq {
                return Err(Box::new(ReceiveProbeNoPktError::new(
                    "tcp ack did not match sent seq",
                )));
            }
        }

        let rtt = last_probe.send_time.elapsed();
        Ok(ProbeResponse {
            ttl: last_probe.ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: true,
        })
    }

    fn handle_icmp(&self) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        if !self.parser.is_ttl_exceeded() {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp icmp packet did not match traceroute",
            )));
        }
        let ip_pair = self.parser.get_ip_pair()?;
        let icmp_info = self.parser.get_icmp_info().map_err(|err| {
            BadPacketError::new(format!("tcp driver failed to get ICMP info: {}", err))
        })?;
        let tcp_info = parse_tcp_first_bytes(&icmp_info.payload).map_err(|err| {
            BadPacketError::new(format!("tcp driver failed to parse TCP info: {}", err))
        })?;

        let icmp_src = SocketAddr::new(icmp_info.icmp_pair.src_addr, tcp_info.src_port);
        let icmp_dst = SocketAddr::new(icmp_info.icmp_pair.dst_addr, tcp_info.dst_port);
        let local = SocketAddr::new(self.params.local_ip, self.params.local_port);
        let target = SocketAddr::new(self.params.target, self.params.dest_port);

        if icmp_dst != target {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp icmp payload destination mismatch",
            )));
        }
        if !self.params.loosen_icmp_src && icmp_src != local {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp icmp payload source mismatch",
            )));
        }

        let probe = self
            .find_probe(icmp_info.wrapped_packet_id, tcp_info.seq)
            .ok_or_else(|| {
                Box::new(ReceiveProbeNoPktError::new("tcp probe not found"))
                    as Box<dyn Error + Send + Sync>
            })?;

        let rtt = probe.send_time.elapsed();
        Ok(ProbeResponse {
            ttl: probe.ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: false,
        })
    }

    fn next_packet_id_and_seq(&self, ttl: u8) -> (u16, u32) {
        if self.params.paris_traceroute_mode {
            (41821, random_u32())
        } else {
            (self.base_packet_id.wrapping_add(ttl as u16), self.base_seq)
        }
    }
}

impl Drop for TcpDriver {
    fn drop(&mut self) {
        self.close();
    }
}

impl TracerouteDriver for TcpDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            supports_parallel: false,
        }
    }

    fn send_probe(&mut self, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>> {
        if ttl < self.params.min_ttl || ttl > self.params.max_ttl {
            return Err(format!("tcp driver asked to send invalid TTL {}", ttl).into());
        }
        let (packet_id, seq) = self.next_packet_id_and_seq(ttl);
        let packet = build_tcp_packet(
            self.params.local_ip,
            self.params.local_port,
            self.params.target,
            self.params.dest_port,
            packet_id,
            seq,
            ttl,
        )?;
        self.store_probe(ProbeData {
            send_time: Instant::now(),
            ttl,
            packet_id: if self.params.target.is_ipv6() {
                0
            } else {
                packet_id
            },
            seq,
        })?;
        let addr = SocketAddr::new(self.params.target, self.params.dest_port);
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
            LayerType::Tcp => {
                let tcp = self
                    .parser
                    .tcp_packet()
                    .ok_or_else(|| BadPacketError::new("missing TCP packet"))?;
                self.handle_tcp(tcp)
            }
            LayerType::Icmpv4 | LayerType::Icmpv6 => self.handle_icmp(),
            _ => Err(Box::new(ReceiveProbeNoPktError::new(
                "tcp packet did not match traceroute",
            ))),
        }
    }
}

fn build_tcp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    packet_id: u16,
    seq: u32,
    ttl: u8,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            build_tcp_ipv4(src, src_port, dst, dst_port, packet_id, seq, ttl)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            build_tcp_ipv6(src, src_port, dst, dst_port, seq, ttl)
        }
        _ => Err("source/destination IP family mismatch".into()),
    }
}

fn build_tcp_ipv4(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    packet_id: u16,
    seq: u32,
    ttl: u8,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut tcp = vec![0u8; TCP_HEADER_LEN];
    tcp[..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
    tcp[12] = (5u8 << 4) & 0xf0;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
    tcp[16..18].copy_from_slice(&0u16.to_be_bytes());
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes());

    let checksum = tcp_checksum_ipv4(src, dst, &tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    let total_len = (IPV4_HEADER_LEN + tcp.len()) as u16;
    let mut ip = vec![0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&packet_id.to_be_bytes());
    ip[8] = ttl;
    ip[9] = IPPROTO_TCP;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum16(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(ip.len() + tcp.len());
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&tcp);
    Ok(packet)
}

fn build_tcp_ipv6(
    src: Ipv6Addr,
    src_port: u16,
    dst: Ipv6Addr,
    dst_port: u16,
    seq: u32,
    ttl: u8,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut tcp = vec![0u8; TCP_HEADER_LEN];
    tcp[..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = (5u8 << 4) & 0xf0;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());

    let checksum = tcp_checksum_ipv6(src, dst, &tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut ip = vec![0u8; IPV6_HEADER_LEN];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    ip[6] = IPPROTO_TCP;
    ip[7] = ttl;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());

    let mut packet = Vec::with_capacity(ip.len() + tcp.len());
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&tcp);
    Ok(packet)
}

fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IPPROTO_TCP);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    checksum16(&pseudo)
}

fn tcp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(IPPROTO_TCP);
    pseudo.extend_from_slice(tcp);
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

fn random_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .subsec_nanos()
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

    fn build_tcp_header(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0u8; TCP_HEADER_LEN];
        tcp[..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = (5u8 << 4) & 0xf0;
        tcp[13] = flags;
        tcp
    }

    fn build_icmpv4(type_code: u8, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + payload.len()];
        icmp[0] = type_code;
        icmp[1] = 0;
        icmp[8..].copy_from_slice(payload);
        icmp
    }

    fn build_icmpv6(type_code: u8, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0u8; 4 + payload.len()];
        icmp[0] = type_code;
        icmp[1] = 0;
        icmp[4..].copy_from_slice(payload);
        icmp
    }

    #[test]
    fn tcp_driver_handles_v4_icmp_and_synack() {
        let params = TcpParams {
            target: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dest_port: 443,
            local_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            local_port: 1234,
            min_ttl: 1,
            max_ttl: 3,
            paris_traceroute_mode: false,
            loosen_icmp_src: false,
        };
        let mut driver = TcpDriver::new(
            params,
            Box::new(MockSink),
            Box::new(MockSource::new(Vec::new())),
        );
        driver.send_probe(1).expect("send probe");

        let probe = driver.last_probe().expect("probe");
        let inner_tcp = build_tcp_header(1234, 443, probe.seq, 0, 0x02);
        let inner_ip = build_ipv4_packet(
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(1, 2, 3, 4),
            IPPROTO_TCP,
            &inner_tcp,
        );
        let icmp = build_icmpv4(11, &inner_ip);
        let packet = build_ipv4_packet(
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(5, 6, 7, 8),
            1,
            &icmp,
        );

        let synack = build_tcp_header(443, 1234, 100, probe.seq.wrapping_add(1), 0x12);
        let packet2 = build_ipv4_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            IPPROTO_TCP,
            &synack,
        );

        driver.source = Box::new(MockSource::new(vec![packet, packet2]));
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 1);
        assert!(!resp.is_dest);
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 1);
        assert!(resp.is_dest);
    }

    #[test]
    fn tcp_driver_handles_v6_icmp_and_synack() {
        let params = TcpParams {
            target: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            dest_port: 443,
            local_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            local_port: 1234,
            min_ttl: 1,
            max_ttl: 3,
            paris_traceroute_mode: false,
            loosen_icmp_src: false,
        };
        let mut driver = TcpDriver::new(
            params,
            Box::new(MockSink),
            Box::new(MockSource::new(Vec::new())),
        );
        driver.send_probe(1).expect("send probe");

        let probe = driver.last_probe().expect("probe");
        let inner_tcp = build_tcp_header(1234, 443, probe.seq, 0, 0x02);
        let inner_ip = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            IPPROTO_TCP,
            &inner_tcp,
        );
        let mut icmp_payload = vec![0u8; 4];
        icmp_payload.extend_from_slice(&inner_ip);
        let icmp = build_icmpv6(3, &icmp_payload);
        let packet = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            58,
            &icmp,
        );

        let synack = build_tcp_header(443, 1234, 100, probe.seq.wrapping_add(1), 0x12);
        let packet2 = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            IPPROTO_TCP,
            &synack,
        );

        driver.source = Box::new(MockSource::new(vec![packet, packet2]));
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 1);
        assert!(!resp.is_dest);
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 1);
        assert!(resp.is_dest);
    }
}
