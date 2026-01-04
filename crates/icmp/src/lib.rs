//! ICMP traceroute driver.

use datadog_traceroute_common::{
    BadPacketError, ProbeResponse, ReceiveProbeNoPktError, TracerouteDriver, TracerouteDriverInfo,
};
use datadog_traceroute_packets::{
    FrameParser, IPPair, IcmpInfo, IcmpPacket, LayerType, PacketSink, PacketSource, read_and_parse,
};
use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_TIME_EXCEEDED: u8 = 3;

const ICMP_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;

static ECHO_ID: AtomicU32 = AtomicU32::new(0);

fn next_echo_id() -> u16 {
    (ECHO_ID.fetch_add(1, Ordering::SeqCst) + 1) as u16
}

#[derive(Debug, Clone)]
pub struct IcmpParams {
    pub target: IpAddr,
    pub min_ttl: u8,
    pub max_ttl: u8,
}

pub struct IcmpDriver {
    sink: Box<dyn PacketSink + Send>,
    source: Box<dyn PacketSource + Send>,
    buffer: Vec<u8>,
    parser: FrameParser,
    sent_probes: Mutex<HashMap<u8, Instant>>,
    local_addr: IpAddr,
    params: IcmpParams,
    echo_id: u16,
    is_ipv6: bool,
}

impl IcmpDriver {
    pub fn new(
        params: IcmpParams,
        local_addr: IpAddr,
        sink: Box<dyn PacketSink + Send>,
        source: Box<dyn PacketSource + Send>,
    ) -> Self {
        Self {
            sink,
            source,
            buffer: vec![0u8; 1024],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(HashMap::new()),
            local_addr,
            params,
            echo_id: next_echo_id(),
            is_ipv6: local_addr.is_ipv6(),
        }
    }

    pub fn close(&mut self) {
        let _ = self.source.close();
        let _ = self.sink.close();
    }

    fn store_probe(&self, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut sent = self
            .sent_probes
            .lock()
            .map_err(|_| "sent_probes mutex poisoned")?;
        if sent.contains_key(&ttl) {
            return Err(format!("icmp driver tried to send duplicate TTL {}", ttl).into());
        }
        sent.insert(ttl, Instant::now());
        Ok(())
    }

    fn get_rtt_from_seq(&self, ttl: u8) -> Result<Duration, Box<dyn Error + Send + Sync>> {
        if ttl < self.params.min_ttl || ttl > self.params.max_ttl {
            return Err(format!("invalid relative sequence number {}", ttl).into());
        }
        let sent = self
            .sent_probes
            .lock()
            .map_err(|_| "sent_probes mutex poisoned")?;
        let start = sent
            .get(&ttl)
            .ok_or_else(|| format!("no probe sent for relative sequence number {}", ttl))?;
        Ok(start.elapsed())
    }

    fn handle_icmpv4(&self) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let ip_pair = self.parser.get_ip_pair()?;
        let icmp = self
            .parser
            .icmp4_packet()
            .ok_or_else(|| BadPacketError::new("missing ICMPv4 layer"))?;
        match icmp.icmp_type {
            ICMP_TIME_EXCEEDED => self.handle_icmpv4_time_exceeded(ip_pair, icmp),
            ICMP_ECHO_REPLY => self.handle_icmpv4_echo_reply(ip_pair, icmp),
            _ => Err(Box::new(ReceiveProbeNoPktError::new(
                "icmpv4 packet did not match traceroute",
            ))),
        }
    }

    fn handle_icmpv4_time_exceeded(
        &self,
        ip_pair: IPPair,
        _icmp: &IcmpPacket,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let icmp_info = self.parser.get_icmp_info()?;
        self.validate_icmp_pair(&icmp_info)?;
        let (echo_id, seq) = parse_icmpv4_echo(&icmp_info)?;
        if echo_id != self.echo_id {
            return Err(Box::new(BadPacketError::new("mismatched echo ID")));
        }
        let ttl = seq as u8;
        let rtt = self
            .get_rtt_from_seq(ttl)
            .map_err(|err| BadPacketError::new(format!("failed to get RTT: {}", err)))?;
        Ok(ProbeResponse {
            ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: false,
        })
    }

    fn handle_icmpv4_echo_reply(
        &self,
        ip_pair: IPPair,
        icmp: &IcmpPacket,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let (echo_id, seq) = parse_icmp_header_echo(icmp);
        if echo_id != self.echo_id {
            return Err(Box::new(BadPacketError::new("mismatched echo ID")));
        }
        let ttl = seq as u8;
        let rtt = self
            .get_rtt_from_seq(ttl)
            .map_err(|err| BadPacketError::new(format!("failed to get RTT: {}", err)))?;
        Ok(ProbeResponse {
            ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: true,
        })
    }

    fn handle_icmpv6(&self) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let ip_pair = self.parser.get_ip_pair()?;
        let icmp = self
            .parser
            .icmp6_packet()
            .ok_or_else(|| BadPacketError::new("missing ICMPv6 layer"))?;
        match icmp.icmp_type {
            ICMPV6_TIME_EXCEEDED => self.handle_icmpv6_time_exceeded(ip_pair),
            ICMPV6_ECHO_REPLY => self.handle_icmpv6_echo_reply(ip_pair, icmp),
            _ => Err(Box::new(ReceiveProbeNoPktError::new(
                "icmpv6 packet did not match traceroute",
            ))),
        }
    }

    fn handle_icmpv6_time_exceeded(
        &self,
        ip_pair: IPPair,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let icmp_info = self.parser.get_icmp_info()?;
        self.validate_icmp_pair(&icmp_info)?;
        let (echo_id, seq) = parse_icmpv6_inner_echo(&icmp_info)?;
        if echo_id != self.echo_id {
            return Err(Box::new(BadPacketError::new("mismatched echo ID")));
        }
        let ttl = seq as u8;
        let rtt = self
            .get_rtt_from_seq(ttl)
            .map_err(|err| BadPacketError::new(format!("failed to get RTT: {}", err)))?;
        Ok(ProbeResponse {
            ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: false,
        })
    }

    fn handle_icmpv6_echo_reply(
        &self,
        ip_pair: IPPair,
        icmp: &IcmpPacket,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        if icmp.payload.len() < 4 {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "icmpv6 echo reply payload too short",
            )));
        }
        let echo_id = u16::from_be_bytes([icmp.payload[0], icmp.payload[1]]);
        let seq = u16::from_be_bytes([icmp.payload[2], icmp.payload[3]]);
        if echo_id != self.echo_id {
            return Err(Box::new(BadPacketError::new("mismatched echo ID")));
        }
        let ttl = seq as u8;
        let rtt = self
            .get_rtt_from_seq(ttl)
            .map_err(|err| BadPacketError::new(format!("failed to get RTT: {}", err)))?;
        Ok(ProbeResponse {
            ttl,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: true,
        })
    }

    fn validate_icmp_pair(&self, info: &IcmpInfo) -> Result<(), Box<dyn Error + Send + Sync>> {
        if info.icmp_pair.dst_addr != self.params.target {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "icmp packet had another destination",
            )));
        }
        if info.icmp_pair.src_addr != self.local_addr {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "icmp packet had another source",
            )));
        }
        Ok(())
    }
}

impl Drop for IcmpDriver {
    fn drop(&mut self) {
        self.close();
    }
}

impl TracerouteDriver for IcmpDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            supports_parallel: true,
        }
    }

    fn send_probe(&mut self, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>> {
        if ttl < self.params.min_ttl || ttl > self.params.max_ttl {
            return Err(format!("icmp driver asked to send invalid TTL {}", ttl).into());
        }
        self.store_probe(ttl)?;
        let packet = if self.is_ipv6 {
            build_ipv6_echo_request(self.local_addr, self.params.target, ttl, self.echo_id)?
        } else {
            build_ipv4_echo_request(self.local_addr, self.params.target, ttl, self.echo_id)?
        };
        let addr = SocketAddr::new(self.params.target, 80);
        self.sink.write_to(&packet, addr)?;
        Ok(())
    }

    fn receive_probe(
        &mut self,
        timeout: Duration,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let deadline = Instant::now() + timeout;
        self.source.set_read_deadline(deadline)?;
        read_and_parse(&mut *self.source, &mut self.buffer, &mut self.parser)?;

        match self.parser.get_transport_layer() {
            LayerType::Icmpv4 => self.handle_icmpv4(),
            LayerType::Icmpv6 => self.handle_icmpv6(),
            _ => Err(Box::new(ReceiveProbeNoPktError::new(
                "packet did not match traceroute",
            ))),
        }
    }
}

fn parse_icmp_header_echo(icmp: &IcmpPacket) -> (u16, u16) {
    let echo_id = u16::from_be_bytes([icmp.header_rest[0], icmp.header_rest[1]]);
    let seq = u16::from_be_bytes([icmp.header_rest[2], icmp.header_rest[3]]);
    (echo_id, seq)
}

fn parse_icmpv4_echo(info: &IcmpInfo) -> Result<(u16, u16), Box<dyn Error + Send + Sync>> {
    if info.payload.len() < 8 {
        return Err(Box::new(BadPacketError::new(
            "icmpv4 echo payload too short",
        )));
    }
    let echo_id = u16::from_be_bytes([info.payload[4], info.payload[5]]);
    let seq = u16::from_be_bytes([info.payload[6], info.payload[7]]);
    Ok((echo_id, seq))
}

fn parse_icmpv6_inner_echo(info: &IcmpInfo) -> Result<(u16, u16), Box<dyn Error + Send + Sync>> {
    if info.payload.len() < 8 {
        return Err(Box::new(BadPacketError::new("icmpv6 payload too short")));
    }
    let echo_id = u16::from_be_bytes([info.payload[4], info.payload[5]]);
    let seq = u16::from_be_bytes([info.payload[6], info.payload[7]]);
    Ok((echo_id, seq))
}

fn build_ipv4_echo_request(
    src: IpAddr,
    dst: IpAddr,
    ttl: u8,
    echo_id: u16,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let src = match src {
        IpAddr::V4(addr) => addr,
        _ => return Err("expected IPv4 source".into()),
    };
    let dst = match dst {
        IpAddr::V4(addr) => addr,
        _ => return Err("expected IPv4 destination".into()),
    };

    let mut icmp = vec![0u8; 8 + 1];
    icmp[0] = 8;
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&echo_id.to_be_bytes());
    icmp[6..8].copy_from_slice(&(ttl as u16).to_be_bytes());
    icmp[8] = ttl;
    let checksum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let total_len = 20 + icmp.len();
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&echo_id.to_be_bytes());
    ip[8] = ttl;
    ip[9] = ICMP_PROTOCOL;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum16(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    ip.extend_from_slice(&icmp);
    Ok(ip)
}

fn build_ipv6_echo_request(
    src: IpAddr,
    dst: IpAddr,
    ttl: u8,
    echo_id: u16,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let src = match src {
        IpAddr::V6(addr) => addr,
        _ => return Err("expected IPv6 source".into()),
    };
    let dst = match dst {
        IpAddr::V6(addr) => addr,
        _ => return Err("expected IPv6 destination".into()),
    };

    let mut icmp = vec![0u8; 4 + 5];
    icmp[0] = 128;
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&echo_id.to_be_bytes());
    icmp[6..8].copy_from_slice(&(ttl as u16).to_be_bytes());
    icmp[8] = ttl;
    let checksum = checksum_icmpv6(&src, &dst, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let payload_len = icmp.len() as u16;
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip[6] = ICMPV6_PROTOCOL;
    ip[7] = ttl;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip.extend_from_slice(&icmp);
    Ok(ip)
}

fn checksum_icmpv6(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(ICMPV6_PROTOCOL);
    pseudo.extend_from_slice(icmp);
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
    use datadog_traceroute_packets::PacketFilterSpec;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
                    "no more packets",
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

        fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MockSink {
        writes: Vec<(Vec<u8>, SocketAddr)>,
    }

    impl MockSink {
        fn new() -> Self {
            Self { writes: Vec::new() }
        }
    }

    impl PacketSink for MockSink {
        fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> std::io::Result<()> {
            self.writes.push((buf.to_vec(), addr));
            Ok(())
        }

        fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn build_ipv4_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        ttl: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip[8] = ttl;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        let checksum = checksum16(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip.extend_from_slice(payload);
        ip
    }

    fn build_icmpv4_message(icmp_type: u8, code: u8, rest: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + payload.len()];
        buf[0] = icmp_type;
        buf[1] = code;
        buf[4..8].copy_from_slice(&rest);
        buf[8..].copy_from_slice(payload);
        let checksum = checksum16(&buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());
        buf
    }

    fn build_ipv6_packet(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let payload_len = payload.len() as u16;
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = next_header;
        ip[7] = hop_limit;
        ip[8..24].copy_from_slice(&src.octets());
        ip[24..40].copy_from_slice(&dst.octets());
        ip.extend_from_slice(payload);
        ip
    }

    fn build_icmpv6_message(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        icmp_type: u8,
        code: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 4 + payload.len()];
        buf[0] = icmp_type;
        buf[1] = code;
        buf[4..].copy_from_slice(payload);
        let checksum = checksum_icmpv6(&src, &dst, &buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());
        buf
    }

    #[test]
    fn icmp_driver_handles_v4_time_exceeded_and_reply() {
        let target = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let local = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let params = IcmpParams {
            target,
            min_ttl: 1,
            max_ttl: 30,
        };

        let echo_id = next_echo_id();
        let mut driver = IcmpDriver {
            sink: Box::new(MockSink::new()),
            source: Box::new(MockSource::new(Vec::new())),
            buffer: vec![0u8; 1024],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(HashMap::new()),
            local_addr: local,
            params,
            echo_id,
            is_ipv6: false,
        };

        driver.send_probe(1).expect("send probe");

        let inner_echo = build_icmpv4_message(
            8,
            0,
            {
                let mut rest = [0u8; 4];
                rest[..2].copy_from_slice(&echo_id.to_be_bytes());
                rest[2..].copy_from_slice(&(1u16).to_be_bytes());
                rest
            },
            &[1u8],
        );
        let inner_ip = build_ipv4_packet(
            match local {
                IpAddr::V4(a) => a,
                _ => unreachable!(),
            },
            match target {
                IpAddr::V4(a) => a,
                _ => unreachable!(),
            },
            ICMP_PROTOCOL,
            64,
            &inner_echo,
        );
        let time_exceeded = build_icmpv4_message(11, 0, [0u8; 4], &inner_ip);
        let reply_packet = build_ipv4_packet(
            Ipv4Addr::new(42, 42, 42, 42),
            match local {
                IpAddr::V4(a) => a,
                _ => unreachable!(),
            },
            ICMP_PROTOCOL,
            64,
            &time_exceeded,
        );

        driver.source = Box::new(MockSource::new(vec![reply_packet]));
        let probe = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(probe.ttl, 1);
        assert!(!probe.is_dest);

        driver.send_probe(2).expect("send probe");
        let echo_reply_payload = {
            let mut payload = [0u8; 4];
            payload[..2].copy_from_slice(&echo_id.to_be_bytes());
            payload[2..].copy_from_slice(&(2u16).to_be_bytes());
            payload
        };
        let echo_reply = build_icmpv4_message(0, 0, echo_reply_payload, &[2u8]);
        let echo_reply_packet = build_ipv4_packet(
            match target {
                IpAddr::V4(a) => a,
                _ => unreachable!(),
            },
            match local {
                IpAddr::V4(a) => a,
                _ => unreachable!(),
            },
            ICMP_PROTOCOL,
            64,
            &echo_reply,
        );
        driver.source = Box::new(MockSource::new(vec![echo_reply_packet]));
        let probe = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(probe.ttl, 2);
        assert!(probe.is_dest);
    }

    #[test]
    fn icmp_driver_handles_v6_time_exceeded_and_reply() {
        let target = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x12, 0, 0, 0, 1));
        let local = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 2));
        let params = IcmpParams {
            target,
            min_ttl: 1,
            max_ttl: 30,
        };

        let echo_id = next_echo_id();
        let mut driver = IcmpDriver {
            sink: Box::new(MockSink::new()),
            source: Box::new(MockSource::new(Vec::new())),
            buffer: vec![0u8; 1024],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(HashMap::new()),
            local_addr: local,
            params,
            echo_id,
            is_ipv6: true,
        };

        driver.send_probe(1).expect("send probe");

        let inner_payload = {
            let mut payload = vec![0u8; 4 + 5];
            payload[0] = 128;
            payload[4..6].copy_from_slice(&echo_id.to_be_bytes());
            payload[6..8].copy_from_slice(&(1u16).to_be_bytes());
            payload[8] = 1;
            payload
        };
        let inner_ip = build_ipv6_packet(
            match local {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            match target {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            ICMPV6_PROTOCOL,
            64,
            &inner_payload,
        );
        let mut time_exceeded_payload = vec![0u8; 4];
        time_exceeded_payload.extend_from_slice(&inner_ip);
        let time_exceeded = build_icmpv6_message(
            match target {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            match local {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            ICMPV6_TIME_EXCEEDED,
            0,
            &time_exceeded_payload,
        );
        let reply_packet = build_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0, 0, 0x7334),
            match local {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            ICMPV6_PROTOCOL,
            64,
            &time_exceeded,
        );

        driver.source = Box::new(MockSource::new(vec![reply_packet]));
        let probe = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(probe.ttl, 1);
        assert!(!probe.is_dest);

        driver.send_probe(2).expect("send probe");
        let echo_reply_payload = {
            let mut payload = vec![0u8; 4 + 1];
            payload[0..2].copy_from_slice(&echo_id.to_be_bytes());
            payload[2..4].copy_from_slice(&(2u16).to_be_bytes());
            payload[4] = 2;
            payload
        };
        let echo_reply = build_icmpv6_message(
            match target {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            match local {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            ICMPV6_ECHO_REPLY,
            0,
            &echo_reply_payload,
        );
        let echo_reply_packet = build_ipv6_packet(
            match target {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            match local {
                IpAddr::V6(a) => a,
                _ => unreachable!(),
            },
            ICMPV6_PROTOCOL,
            64,
            &echo_reply,
        );
        driver.source = Box::new(MockSource::new(vec![echo_reply_packet]));
        let probe = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(probe.ttl, 2);
        assert!(probe.is_dest);
    }
}
