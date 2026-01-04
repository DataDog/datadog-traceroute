//! TCP SACK traceroute driver.

use datadog_traceroute_common::{
    BadPacketError, ProbeResponse, ReceiveProbeNoPktError, TracerouteDriver, TracerouteDriverInfo,
};
use datadog_traceroute_packets::{
    FrameParser, IPPair, PacketSink, PacketSource, TcpOption, parse_tcp_first_bytes, read_and_parse,
};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const TCP_OPTION_SACK_PERMITTED: u8 = 4;
const TCP_OPTION_SACK: u8 = 5;
const TCP_OPTION_TIMESTAMP: u8 = 8;

const IPPROTO_TCP: u8 = 6;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_MIN_LEN: usize = 20;

#[derive(Debug)]
pub struct NotSupportedError {
    message: String,
}

impl NotSupportedError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for NotSupportedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SACK not supported for this target/source: {}",
            self.message
        )
    }
}

impl Error for NotSupportedError {}

#[derive(Debug, Clone, Copy)]
pub struct SackParams {
    pub target: SocketAddr,
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub handshake_timeout: Duration,
    pub loosen_icmp_src: bool,
}

#[derive(Debug, Clone, Copy)]
struct SackTcpState {
    local_init_seq: u32,
    local_init_ack: u32,
    has_ts: bool,
    ts_value: u32,
    ts_ecr: u32,
}

pub struct SackDriver {
    params: SackParams,
    sink: Box<dyn PacketSink + Send>,
    source: Box<dyn PacketSource + Send>,
    buffer: Vec<u8>,
    parser: FrameParser,
    send_times: Vec<Option<Instant>>,
    local_addr: IpAddr,
    local_port: u16,
    state: Option<SackTcpState>,
}

impl SackDriver {
    pub fn new(
        params: SackParams,
        local_addr: IpAddr,
        sink: Box<dyn PacketSink + Send>,
        source: Box<dyn PacketSource + Send>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if local_addr.is_ipv6() || params.target.is_ipv6() {
            return Err("SACK driver does not support IPv6".into());
        }
        Ok(Self {
            params,
            sink,
            source,
            buffer: vec![0u8; 1024],
            parser: FrameParser::new(),
            send_times: vec![None; params.max_ttl as usize + 1],
            local_addr,
            local_port: 0,
            state: None,
        })
    }

    pub fn close(&mut self) {
        let _ = self.source.close();
        let _ = self.sink.close();
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_some()
    }

    pub fn read_handshake(&mut self, local_port: u16) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.local_port = local_port;
        let deadline = Instant::now() + self.params.handshake_timeout;
        while Instant::now() < deadline {
            self.source.set_read_deadline(deadline)?;
            if let Err(err) = read_and_parse(&mut *self.source, &mut self.buffer, &mut self.parser)
            {
                if err.is::<ReceiveProbeNoPktError>() || err.is::<BadPacketError>() {
                    continue;
                }
                return Err(err);
            }
            if self.handle_handshake()? {
                return Ok(());
            }
        }
        Err("sack handshake timed out".into())
    }

    fn handle_handshake(&mut self) -> Result<bool, Box<dyn Error + Send + Sync>> {
        if self.parser.get_transport_layer() != datadog_traceroute_packets::LayerType::Tcp {
            return Ok(false);
        }
        let ip_pair = self.parser.get_ip_pair()?;
        if ip_pair != self.expected_ip_pair() {
            return Ok(false);
        }
        let tcp = self
            .parser
            .tcp_packet()
            .ok_or_else(|| BadPacketError::new("missing TCP packet"))?;
        if tcp.src_port != self.params.target.port() || tcp.dst_port != self.local_port {
            return Ok(false);
        }
        if !tcp.syn || !tcp.ack_flag {
            return Ok(false);
        }

        let mut found_sack = false;
        let mut state = SackTcpState {
            local_init_seq: tcp.ack,
            local_init_ack: tcp.seq.wrapping_add(1),
            has_ts: false,
            ts_value: 0,
            ts_ecr: 0,
        };
        for opt in &tcp.options {
            match opt.kind {
                TCP_OPTION_SACK_PERMITTED => {
                    found_sack = true;
                }
                TCP_OPTION_TIMESTAMP => {
                    if opt.data.len() < 8 {
                        return Err("sack handshake saw truncated timestamps option".into());
                    }
                    let remote_ts_value =
                        u32::from_be_bytes([opt.data[0], opt.data[1], opt.data[2], opt.data[3]]);
                    let remote_ts_ecr =
                        u32::from_be_bytes([opt.data[4], opt.data[5], opt.data[6], opt.data[7]]);
                    state.has_ts = true;
                    state.ts_value = remote_ts_ecr.wrapping_add(50);
                    state.ts_ecr = remote_ts_value;
                }
                _ => {}
            }
        }
        if !found_sack {
            return Err(Box::new(NotSupportedError::new(
                "missing SACK-permitted option",
            )));
        }
        self.state = Some(state);
        Ok(true)
    }

    fn expected_ip_pair(&self) -> IPPair {
        IPPair {
            src_addr: self.params.target.ip(),
            dst_addr: self.local_addr,
        }
    }

    fn get_min_sack(
        &self,
        local_init_seq: u32,
        options: &[TcpOption],
    ) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let mut found = false;
        let mut min = u32::MAX;
        for opt in options {
            if opt.kind != TCP_OPTION_SACK {
                continue;
            }
            let mut idx = 0;
            while idx + 8 <= opt.data.len() {
                found = true;
                let left_edge = u32::from_be_bytes([
                    opt.data[idx],
                    opt.data[idx + 1],
                    opt.data[idx + 2],
                    opt.data[idx + 3],
                ]);
                let rel = left_edge.wrapping_sub(local_init_seq);
                if rel < min {
                    min = rel;
                }
                idx += 8;
            }
        }
        if !found {
            return Err(Box::new(NotSupportedError::new(
                "endpoint returned SACK-permitted but no SACK blocks",
            )));
        }
        Ok(min)
    }

    fn rtt_for_rel_seq(&self, rel_seq: u32) -> Result<Duration, Box<dyn Error + Send + Sync>> {
        if rel_seq < self.params.min_ttl as u32 || rel_seq > self.params.max_ttl as u32 {
            return Err(format!("invalid relative sequence number {}", rel_seq).into());
        }
        let entry = self
            .send_times
            .get(rel_seq as usize)
            .and_then(|val| *val)
            .ok_or_else(|| format!("no probe sent for rel seq {}", rel_seq))?;
        Ok(entry.elapsed())
    }

    fn build_packet(&self, ttl: u8) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let state = self
            .state
            .ok_or_else(|| "sack driver handshake not finished")?;
        let src = match self.local_addr {
            IpAddr::V4(addr) => addr,
            _ => return Err("expected IPv4 local addr".into()),
        };
        let dst = match self.params.target.ip() {
            IpAddr::V4(addr) => addr,
            _ => return Err("expected IPv4 target addr".into()),
        };

        let mut options = Vec::new();
        if state.has_ts {
            let mut ts = Vec::with_capacity(10);
            ts.push(TCP_OPTION_TIMESTAMP);
            ts.push(10);
            ts.extend_from_slice(&(state.ts_value.wrapping_add(ttl as u32)).to_be_bytes());
            ts.extend_from_slice(&state.ts_ecr.to_be_bytes());
            options.extend_from_slice(&ts);
            options.push(1);
            options.push(1);
        }

        let data_offset = ((TCP_HEADER_MIN_LEN + options.len() + 3) / 4) as u8;
        let tcp_header_len = data_offset as usize * 4;
        let mut tcp = vec![0u8; tcp_header_len];
        tcp[..2].copy_from_slice(&self.local_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&self.params.target.port().to_be_bytes());
        let seq = state.local_init_seq.wrapping_add(ttl as u32);
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&state.local_init_ack.to_be_bytes());
        tcp[12] = data_offset << 4;
        tcp[13] = 0x18;
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
        if !options.is_empty() {
            tcp[TCP_HEADER_MIN_LEN..TCP_HEADER_MIN_LEN + options.len()].copy_from_slice(&options);
        }
        let checksum = tcp_checksum_ipv4(src, dst, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut ip = vec![0u8; IPV4_HEADER_LEN];
        let total_len = (IPV4_HEADER_LEN + tcp.len() + 1) as u16;
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[4..6].copy_from_slice(&41821u16.to_be_bytes());
        ip[8] = ttl;
        ip[9] = IPPROTO_TCP;
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        let ip_checksum = checksum16(&ip);
        ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let mut packet = Vec::with_capacity(ip.len() + tcp.len() + 1);
        packet.extend_from_slice(&ip);
        packet.extend_from_slice(&tcp);
        packet.push(ttl);
        Ok(packet)
    }

    fn handle_tcp(&self) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        let tcp = self
            .parser
            .tcp_packet()
            .ok_or_else(|| BadPacketError::new("missing TCP packet"))?;
        let ip_pair = self.parser.get_ip_pair()?;
        if ip_pair != self.expected_ip_pair() {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "sack tcp ip pair mismatch",
            )));
        }
        if tcp.src_port != self.params.target.port() || tcp.dst_port != self.local_port {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "sack tcp port mismatch",
            )));
        }
        if tcp.syn || tcp.rst {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "sack tcp packet did not match traceroute",
            )));
        }
        let state = self
            .state
            .ok_or_else(|| "sack driver handshake not finished")?;
        let rel_seq = self.get_min_sack(state.local_init_seq, &tcp.options)?;
        let rtt = self.rtt_for_rel_seq(rel_seq).map_err(|err| {
            BadPacketError::new(format!("sack driver failed to get RTT: {}", err))
        })?;
        Ok(ProbeResponse {
            ttl: rel_seq as u8,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: true,
        })
    }

    fn handle_icmp(&self) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        if !self.parser.is_ttl_exceeded() {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "sack icmp packet did not match traceroute",
            )));
        }
        let ip_pair = self.parser.get_ip_pair()?;
        let icmp_info = self.parser.get_icmp_info().map_err(|err| {
            BadPacketError::new(format!("sack driver failed to get ICMP info: {}", err))
        })?;
        let tcp_info = parse_tcp_first_bytes(&icmp_info.payload).map_err(|err| {
            BadPacketError::new(format!("sack driver failed to parse TCP info: {}", err))
        })?;
        let icmp_dst = SocketAddr::new(icmp_info.icmp_pair.dst_addr, tcp_info.dst_port);
        if icmp_dst != self.params.target {
            return Err(Box::new(ReceiveProbeNoPktError::new(
                "sack icmp destination mismatch",
            )));
        }
        if !self.params.loosen_icmp_src {
            let icmp_src = SocketAddr::new(icmp_info.icmp_pair.src_addr, tcp_info.src_port);
            let expected_src = SocketAddr::new(self.local_addr, self.local_port);
            if icmp_src != expected_src {
                return Err(Box::new(ReceiveProbeNoPktError::new(
                    "sack icmp source mismatch",
                )));
            }
        }
        let state = self
            .state
            .ok_or_else(|| "sack driver handshake not finished")?;
        let rel_seq = tcp_info.seq.wrapping_sub(state.local_init_seq);
        let rtt = self.rtt_for_rel_seq(rel_seq).map_err(|err| {
            BadPacketError::new(format!("sack driver failed to get RTT: {}", err))
        })?;
        Ok(ProbeResponse {
            ttl: rel_seq as u8,
            ip: ip_pair.src_addr,
            rtt,
            is_dest: ip_pair.src_addr == self.params.target.ip(),
        })
    }
}

impl TracerouteDriver for SackDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            supports_parallel: true,
        }
    }

    fn send_probe(&mut self, ttl: u8) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.is_handshake_finished() {
            return Err("sack driver handshake not finished".into());
        }
        if ttl < self.params.min_ttl || ttl > self.params.max_ttl {
            return Err(format!("sack driver asked to send invalid TTL {}", ttl).into());
        }
        let packet = self.build_packet(ttl)?;
        if self.send_times[ttl as usize].is_some() {
            return Err(format!("sack driver already sent TTL {}", ttl).into());
        }
        self.send_times[ttl as usize] = Some(Instant::now());
        self.sink.write_to(&packet, self.params.target)?;
        Ok(())
    }

    fn receive_probe(
        &mut self,
        timeout: Duration,
    ) -> Result<ProbeResponse, Box<dyn Error + Send + Sync>> {
        if !self.is_handshake_finished() {
            return Err("sack driver handshake not finished".into());
        }
        self.source.set_read_deadline(Instant::now() + timeout)?;
        read_and_parse(&mut *self.source, &mut self.buffer, &mut self.parser)?;

        match self.parser.get_transport_layer() {
            datadog_traceroute_packets::LayerType::Tcp => self.handle_tcp(),
            datadog_traceroute_packets::LayerType::Icmpv4 => self.handle_icmp(),
            _ => Err(Box::new(ReceiveProbeNoPktError::new(
                "sack packet did not match traceroute",
            ))),
        }
    }
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

        fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> std::io::Result<()> {
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

    fn build_tcp_header_with_options(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        options: &[u8],
    ) -> Vec<u8> {
        let padding = (4 - (options.len() % 4)) % 4;
        let header_len = TCP_HEADER_MIN_LEN + options.len() + padding;
        let mut tcp = vec![0u8; header_len];
        tcp[..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = ((header_len / 4) as u8) << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
        if !options.is_empty() {
            tcp[TCP_HEADER_MIN_LEN..TCP_HEADER_MIN_LEN + options.len()].copy_from_slice(options);
        }
        tcp
    }

    fn build_icmpv4(type_code: u8, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + payload.len()];
        icmp[0] = type_code;
        icmp[1] = 0;
        icmp[8..].copy_from_slice(payload);
        icmp
    }

    #[test]
    fn sack_driver_handles_tcp_sack() {
        let params = SackParams {
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
            min_ttl: 1,
            max_ttl: 5,
            handshake_timeout: Duration::from_secs(1),
            loosen_icmp_src: false,
        };
        let mut driver = SackDriver::new(
            params,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            Box::new(MockSink),
            Box::new(MockSource::new(Vec::new())),
        )
        .expect("driver");

        driver.state = Some(SackTcpState {
            local_init_seq: 100,
            local_init_ack: 200,
            has_ts: false,
            ts_value: 0,
            ts_ecr: 0,
        });
        driver.local_port = 1234;
        driver.send_times[2] = Some(Instant::now());

        let mut sack_data = Vec::new();
        sack_data.extend_from_slice(&102u32.to_be_bytes());
        sack_data.extend_from_slice(&110u32.to_be_bytes());
        let options = [
            TCP_OPTION_SACK,
            10,
            sack_data[0],
            sack_data[1],
            sack_data[2],
            sack_data[3],
            sack_data[4],
            sack_data[5],
            sack_data[6],
            sack_data[7],
        ];
        let tcp = build_tcp_header_with_options(443, 1234, 0, 0, 0x10, &options);
        let packet = build_ipv4_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            IPPROTO_TCP,
            &tcp,
        );

        driver.source = Box::new(MockSource::new(vec![packet]));
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 2);
        assert!(resp.is_dest);
    }

    #[test]
    fn sack_driver_handles_icmp_ttl_exceeded() {
        let params = SackParams {
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
            min_ttl: 1,
            max_ttl: 5,
            handshake_timeout: Duration::from_secs(1),
            loosen_icmp_src: false,
        };
        let mut driver = SackDriver::new(
            params,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            Box::new(MockSink),
            Box::new(MockSource::new(Vec::new())),
        )
        .expect("driver");
        driver.state = Some(SackTcpState {
            local_init_seq: 100,
            local_init_ack: 200,
            has_ts: false,
            ts_value: 0,
            ts_ecr: 0,
        });
        driver.local_port = 1234;
        driver.send_times[3] = Some(Instant::now());

        let inner_tcp = vec![0u8; TCP_HEADER_MIN_LEN];
        let mut inner_ip = build_ipv4_packet(
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(1, 2, 3, 4),
            IPPROTO_TCP,
            &inner_tcp,
        );
        inner_ip[4..6].copy_from_slice(&0u16.to_be_bytes());
        inner_ip[20..22].copy_from_slice(&1234u16.to_be_bytes());
        inner_ip[22..24].copy_from_slice(&443u16.to_be_bytes());
        inner_ip[24..28].copy_from_slice(&103u32.to_be_bytes());
        let icmp = build_icmpv4(11, &inner_ip);
        let packet = build_ipv4_packet(
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(5, 6, 7, 8),
            1,
            &icmp,
        );

        driver.source = Box::new(MockSource::new(vec![packet]));
        let resp = driver.receive_probe(Duration::from_secs(1)).expect("probe");
        assert_eq!(resp.ttl, 3);
        assert!(!resp.is_dest);
    }
}
