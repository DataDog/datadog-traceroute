use datadog_traceroute_common::{BadPacketError, ReceiveProbeNoPktError};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const ICMP_HEADER_LEN_V4: usize = 8;
const ICMP_HEADER_LEN_V6: usize = 4;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerType {
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPPair {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
}

impl IPPair {
    pub fn flipped(&self) -> IPPair {
        IPPair {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub header_rest: [u8; 4],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct IcmpInfo {
    pub ip_pair: IPPair,
    pub wrapped_packet_id: u16,
    pub icmp_pair: IPPair,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub rst: bool,
    pub options: Vec<TcpOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOption {
    pub kind: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FrameParser {
    ip_layer: LayerType,
    transport_layer: LayerType,
    ip_pair: Option<IPPair>,
    icmp4: Option<IcmpPacket>,
    icmp6: Option<IcmpPacket>,
    tcp: Option<TcpPacket>,
}

impl FrameParser {
    pub fn new() -> Self {
        Self {
            ip_layer: LayerType::Unknown,
            transport_layer: LayerType::Unknown,
            ip_pair: None,
            icmp4: None,
            icmp6: None,
            tcp: None,
        }
    }

    pub fn parse(&mut self, buffer: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        if buffer.is_empty() {
            return Err(Box::new(BadPacketError::new("parse: buffer was empty")));
        }
        let version = buffer[0] >> 4;
        match version {
            4 => self.parse_ipv4(buffer),
            6 => self.parse_ipv6(buffer),
            _ => Err(Box::new(BadPacketError::new(format!(
                "unexpected IP version {}",
                version
            )))),
        }
    }

    pub fn get_ip_layer(&self) -> LayerType {
        self.ip_layer
    }

    pub fn get_transport_layer(&self) -> LayerType {
        self.transport_layer
    }

    pub fn get_ip_pair(&self) -> Result<IPPair, Box<dyn Error + Send + Sync>> {
        self.ip_pair.ok_or_else(|| {
            Box::new(BadPacketError::new(
                "GetIPPair: IP layer not parsed before GetIPPair",
            )) as Box<dyn Error + Send + Sync>
        })
    }

    pub fn is_ttl_exceeded(&self) -> bool {
        match self.transport_layer {
            LayerType::Icmpv4 => self
                .icmp4
                .as_ref()
                .map(|icmp| icmp.icmp_type == 11 && icmp.icmp_code == 0)
                .unwrap_or(false),
            LayerType::Icmpv6 => self
                .icmp6
                .as_ref()
                .map(|icmp| icmp.icmp_type == 3 && icmp.icmp_code == 0)
                .unwrap_or(false),
            _ => false,
        }
    }

    pub fn is_destination_unreachable(&self) -> bool {
        match self.transport_layer {
            LayerType::Icmpv4 => self
                .icmp4
                .as_ref()
                .map(|icmp| icmp.icmp_type == 3)
                .unwrap_or(false),
            LayerType::Icmpv6 => self
                .icmp6
                .as_ref()
                .map(|icmp| icmp.icmp_type == 1)
                .unwrap_or(false),
            _ => false,
        }
    }

    pub fn get_icmp_info(&self) -> Result<IcmpInfo, Box<dyn Error + Send + Sync>> {
        let ip_pair = self.get_ip_pair()?;
        match self.transport_layer {
            LayerType::Icmpv4 => {
                let icmp = self.icmp4.as_ref().ok_or_else(|| {
                    Box::new(BadPacketError::new("GetICMPInfo: ICMPv4 payload missing"))
                        as Box<dyn Error + Send + Sync>
                })?;
                let inner = parse_ipv4_header(&icmp.payload)?;
                Ok(IcmpInfo {
                    ip_pair,
                    wrapped_packet_id: inner.identification,
                    icmp_pair: IPPair {
                        src_addr: IpAddr::V4(inner.src),
                        dst_addr: IpAddr::V4(inner.dst),
                    },
                    payload: inner.payload.to_vec(),
                })
            }
            LayerType::Icmpv6 => {
                let icmp = self.icmp6.as_ref().ok_or_else(|| {
                    Box::new(BadPacketError::new("GetICMPInfo: ICMPv6 payload missing"))
                        as Box<dyn Error + Send + Sync>
                })?;
                let embedded = extract_embedded_ipv6(&icmp.payload)?;
                let inner = parse_ipv6_header(embedded)?;
                let wrapped_packet_id = if inner.next_header == IPPROTO_UDP {
                    inner.payload_len as u16
                } else {
                    0
                };
                Ok(IcmpInfo {
                    ip_pair,
                    wrapped_packet_id,
                    icmp_pair: IPPair {
                        src_addr: IpAddr::V6(inner.src),
                        dst_addr: IpAddr::V6(inner.dst),
                    },
                    payload: inner.payload.to_vec(),
                })
            }
            _ => Err(Box::new(BadPacketError::new(format!(
                "GetICMPInfo: unexpected layer {:?}",
                self.transport_layer
            )))),
        }
    }

    pub fn icmp4_packet(&self) -> Option<&IcmpPacket> {
        self.icmp4.as_ref()
    }

    pub fn icmp6_packet(&self) -> Option<&IcmpPacket> {
        self.icmp6.as_ref()
    }

    pub fn tcp_packet(&self) -> Option<&TcpPacket> {
        self.tcp.as_ref()
    }

    fn parse_ipv4(&mut self, buffer: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let header = parse_ipv4_header(buffer)?;
        self.ip_layer = LayerType::Ipv4;
        self.ip_pair = Some(IPPair {
            src_addr: IpAddr::V4(header.src),
            dst_addr: IpAddr::V4(header.dst),
        });
        self.icmp4 = None;
        self.icmp6 = None;
        self.tcp = None;

        match header.protocol {
            IPPROTO_TCP => {
                let tcp = parse_tcp_header(header.payload)?;
                self.transport_layer = LayerType::Tcp;
                self.tcp = Some(tcp);
                Ok(())
            }
            IPPROTO_UDP => {
                self.transport_layer = LayerType::Udp;
                Ok(())
            }
            IPPROTO_ICMP => {
                let icmp = parse_icmp_packet(header.payload, ICMP_HEADER_LEN_V4)?;
                self.transport_layer = LayerType::Icmpv4;
                self.icmp4 = Some(icmp);
                Ok(())
            }
            _ => Err(Box::new(ReceiveProbeNoPktError::new(format!(
                "FrameParser saw unsupported IPv4 protocol {}",
                header.protocol
            )))),
        }
    }

    fn parse_ipv6(&mut self, buffer: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let header = parse_ipv6_header(buffer)?;
        self.ip_layer = LayerType::Ipv6;
        self.ip_pair = Some(IPPair {
            src_addr: IpAddr::V6(header.src),
            dst_addr: IpAddr::V6(header.dst),
        });
        self.icmp4 = None;
        self.icmp6 = None;
        self.tcp = None;

        match header.next_header {
            IPPROTO_TCP => {
                let tcp = parse_tcp_header(header.payload)?;
                self.transport_layer = LayerType::Tcp;
                self.tcp = Some(tcp);
                Ok(())
            }
            IPPROTO_UDP => {
                self.transport_layer = LayerType::Udp;
                Ok(())
            }
            IPPROTO_ICMPV6 => {
                let icmp = parse_icmp_packet(header.payload, ICMP_HEADER_LEN_V6)?;
                self.transport_layer = LayerType::Icmpv6;
                self.icmp6 = Some(icmp);
                Ok(())
            }
            _ => Err(Box::new(ReceiveProbeNoPktError::new(format!(
                "FrameParser saw unsupported IPv6 protocol {}",
                header.next_header
            )))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedIpv4<'a> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    identification: u16,
    protocol: u8,
    payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct ParsedIpv6<'a> {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    payload_len: usize,
    payload: &'a [u8],
}

fn parse_ipv4_header(buffer: &[u8]) -> Result<ParsedIpv4<'_>, Box<dyn Error + Send + Sync>> {
    if buffer.len() < IPV4_HEADER_MIN_LEN {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_ipv4: header too short ({} bytes)",
            buffer.len()
        ))));
    }
    let header_len = (buffer[0] & 0x0f) as usize * 4;
    if header_len < IPV4_HEADER_MIN_LEN || buffer.len() < header_len {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_ipv4: invalid header length {}",
            header_len
        ))));
    }
    let total_len = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
    if total_len < header_len {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_ipv4: total length {} smaller than header length {}",
            total_len, header_len
        ))));
    }
    let payload_end = total_len.min(buffer.len());
    if payload_end < header_len {
        return Err(Box::new(BadPacketError::new(
            "parse_ipv4: payload length underflow",
        )));
    }
    let src = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);
    let dst = Ipv4Addr::new(buffer[16], buffer[17], buffer[18], buffer[19]);
    Ok(ParsedIpv4 {
        src,
        dst,
        identification: u16::from_be_bytes([buffer[4], buffer[5]]),
        protocol: buffer[9],
        payload: &buffer[header_len..payload_end],
    })
}

fn parse_ipv6_header(buffer: &[u8]) -> Result<ParsedIpv6<'_>, Box<dyn Error + Send + Sync>> {
    if buffer.len() < IPV6_HEADER_LEN {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_ipv6: header too short ({} bytes)",
            buffer.len()
        ))));
    }
    let payload_len = u16::from_be_bytes([buffer[4], buffer[5]]) as usize;
    let payload_end = IPV6_HEADER_LEN + payload_len;
    if buffer.len() < payload_end {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_ipv6: buffer length {} shorter than payload end {}",
            buffer.len(),
            payload_end
        ))));
    }
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&buffer[8..24]);
    dst_octets.copy_from_slice(&buffer[24..40]);
    Ok(ParsedIpv6 {
        src: Ipv6Addr::from(src_octets),
        dst: Ipv6Addr::from(dst_octets),
        next_header: buffer[6],
        payload_len,
        payload: &buffer[IPV6_HEADER_LEN..payload_end],
    })
}

fn parse_icmp_packet(
    payload: &[u8],
    header_len: usize,
) -> Result<IcmpPacket, Box<dyn Error + Send + Sync>> {
    if payload.len() < header_len {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_icmp: buffer too short ({} bytes)",
            payload.len()
        ))));
    }
    let mut header_rest = [0u8; 4];
    if header_len >= 8 {
        header_rest.copy_from_slice(&payload[4..8]);
    }
    Ok(IcmpPacket {
        icmp_type: payload[0],
        icmp_code: payload[1],
        header_rest,
        payload: payload[header_len..].to_vec(),
    })
}

fn extract_embedded_ipv6(payload: &[u8]) -> Result<&[u8], Box<dyn Error + Send + Sync>> {
    if payload.len() >= 5 && payload[4] >> 4 == 6 {
        return Ok(&payload[4..]);
    }
    if payload.first().map(|byte| byte >> 4 == 6).unwrap_or(false) {
        return Ok(payload);
    }
    Err(Box::new(BadPacketError::new(
        "cannot locate IPv6 header in payload",
    )))
}

fn parse_tcp_header(payload: &[u8]) -> Result<TcpPacket, Box<dyn Error + Send + Sync>> {
    if payload.len() < 20 {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_tcp: buffer too short ({} bytes)",
            payload.len()
        ))));
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ack = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let flags = payload[13];
    let header_len = ((payload[12] >> 4) as usize) * 4;
    if header_len < 20 || header_len > payload.len() {
        return Err(Box::new(BadPacketError::new(format!(
            "parse_tcp: invalid header length {}",
            header_len
        ))));
    }
    let options = parse_tcp_options(&payload[20..header_len])?;
    Ok(TcpPacket {
        src_port,
        dst_port,
        seq,
        ack,
        syn: flags & 0x02 != 0,
        ack_flag: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
        options,
    })
}

fn parse_tcp_options(payload: &[u8]) -> Result<Vec<TcpOption>, Box<dyn Error + Send + Sync>> {
    let mut options = Vec::new();
    let mut idx = 0;
    while idx < payload.len() {
        let kind = payload[idx];
        match kind {
            0 => {
                options.push(TcpOption {
                    kind,
                    data: Vec::new(),
                });
                break;
            }
            1 => {
                options.push(TcpOption {
                    kind,
                    data: Vec::new(),
                });
                idx += 1;
            }
            _ => {
                if idx + 1 >= payload.len() {
                    return Err(Box::new(BadPacketError::new(
                        "parse_tcp: truncated option length",
                    )));
                }
                let len = payload[idx + 1] as usize;
                if len < 2 || idx + len > payload.len() {
                    return Err(Box::new(BadPacketError::new(format!(
                        "parse_tcp: invalid option length {}",
                        len
                    ))));
                }
                let data = payload[idx + 2..idx + len].to_vec();
                options.push(TcpOption { kind, data });
                idx += len;
            }
        }
    }
    Ok(options)
}

pub fn parse_tcp_first_bytes(buffer: &[u8]) -> Result<TcpInfo, Box<dyn Error + Send + Sync>> {
    if buffer.len() < 8 {
        return Err(Box::new(BadPacketError::new(format!(
            "ParseTCPFirstBytes: buffer too short ({} bytes)",
            buffer.len()
        ))));
    }
    Ok(TcpInfo {
        src_port: u16::from_be_bytes([buffer[0], buffer[1]]),
        dst_port: u16::from_be_bytes([buffer[2], buffer[3]]),
        seq: u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
    })
}

pub fn serialize_tcp_first_bytes(tcp: TcpInfo) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&tcp.src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&tcp.dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&tcp.seq.to_be_bytes());
    buf
}

#[cfg(test)]
mod tcp_tests {
    use super::*;

    fn build_tcp_header(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        options: &[u8],
    ) -> Vec<u8> {
        let header_len = 20 + options.len();
        let data_offset = (header_len / 4) as u8;
        let mut tcp = vec![0u8; header_len];
        tcp[..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = data_offset << 4;
        tcp[13] = flags;
        if !options.is_empty() {
            tcp[20..20 + options.len()].copy_from_slice(options);
        }
        tcp
    }

    #[test]
    fn parse_tcp_header_with_sack_option() {
        let mut options = Vec::new();
        options.push(5);
        options.push(10);
        options.extend_from_slice(&1u32.to_be_bytes());
        options.extend_from_slice(&2u32.to_be_bytes());
        options.push(1);
        options.push(1);

        let header = build_tcp_header(1234, 443, 10, 20, 0x12, &options);
        let packet = parse_tcp_header(&header).expect("tcp header parsed");

        assert_eq!(packet.src_port, 1234);
        assert_eq!(packet.dst_port, 443);
        assert!(packet.syn);
        assert!(packet.ack_flag);
        assert_eq!(packet.options.len(), 3);
        assert_eq!(packet.options[0].kind, 5);
        assert_eq!(packet.options[0].data.len(), 8);
        assert_eq!(packet.options[1].kind, 1);
        assert_eq!(packet.options[2].kind, 1);
    }
}

pub fn parse_udp_first_bytes(buffer: &[u8]) -> Result<UdpInfo, Box<dyn Error + Send + Sync>> {
    if buffer.len() < 8 {
        return Err(Box::new(BadPacketError::new(format!(
            "ParseUDPFirstBytes: buffer too short ({} bytes)",
            buffer.len()
        ))));
    }
    Ok(UdpInfo {
        src_port: u16::from_be_bytes([buffer[0], buffer[1]]),
        dst_port: u16::from_be_bytes([buffer[2], buffer[3]]),
        length: u16::from_be_bytes([buffer[4], buffer[5]]),
        checksum: u16::from_be_bytes([buffer[6], buffer[7]]),
    })
}

pub fn write_udp_first_bytes(udp: UdpInfo) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&udp.src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&udp.dst_port.to_be_bytes());
    buf[4..6].copy_from_slice(&udp.length.to_be_bytes());
    buf[6..8].copy_from_slice(&udp.checksum.to_be_bytes());
    buf
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn build_ipv4_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        identification: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = IPV4_HEADER_MIN_LEN + payload.len();
        let mut buf = vec![0u8; IPV4_HEADER_MIN_LEN];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[4..6].copy_from_slice(&identification.to_be_bytes());
        buf[8] = 64;
        buf[9] = protocol;
        buf[12..16].copy_from_slice(&src.octets());
        buf[16..20].copy_from_slice(&dst.octets());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn tcp_first_bytes_round_trip() {
        let info = TcpInfo {
            src_port: 1234,
            dst_port: 443,
            seq: 0x10203040,
        };
        let encoded = serialize_tcp_first_bytes(info);
        let parsed = parse_tcp_first_bytes(&encoded).expect("parse tcp");
        assert_eq!(parsed.src_port, info.src_port);
        assert_eq!(parsed.dst_port, info.dst_port);
        assert_eq!(parsed.seq, info.seq);
    }

    #[test]
    fn udp_first_bytes_round_trip() {
        let info = UdpInfo {
            src_port: 53,
            dst_port: 33434,
            length: 1200,
            checksum: 0xabcd,
        };
        let encoded = write_udp_first_bytes(info);
        let parsed = parse_udp_first_bytes(&encoded).expect("parse udp");
        assert_eq!(parsed.src_port, info.src_port);
        assert_eq!(parsed.dst_port, info.dst_port);
        assert_eq!(parsed.length, info.length);
        assert_eq!(parsed.checksum, info.checksum);
    }

    #[test]
    fn parse_ipv4_icmp_info_extracts_inner_payload() {
        let inner_src = Ipv4Addr::new(192, 0, 2, 10);
        let inner_dst = Ipv4Addr::new(203, 0, 113, 5);
        let inner_payload = [0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd];
        let inner_id = 0x1234;
        let inner_packet =
            build_ipv4_packet(inner_src, inner_dst, IPPROTO_TCP, inner_id, &inner_payload);

        let mut icmp_payload = vec![11, 0, 0, 0, 0, 0, 0, 0];
        icmp_payload.extend_from_slice(&inner_packet);

        let outer_src = Ipv4Addr::new(10, 0, 0, 1);
        let outer_dst = Ipv4Addr::new(8, 8, 8, 8);
        let outer_packet =
            build_ipv4_packet(outer_src, outer_dst, IPPROTO_ICMP, 0x9999, &icmp_payload);

        let mut parser = FrameParser::new();
        parser.parse(&outer_packet).expect("parse outer");
        assert_eq!(parser.get_ip_layer(), LayerType::Ipv4);
        assert_eq!(parser.get_transport_layer(), LayerType::Icmpv4);

        let info = parser.get_icmp_info().expect("icmp info");
        assert_eq!(info.ip_pair.src_addr, IpAddr::V4(outer_src));
        assert_eq!(info.ip_pair.dst_addr, IpAddr::V4(outer_dst));
        assert_eq!(info.wrapped_packet_id, inner_id);
        assert_eq!(info.icmp_pair.src_addr, IpAddr::V4(inner_src));
        assert_eq!(info.icmp_pair.dst_addr, IpAddr::V4(inner_dst));
        assert_eq!(info.payload, inner_payload);
    }
}
