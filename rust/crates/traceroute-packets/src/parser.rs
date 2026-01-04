//! Frame parsing using etherparse.

use etherparse::{
    Icmpv4Header, Icmpv4Type, Icmpv6Header, Icmpv6Type, IpHeaders, PacketHeaders,
    TransportHeader,
};
use std::net::IpAddr;
use traceroute_core::TracerouteError;

/// Parsed ICMP information from a packet.
#[derive(Debug, Clone)]
pub struct IcmpInfo {
    /// ICMP type.
    pub icmp_type: u8,
    /// ICMP code.
    pub icmp_code: u8,
    /// Source/dest IPs from outer IP header.
    pub ip_pair: IpPair,
    /// Wrapped packet ID (from inner IP header if TTL exceeded).
    pub wrapped_packet_id: u16,
    /// Source/dest IPs from the wrapped IP payload.
    pub icmp_pair: IpPair,
    /// Payload from within the wrapped IP packet (first 8 bytes of TCP/UDP).
    pub payload: Vec<u8>,
}

/// IP source/destination pair.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpPair {
    /// Source IP address.
    pub src_addr: Option<IpAddr>,
    /// Destination IP address.
    pub dst_addr: Option<IpAddr>,
}

impl IpPair {
    /// Returns the pair with source and destination swapped.
    pub fn flipped(&self) -> Self {
        Self {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
        }
    }
}

/// UDP header info parsed from ICMP payload.
#[derive(Debug, Clone, Copy)]
pub struct UdpInfo {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// UDP length.
    pub length: u16,
    /// UDP checksum.
    pub checksum: u16,
}

/// TCP header info parsed from ICMP payload.
#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
}

/// Parse the first 8 bytes of a UDP header from an ICMP payload.
pub fn parse_udp_first_bytes(buf: &[u8]) -> Result<UdpInfo, TracerouteError> {
    if buf.len() < 8 {
        return Err(TracerouteError::PacketTooShort {
            expected: 8,
            actual: buf.len(),
        });
    }

    Ok(UdpInfo {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        length: u16::from_be_bytes([buf[4], buf[5]]),
        checksum: u16::from_be_bytes([buf[6], buf[7]]),
    })
}

/// Parse the first 8 bytes of a TCP header from an ICMP payload.
pub fn parse_tcp_first_bytes(buf: &[u8]) -> Result<TcpInfo, TracerouteError> {
    if buf.len() < 8 {
        return Err(TracerouteError::PacketTooShort {
            expected: 8,
            actual: buf.len(),
        });
    }

    Ok(TcpInfo {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
    })
}

/// Frame parser for network packets.
#[derive(Debug, Default)]
pub struct FrameParser {
    /// Last parsed IP source address.
    pub src_ip: Option<IpAddr>,
    /// Last parsed IP destination address.
    pub dst_ip: Option<IpAddr>,
    /// Whether the last packet was a TTL exceeded response.
    pub is_ttl_exceeded: bool,
    /// Whether the last packet was a destination unreachable response.
    pub is_dest_unreachable: bool,
    /// Whether the last packet was an ICMP Echo Reply.
    pub is_echo_reply: bool,
    /// Whether the last packet was a TCP SYN/ACK.
    pub is_syn_ack: bool,
    /// Whether the last packet was a TCP RST.
    pub is_rst: bool,
    /// ICMP info if packet was ICMP.
    pub icmp_info: Option<IcmpInfo>,
    /// TCP info if packet was TCP.
    pub tcp_info: Option<TcpInfo>,
    /// Transport layer type.
    transport_type: TransportType,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TransportType {
    #[default]
    None,
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
}

impl FrameParser {
    /// Creates a new frame parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the parser state.
    fn reset(&mut self) {
        self.src_ip = None;
        self.dst_ip = None;
        self.is_ttl_exceeded = false;
        self.is_dest_unreachable = false;
        self.is_echo_reply = false;
        self.is_syn_ack = false;
        self.is_rst = false;
        self.icmp_info = None;
        self.tcp_info = None;
        self.transport_type = TransportType::None;
    }

    /// Parses a raw packet buffer (starting from IP layer).
    pub fn parse(&mut self, data: &[u8]) -> Result<(), TracerouteError> {
        self.reset();

        let headers = PacketHeaders::from_ip_slice(data).map_err(|e| {
            TracerouteError::PacketParseFailed {
                layer: "IP",
                reason: e.to_string(),
            }
        })?;

        // Extract IP addresses
        let ip_pair = match &headers.ip {
            Some(IpHeaders::Ipv4(ipv4, _)) => {
                self.src_ip = Some(IpAddr::V4(ipv4.source.into()));
                self.dst_ip = Some(IpAddr::V4(ipv4.destination.into()));
                IpPair {
                    src_addr: self.src_ip,
                    dst_addr: self.dst_ip,
                }
            }
            Some(IpHeaders::Ipv6(ipv6, _)) => {
                self.src_ip = Some(IpAddr::V6(ipv6.source.into()));
                self.dst_ip = Some(IpAddr::V6(ipv6.destination.into()));
                IpPair {
                    src_addr: self.src_ip,
                    dst_addr: self.dst_ip,
                }
            }
            None => {
                return Err(TracerouteError::PacketParseFailed {
                    layer: "IP",
                    reason: "No IP header found".to_string(),
                });
            }
        };

        // Parse transport layer
        match headers.transport {
            Some(TransportHeader::Icmpv4(icmp)) => {
                self.transport_type = TransportType::Icmpv4;
                self.parse_icmpv4(&icmp, &headers.payload, ip_pair)?;
            }
            Some(TransportHeader::Icmpv6(icmp)) => {
                self.transport_type = TransportType::Icmpv6;
                self.parse_icmpv6(&icmp, &headers.payload, ip_pair)?;
            }
            Some(TransportHeader::Tcp(tcp)) => {
                self.transport_type = TransportType::Tcp;
                self.is_syn_ack = tcp.syn && tcp.ack;
                self.is_rst = tcp.rst;
                self.tcp_info = Some(TcpInfo {
                    src_port: tcp.source_port,
                    dst_port: tcp.destination_port,
                    seq: tcp.sequence_number,
                });
            }
            Some(TransportHeader::Udp(_)) => {
                self.transport_type = TransportType::Udp;
            }
            None => {
                return Err(TracerouteError::PacketParseFailed {
                    layer: "Transport",
                    reason: "No transport header found".to_string(),
                });
            }
        }

        Ok(())
    }

    fn parse_icmpv4(
        &mut self,
        icmp: &Icmpv4Header,
        payload: &[u8],
        ip_pair: IpPair,
    ) -> Result<(), TracerouteError> {
        let (icmp_type, icmp_code) = match icmp.icmp_type {
            Icmpv4Type::TimeExceeded(code) => {
                self.is_ttl_exceeded = true;
                (11, code.code_u8())
            }
            Icmpv4Type::DestinationUnreachable(header) => {
                self.is_dest_unreachable = true;
                (3, header.code_u8())
            }
            Icmpv4Type::EchoReply(_) => {
                self.is_echo_reply = true;
                (0, 0)
            }
            _ => {
                let bytes = icmp.icmp_type.to_bytes();
                (bytes[0], bytes[1])
            }
        };

        // For TTL exceeded and dest unreachable, parse the inner IP packet
        if self.is_ttl_exceeded || self.is_dest_unreachable {
            self.icmp_info = Some(self.parse_icmp_payload(payload, ip_pair, icmp_type, icmp_code)?);
        } else {
            self.icmp_info = Some(IcmpInfo {
                icmp_type,
                icmp_code,
                ip_pair,
                wrapped_packet_id: 0,
                icmp_pair: IpPair::default(),
                payload: Vec::new(),
            });
        }

        Ok(())
    }

    fn parse_icmpv6(
        &mut self,
        icmp: &Icmpv6Header,
        payload: &[u8],
        ip_pair: IpPair,
    ) -> Result<(), TracerouteError> {
        let (icmp_type, icmp_code) = match icmp.icmp_type {
            Icmpv6Type::TimeExceeded(code) => {
                self.is_ttl_exceeded = true;
                (3, code.code_u8())
            }
            Icmpv6Type::DestinationUnreachable(code) => {
                self.is_dest_unreachable = true;
                (1, code.code_u8())
            }
            Icmpv6Type::EchoReply(_) => {
                self.is_echo_reply = true;
                (129, 0)
            }
            _ => {
                let bytes = icmp.icmp_type.to_bytes();
                (bytes[0], bytes[1])
            }
        };

        if self.is_ttl_exceeded || self.is_dest_unreachable {
            // ICMPv6 has a 4-byte unused field before the embedded packet
            let inner_payload = if payload.len() > 4 { &payload[4..] } else { payload };
            self.icmp_info = Some(self.parse_icmp_payload(inner_payload, ip_pair, icmp_type, icmp_code)?);
        } else {
            self.icmp_info = Some(IcmpInfo {
                icmp_type,
                icmp_code,
                ip_pair,
                wrapped_packet_id: 0,
                icmp_pair: IpPair::default(),
                payload: Vec::new(),
            });
        }

        Ok(())
    }

    fn parse_icmp_payload(
        &self,
        payload: &[u8],
        ip_pair: IpPair,
        icmp_type: u8,
        icmp_code: u8,
    ) -> Result<IcmpInfo, TracerouteError> {
        // Parse the embedded IP packet
        let inner_headers = PacketHeaders::from_ip_slice(payload).map_err(|e| {
            TracerouteError::PacketParseFailed {
                layer: "Inner IP",
                reason: e.to_string(),
            }
        })?;

        let (wrapped_packet_id, icmp_pair) = match &inner_headers.ip {
            Some(IpHeaders::Ipv4(ipv4, _)) => {
                let pair = IpPair {
                    src_addr: Some(IpAddr::V4(ipv4.source.into())),
                    dst_addr: Some(IpAddr::V4(ipv4.destination.into())),
                };
                (ipv4.identification, pair)
            }
            Some(IpHeaders::Ipv6(ipv6, _)) => {
                let pair = IpPair {
                    src_addr: Some(IpAddr::V6(ipv6.source.into())),
                    dst_addr: Some(IpAddr::V6(ipv6.destination.into())),
                };
                // For IPv6 UDP, use payload length as packet ID
                (ipv6.payload_length, pair)
            }
            None => (0, IpPair::default()),
        };

        Ok(IcmpInfo {
            icmp_type,
            icmp_code,
            ip_pair,
            wrapped_packet_id,
            icmp_pair,
            payload: inner_headers.payload.to_vec(),
        })
    }

    /// Returns true if the parsed packet was a TTL exceeded response.
    pub fn is_ttl_exceeded(&self) -> bool {
        self.is_ttl_exceeded
    }

    /// Returns true if the parsed packet was a destination unreachable response.
    pub fn is_dest_unreachable(&self) -> bool {
        self.is_dest_unreachable
    }

    /// Returns the ICMP info if available.
    pub fn get_icmp_info(&self) -> Option<&IcmpInfo> {
        self.icmp_info.as_ref()
    }

    /// Returns the IP pair from the outer packet.
    pub fn get_ip_pair(&self) -> IpPair {
        IpPair {
            src_addr: self.src_ip,
            dst_addr: self.dst_ip,
        }
    }

    /// Returns true if the transport layer is ICMP.
    pub fn is_icmp(&self) -> bool {
        matches!(self.transport_type, TransportType::Icmpv4 | TransportType::Icmpv6)
    }

    /// Returns true if the transport layer is TCP.
    pub fn is_tcp(&self) -> bool {
        self.transport_type == TransportType::Tcp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = FrameParser::new();
        assert!(parser.src_ip.is_none());
        assert!(parser.dst_ip.is_none());
    }

    #[test]
    fn test_parse_udp_first_bytes() {
        let buf = [0x00, 0x50, 0x82, 0x9A, 0x00, 0x10, 0x12, 0x34];
        let info = parse_udp_first_bytes(&buf).unwrap();
        assert_eq!(info.src_port, 80);
        assert_eq!(info.dst_port, 33434);
        assert_eq!(info.length, 16);
        assert_eq!(info.checksum, 0x1234);
    }

    #[test]
    fn test_parse_tcp_first_bytes() {
        let buf = [0x00, 0x50, 0x01, 0xBB, 0x12, 0x34, 0x56, 0x78];
        let info = parse_tcp_first_bytes(&buf).unwrap();
        assert_eq!(info.src_port, 80);
        assert_eq!(info.dst_port, 443);
        assert_eq!(info.seq, 0x12345678);
    }

    #[test]
    fn test_ip_pair_flipped() {
        let pair = IpPair {
            src_addr: Some("10.0.0.1".parse().unwrap()),
            dst_addr: Some("10.0.0.2".parse().unwrap()),
        };
        let flipped = pair.flipped();
        assert_eq!(flipped.src_addr, pair.dst_addr);
        assert_eq!(flipped.dst_addr, pair.src_addr);
    }
}
