//! ICMP packet construction using pnet.

use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use std::net::{IpAddr, Ipv4Addr};
use traceroute_core::TracerouteError;

/// Creates an ICMP Echo Request packet for traceroute.
///
/// Returns the packet bytes.
pub fn create_icmp_echo_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ttl: u8,
    echo_id: u16,
) -> Result<Vec<u8>, TracerouteError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => create_icmp_echo_packet_v4(src, dst, ttl, echo_id),
        (IpAddr::V6(_src), IpAddr::V6(_dst)) => {
            // TODO: Implement IPv6
            Err(TracerouteError::Internal(
                "IPv6 not yet implemented".to_string(),
            ))
        }
        _ => Err(TracerouteError::Internal(
            "IP version mismatch between source and destination".to_string(),
        )),
    }
}

fn create_icmp_echo_packet_v4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    echo_id: u16,
) -> Result<Vec<u8>, TracerouteError> {
    // ICMP Echo Request: 8 bytes header + 1 byte payload (ttl)
    let icmp_len = 8 + 1;
    let ip_len = 20 + icmp_len;

    let mut buffer = vec![0u8; ip_len];

    // Create IPv4 packet
    let mut ip_packet = MutableIpv4Packet::new(&mut buffer)
        .ok_or_else(|| TracerouteError::Internal("Failed to create IP packet".to_string()))?;

    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(ip_len as u16);
    ip_packet.set_identification(echo_id);
    ip_packet.set_flags(Ipv4Flags::DontFragment);
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);

    // Calculate IP checksum
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    // Create ICMP Echo Request in the payload section
    let icmp_start = 20;
    {
        let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer[icmp_start..])
            .ok_or_else(|| TracerouteError::Internal("Failed to create ICMP packet".to_string()))?;

        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(IcmpCode::new(0));
        icmp_packet.set_identifier(echo_id);
        // Sequence number is the TTL - this is how we identify which probe got a response
        icmp_packet.set_sequence_number(ttl as u16);
        // Payload is just the TTL byte
        icmp_packet.set_payload(&[ttl]);
    }

    // Calculate ICMP checksum using IcmpPacket view
    {
        let icmp_view = IcmpPacket::new(&buffer[icmp_start..])
            .ok_or_else(|| TracerouteError::Internal("Failed to create ICMP view".to_string()))?;
        let icmp_checksum = pnet_packet::icmp::checksum(&icmp_view);
        buffer[icmp_start + 2] = (icmp_checksum >> 8) as u8;
        buffer[icmp_start + 3] = (icmp_checksum & 0xff) as u8;
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_icmp_echo_packet() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let result = create_icmp_echo_packet(IpAddr::V4(src_ip), IpAddr::V4(dst_ip), 5, 12345);

        assert!(result.is_ok());
        let packet = result.unwrap();

        // Check packet length (20 IP + 8 ICMP header + 1 payload = 29)
        assert_eq!(packet.len(), 29);

        // Check IP version
        assert_eq!(packet[0] >> 4, 4);

        // Check TTL
        assert_eq!(packet[8], 5);

        // Check protocol (ICMP = 1)
        assert_eq!(packet[9], 1);

        // Check ICMP type (Echo Request = 8)
        assert_eq!(packet[20], 8);

        // Check ICMP code (0)
        assert_eq!(packet[21], 0);
    }

    #[test]
    fn test_echo_id_and_seq() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let echo_id: u16 = 0xABCD;
        let ttl: u8 = 10;

        let packet =
            create_icmp_echo_packet(IpAddr::V4(src_ip), IpAddr::V4(dst_ip), ttl, echo_id).unwrap();

        // Echo ID is at ICMP offset + 4 (bytes 24-25)
        let icmp_start = 20;
        let parsed_id = u16::from_be_bytes([packet[icmp_start + 4], packet[icmp_start + 5]]);
        assert_eq!(parsed_id, echo_id);

        // Sequence number is at ICMP offset + 6 (bytes 26-27)
        let parsed_seq = u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]]);
        assert_eq!(parsed_seq, ttl as u16);
    }
}
