//! UDP packet construction using pnet.

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::udp::MutableUdpPacket;
use std::net::{IpAddr, Ipv4Addr};
use traceroute_core::TracerouteError;

/// Magic payload used in UDP traceroute packets.
pub const MAGIC_PAYLOAD: &[u8] = b"NSMNC";

/// Base packet ID (same as Go implementation).
const BASE_PACKET_ID: u16 = 41821;

/// Creates a UDP packet for traceroute.
///
/// Returns (packet_id, packet_bytes, checksum).
pub fn create_udp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
) -> Result<(u16, Vec<u8>, u16), TracerouteError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            create_udp_packet_v4(src, dst, src_port, dst_port, ttl)
        }
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

fn create_udp_packet_v4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
) -> Result<(u16, Vec<u8>, u16), TracerouteError> {
    // Packet ID based on TTL (same as Go implementation)
    let packet_id = BASE_PACKET_ID + ttl as u16;

    // UDP payload: "NSMNC" + 3 bytes (last 2 bytes contain packet ID)
    let mut udp_payload = vec![0u8; 8];
    udp_payload[..5].copy_from_slice(MAGIC_PAYLOAD);
    udp_payload[6] = (packet_id >> 8) as u8;
    udp_payload[7] = (packet_id & 0xff) as u8;

    // Calculate sizes
    let udp_len = 8 + udp_payload.len(); // UDP header (8) + payload
    let ip_len = 20 + udp_len; // IP header (20) + UDP packet

    // Allocate buffer for the entire packet
    let mut buffer = vec![0u8; ip_len];

    // Create IPv4 packet
    let mut ip_packet = MutableIpv4Packet::new(&mut buffer)
        .ok_or_else(|| TracerouteError::Internal("Failed to create IP packet".to_string()))?;

    ip_packet.set_version(4);
    ip_packet.set_header_length(5); // 5 * 4 = 20 bytes
    ip_packet.set_total_length(ip_len as u16);
    ip_packet.set_identification(packet_id);
    ip_packet.set_flags(Ipv4Flags::DontFragment);
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);

    // Calculate IP checksum
    let checksum = pnet_packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);

    // Create UDP packet in the payload section
    let udp_start = 20; // After IP header
    {
        let mut udp_packet = MutableUdpPacket::new(&mut buffer[udp_start..])
            .ok_or_else(|| TracerouteError::Internal("Failed to create UDP packet".to_string()))?;

        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length(udp_len as u16);

        // Set payload
        udp_packet.set_payload(&udp_payload);

        // Calculate UDP checksum
        let udp_checksum =
            pnet_packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
        udp_packet.set_checksum(udp_checksum);
    }

    // Read back the checksum
    let udp_checksum = u16::from_be_bytes([buffer[udp_start + 6], buffer[udp_start + 7]]);

    Ok((packet_id, buffer, udp_checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_udp_packet() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let result = create_udp_packet(IpAddr::V4(src_ip), IpAddr::V4(dst_ip), 12345, 33434, 5);

        assert!(result.is_ok());
        let (packet_id, packet, _checksum) = result.unwrap();

        // Check packet ID
        assert_eq!(packet_id, BASE_PACKET_ID + 5);

        // Check packet length (20 IP + 8 UDP header + 8 payload = 36)
        assert_eq!(packet.len(), 36);

        // Check IP version
        assert_eq!(packet[0] >> 4, 4);

        // Check TTL
        assert_eq!(packet[8], 5);

        // Check protocol (UDP = 17)
        assert_eq!(packet[9], 17);
    }

    #[test]
    fn test_packet_id_varies_with_ttl() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let (id1, _, _) =
            create_udp_packet(IpAddr::V4(src_ip), IpAddr::V4(dst_ip), 12345, 33434, 1).unwrap();

        let (id2, _, _) =
            create_udp_packet(IpAddr::V4(src_ip), IpAddr::V4(dst_ip), 12345, 33434, 2).unwrap();

        assert_eq!(id2 - id1, 1);
    }
}
