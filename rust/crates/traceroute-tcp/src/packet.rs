//! TCP packet construction using pnet.

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr};
use traceroute_core::TracerouteError;

/// Base packet ID for Paris traceroute mode.
pub const PARIS_PACKET_ID: u16 = 41821;

/// TCP window size used in SYN packets.
const TCP_WINDOW_SIZE: u16 = 1024;

/// Creates a TCP SYN packet for traceroute.
///
/// Returns (packet_bytes, checksum).
pub fn create_tcp_syn_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    seq_num: u32,
    packet_id: u16,
) -> Result<(Vec<u8>, u16), TracerouteError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            create_tcp_syn_packet_v4(src, dst, src_port, dst_port, ttl, seq_num, packet_id)
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

fn create_tcp_syn_packet_v4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    seq_num: u32,
    packet_id: u16,
) -> Result<(Vec<u8>, u16), TracerouteError> {
    // Calculate sizes
    let tcp_len = 20; // TCP header without options
    let ip_len = 20 + tcp_len; // IP header (20) + TCP header

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
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);

    // Calculate IP checksum
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    // Create TCP packet in the payload section
    let tcp_start = 20; // After IP header
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[tcp_start..])
            .ok_or_else(|| TracerouteError::Internal("Failed to create TCP packet".to_string()))?;

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(seq_num);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes (no options)
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(TCP_WINDOW_SIZE);
        tcp_packet.set_urgent_ptr(0);

        // Calculate TCP checksum
        let tcp_checksum =
            pnet_packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
        tcp_packet.set_checksum(tcp_checksum);
    }

    // Read back the checksum
    let tcp_checksum = u16::from_be_bytes([buffer[tcp_start + 16], buffer[tcp_start + 17]]);

    Ok((buffer, tcp_checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tcp_syn_packet() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let result = create_tcp_syn_packet(
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            12345,
            80,
            5,
            0x12345678,
            PARIS_PACKET_ID,
        );

        assert!(result.is_ok());
        let (packet, _checksum) = result.unwrap();

        // Check packet length (20 IP + 20 TCP = 40)
        assert_eq!(packet.len(), 40);

        // Check IP version
        assert_eq!(packet[0] >> 4, 4);

        // Check TTL
        assert_eq!(packet[8], 5);

        // Check protocol (TCP = 6)
        assert_eq!(packet[9], 6);

        // Check TCP flags (SYN = 0x02)
        assert_eq!(packet[33] & 0x3f, 0x02);
    }

    #[test]
    fn test_tcp_seq_number() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let seq_num: u32 = 0xDEADBEEF;

        let (packet, _) = create_tcp_syn_packet(
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            12345,
            80,
            5,
            seq_num,
            PARIS_PACKET_ID,
        )
        .unwrap();

        // Sequence number is at TCP offset + 4 (bytes 24-27 in the full packet)
        let tcp_start = 20;
        let parsed_seq = u32::from_be_bytes([
            packet[tcp_start + 4],
            packet[tcp_start + 5],
            packet[tcp_start + 6],
            packet[tcp_start + 7],
        ]);
        assert_eq!(parsed_seq, seq_num);
    }

    #[test]
    fn test_paris_packet_id() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let (packet, _) = create_tcp_syn_packet(
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            12345,
            80,
            5,
            0,
            PARIS_PACKET_ID,
        )
        .unwrap();

        // Packet ID is at IP offset + 4 (bytes 4-5)
        let parsed_id = u16::from_be_bytes([packet[4], packet[5]]);
        assert_eq!(parsed_id, PARIS_PACKET_ID);
    }
}
