//! TCP SACK packet construction using pnet.

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr};
use traceroute_core::TracerouteError;

/// TCP state for SACK traceroute.
#[derive(Debug, Clone)]
pub struct SackTcpState {
    /// Initial sequence number from our side.
    pub local_init_seq: u32,
    /// Initial acknowledgment number (server's seq + 1).
    pub local_init_ack: u32,
    /// Whether timestamps are enabled.
    pub has_ts: bool,
    /// Timestamp value to send.
    pub ts_value: u32,
    /// Timestamp echo reply.
    pub ts_ecr: u32,
}

/// Packet ID for SACK packets.
const SACK_PACKET_ID: u16 = 41821;

/// TCP window size.
const TCP_WINDOW_SIZE: u16 = 1024;

/// Creates a TCP SACK probe packet.
///
/// The packet is an ACK+PSH packet with sequence number based on the TTL.
pub fn create_sack_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    state: &SackTcpState,
) -> Result<Vec<u8>, TracerouteError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            create_sack_packet_v4(src, dst, src_port, dst_port, ttl, state)
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

fn create_sack_packet_v4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    state: &SackTcpState,
) -> Result<Vec<u8>, TracerouteError> {
    // Calculate TCP options length
    let options_len = if state.has_ts {
        12 // Timestamp (10 bytes) + 2 NOPs for alignment
    } else {
        0
    };

    // TCP header: 20 bytes base + options
    let tcp_header_len = 20 + options_len;
    let payload_len = 1; // Single byte payload (the TTL)
    let ip_len = 20 + tcp_header_len + payload_len;

    let mut buffer = vec![0u8; ip_len];

    // Create IPv4 packet
    let mut ip_packet = MutableIpv4Packet::new(&mut buffer)
        .ok_or_else(|| TracerouteError::Internal("Failed to create IP packet".to_string()))?;

    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(ip_len as u16);
    ip_packet.set_identification(SACK_PACKET_ID);
    ip_packet.set_flags(Ipv4Flags::DontFragment);
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);

    // Calculate IP checksum
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    // Create TCP packet in the payload section
    let tcp_start = 20;
    let buffer_len = buffer.len();
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[tcp_start..])
            .ok_or_else(|| TracerouteError::Internal("Failed to create TCP packet".to_string()))?;

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        // Sequence number is based on TTL
        tcp_packet.set_sequence(state.local_init_seq + ttl as u32);
        tcp_packet.set_acknowledgement(state.local_init_ack);
        // Data offset in 32-bit words
        tcp_packet.set_data_offset((tcp_header_len / 4) as u8);
        // ACK + PSH flags
        tcp_packet.set_flags(TcpFlags::ACK | TcpFlags::PSH);
        tcp_packet.set_window(TCP_WINDOW_SIZE);
        tcp_packet.set_urgent_ptr(0);

        // Set TCP options if timestamps are enabled
        if state.has_ts {
            let mut options_data = vec![0u8; options_len];
            // NOP (kind 1)
            options_data[0] = 1;
            // NOP (kind 1)
            options_data[1] = 1;
            // Timestamp option
            options_data[2] = 8; // kind
            options_data[3] = 10; // length
                                  // TS Value (4 bytes)
            let ts_val = state.ts_value + ttl as u32;
            options_data[4..8].copy_from_slice(&ts_val.to_be_bytes());
            // TS Echo Reply (4 bytes)
            options_data[8..12].copy_from_slice(&state.ts_ecr.to_be_bytes());

            tcp_packet.set_options(&[
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::timestamp(ts_val, state.ts_ecr),
            ]);
        }

        // Set payload (single byte with TTL)
        let payload_start = tcp_header_len;
        if payload_start < buffer_len - tcp_start {
            tcp_packet.set_payload(&[ttl]);
        }

        // Calculate TCP checksum
        let tcp_checksum =
            pnet_packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
        tcp_packet.set_checksum(tcp_checksum);
    }

    Ok(buffer)
}

/// Parses SACK option from TCP options and returns the minimum SACK left edge.
///
/// The minimum SACK left edge relative to local_init_seq indicates the earliest
/// TTL that was received at the destination.
pub fn get_min_sack_from_options(local_init_seq: u32, options: &[u8]) -> Option<u32> {
    let mut min_sack: Option<u32> = None;
    let mut i = 0;

    while i < options.len() {
        let kind = options[i];
        match kind {
            0 => break, // End of options
            1 => {
                // NOP
                i += 1;
            }
            5 => {
                // SACK
                if i + 1 >= options.len() {
                    break;
                }
                let len = options[i + 1] as usize;
                if i + len > options.len() || len < 2 {
                    break;
                }
                // SACK data starts at i + 2
                let sack_data = &options[i + 2..i + len];
                // Each SACK block is 8 bytes (left edge + right edge)
                for block in sack_data.chunks(8) {
                    if block.len() >= 4 {
                        let left_edge =
                            u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
                        let relative_left = left_edge.wrapping_sub(local_init_seq);
                        match min_sack {
                            Some(current) if relative_left < current => {
                                min_sack = Some(relative_left);
                            }
                            None => {
                                min_sack = Some(relative_left);
                            }
                            _ => {}
                        }
                    }
                }
                i += len;
            }
            _ => {
                // Other options
                if i + 1 >= options.len() {
                    break;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    break;
                }
                i += len;
            }
        }
    }

    min_sack
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sack_packet_without_ts() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let state = SackTcpState {
            local_init_seq: 1000,
            local_init_ack: 2000,
            has_ts: false,
            ts_value: 0,
            ts_ecr: 0,
        };

        let result =
            create_sack_packet(IpAddr::V4(src_ip), IpAddr::V4(dst_ip), 12345, 80, 5, &state);

        assert!(result.is_ok());
        let packet = result.unwrap();

        // Check packet length (20 IP + 20 TCP + 1 payload = 41)
        assert_eq!(packet.len(), 41);

        // Check IP version
        assert_eq!(packet[0] >> 4, 4);

        // Check TTL
        assert_eq!(packet[8], 5);

        // Check protocol (TCP = 6)
        assert_eq!(packet[9], 6);

        // Check TCP flags (ACK=0x10, PSH=0x08)
        assert_eq!(packet[33] & 0x3f, 0x18);
    }

    #[test]
    fn test_sack_sequence_number() {
        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let state = SackTcpState {
            local_init_seq: 1000,
            local_init_ack: 2000,
            has_ts: false,
            ts_value: 0,
            ts_ecr: 0,
        };

        let ttl = 10u8;
        let packet = create_sack_packet(
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            12345,
            80,
            ttl,
            &state,
        )
        .unwrap();

        // Sequence number is at TCP offset + 4 (bytes 24-27)
        let tcp_start = 20;
        let seq = u32::from_be_bytes([
            packet[tcp_start + 4],
            packet[tcp_start + 5],
            packet[tcp_start + 6],
            packet[tcp_start + 7],
        ]);

        assert_eq!(seq, state.local_init_seq + ttl as u32);
    }

    #[test]
    fn test_get_min_sack() {
        let local_init_seq: u32 = 1000;

        // Construct SACK option: kind=5, len=10, one block (left=1005, right=1006)
        let options = vec![
            5,  // kind
            10, // length
            0, 0, 0x03, 0xED, // left edge = 1005
            0, 0, 0x03, 0xEE, // right edge = 1006
        ];

        let min_sack = get_min_sack_from_options(local_init_seq, &options);
        assert_eq!(min_sack, Some(5)); // 1005 - 1000 = 5
    }

    #[test]
    fn test_get_min_sack_multiple_blocks() {
        let local_init_seq: u32 = 1000;

        // Two SACK blocks: (1010, 1011) and (1005, 1006)
        let options = vec![
            5,  // kind
            18, // length (2 + 8 + 8)
            0, 0, 0x03, 0xF2, // left edge = 1010
            0, 0, 0x03, 0xF3, // right edge = 1011
            0, 0, 0x03, 0xED, // left edge = 1005
            0, 0, 0x03, 0xEE, // right edge = 1006
        ];

        let min_sack = get_min_sack_from_options(local_init_seq, &options);
        assert_eq!(min_sack, Some(5)); // min(10, 5) = 5
    }
}
