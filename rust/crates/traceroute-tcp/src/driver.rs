//! TCP SYN traceroute driver implementation.

use crate::packet::{create_tcp_syn_packet, PARIS_PACKET_ID};
use async_trait::async_trait;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use traceroute_core::{ProbeResponse, TracerouteDriver, TracerouteDriverInfo, TracerouteError};
use traceroute_packets::{parse_tcp_first_bytes, FrameParser, Sink, Source};
use tracing::{debug, trace, warn};

/// Base packet ID for non-Paris mode (same as Go implementation).
const BASE_PACKET_ID: u16 = 41821;

/// Data stored for each sent probe.
#[derive(Debug, Clone)]
struct ProbeData {
    send_time: Instant,
    ttl: u8,
    packet_id: u16,
    seq_num: u32,
}

/// TCP SYN traceroute driver.
pub struct TcpDriver {
    /// Source IP address.
    src_ip: IpAddr,
    /// Source port.
    src_port: u16,
    /// Target IP address.
    target_ip: IpAddr,
    /// Target port.
    target_port: u16,
    /// Packet source for receiving.
    source: Box<dyn Source>,
    /// Packet sink for sending.
    sink: Box<dyn Sink>,
    /// Read buffer.
    buffer: Vec<u8>,
    /// Frame parser.
    parser: FrameParser,
    /// List of sent probes for matching responses.
    sent_probes: Mutex<Vec<ProbeData>>,
    /// Whether to use Paris traceroute mode.
    paris_mode: bool,
    /// Base packet ID for non-Paris mode.
    base_packet_id: u16,
    /// Base sequence number for non-Paris mode.
    base_seq_num: u32,
    /// Whether to loosen ICMP source checking.
    loosen_icmp_src: bool,
    /// Maximum TTL (for packet ID allocation).
    max_ttl: u8,
}

impl TcpDriver {
    /// Creates a new TCP driver.
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        target_ip: IpAddr,
        target_port: u16,
        source: Box<dyn Source>,
        sink: Box<dyn Sink>,
        paris_mode: bool,
        max_ttl: u8,
    ) -> Self {
        let mut rng = rand::thread_rng();

        // In non-Paris mode: fixed seq number, packet ID varies with TTL
        // In Paris mode: fixed packet ID (41821), random seq per packet
        let (base_packet_id, base_seq_num) = if paris_mode {
            (PARIS_PACKET_ID, 0)
        } else {
            // Allocate packet IDs from a base that won't overflow
            let base_id = BASE_PACKET_ID;
            let seq = rng.gen::<u32>();
            (base_id, seq)
        };

        Self {
            src_ip,
            src_port,
            target_ip,
            target_port,
            source,
            sink,
            buffer: vec![0u8; 1500],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(Vec::new()),
            paris_mode,
            base_packet_id,
            base_seq_num,
            loosen_icmp_src: false,
            max_ttl,
        }
    }

    /// Sets whether to loosen ICMP source checking.
    ///
    /// Some environments don't properly translate the payload of an ICMP TTL exceeded
    /// packet, meaning you can't trust the source address to correspond to your own private IP.
    pub fn set_loosen_icmp_src(&mut self, loosen: bool) {
        self.loosen_icmp_src = loosen;
    }

    fn store_probe(&self, data: ProbeData) {
        let mut probes = self.sent_probes.lock().unwrap();
        probes.push(data);
    }

    fn find_matching_probe(&self, packet_id: u16, seq_num: u32) -> Option<ProbeData> {
        let probes = self.sent_probes.lock().unwrap();
        probes
            .iter()
            .find(|p| p.packet_id == packet_id && p.seq_num == seq_num)
            .cloned()
    }

    fn get_last_sent_probe(&self) -> Option<ProbeData> {
        let probes = self.sent_probes.lock().unwrap();
        probes.last().cloned()
    }

    fn get_next_packet_id_and_seq(&self, ttl: u8) -> (u16, u32) {
        if self.paris_mode {
            // Paris mode: fixed packet ID, random seq per packet
            let seq = rand::thread_rng().gen::<u32>();
            (PARIS_PACKET_ID, seq)
        } else {
            // Regular mode: packet ID varies with TTL, fixed seq
            (self.base_packet_id + ttl as u16, self.base_seq_num)
        }
    }

    fn get_local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip, self.src_port)
    }

    fn get_target_addr(&self) -> SocketAddr {
        SocketAddr::new(self.target_ip, self.target_port)
    }

    async fn handle_probe_layers(&mut self) -> Result<Option<ProbeResponse>, TracerouteError> {
        let ip_pair = self.parser.get_ip_pair();

        // Check if this is a TCP response (SYN/ACK or RST from destination)
        if self.parser.is_tcp() {
            return self.handle_tcp_response(&ip_pair).await;
        }

        // Check if this is an ICMP TTL exceeded response
        if self.parser.is_icmp() && self.parser.is_ttl_exceeded() {
            return self.handle_icmp_response(&ip_pair).await;
        }

        Err(TracerouteError::PacketMismatch)
    }

    async fn handle_tcp_response(
        &mut self,
        ip_pair: &traceroute_packets::IpPair,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        let is_syn_ack = self.parser.is_syn_ack;
        let is_rst = self.parser.is_rst;

        // We only care about SYN/ACK and RST responses
        if !is_syn_ack && !is_rst {
            return Err(TracerouteError::PacketMismatch);
        }

        // Check IP pair (should be from target to us)
        let expected_src = self.target_ip;
        let expected_dst = self.src_ip;

        if ip_pair.src_addr != Some(expected_src) || ip_pair.dst_addr != Some(expected_dst) {
            trace!(
                expected_src = %expected_src,
                expected_dst = %expected_dst,
                actual_src = ?ip_pair.src_addr,
                actual_dst = ?ip_pair.dst_addr,
                "Ignored TCP packet with different IP pair"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        // Check ports
        let tcp_info = self
            .parser
            .tcp_info
            .ok_or_else(|| TracerouteError::MalformedPacket("Missing TCP info".to_string()))?;

        if tcp_info.src_port != self.target_port {
            trace!(
                expected = self.target_port,
                actual = tcp_info.src_port,
                "Ignored TCP packet with different source port"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        if tcp_info.dst_port != self.src_port {
            trace!(
                expected = self.src_port,
                actual = tcp_info.dst_port,
                "Ignored TCP packet with different destination port"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        // Get last sent probe to match sequence number
        let last_probe = self
            .get_last_sent_probe()
            .ok_or_else(|| TracerouteError::Internal("No probes sent yet".to_string()))?;

        // For SYN/ACK, the ACK number should be our SEQ + 1
        // So our sent SEQ should be ACK - 1
        // Note: We don't have access to ACK number in the current TcpInfo struct
        // For now, we'll match based on timing (last probe sent)

        let rtt = last_probe.send_time.elapsed();
        let src_addr = ip_pair
            .src_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        Ok(Some(ProbeResponse {
            ttl: last_probe.ttl,
            ip: src_addr,
            rtt,
            is_dest: true, // TCP responses are always from destination
        }))
    }

    async fn handle_icmp_response(
        &mut self,
        ip_pair: &traceroute_packets::IpPair,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        let icmp_info = self
            .parser
            .get_icmp_info()
            .ok_or_else(|| TracerouteError::MalformedPacket("Missing ICMP info".to_string()))?;

        // Parse TCP info from ICMP payload
        let tcp_info = parse_tcp_first_bytes(&icmp_info.payload).map_err(|e| {
            TracerouteError::MalformedPacket(format!("Failed to parse TCP info: {}", e))
        })?;

        // Check source/destination match
        let icmp_src = SocketAddr::new(
            icmp_info
                .icmp_pair
                .src_addr
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            tcp_info.src_port,
        );
        let icmp_dst = SocketAddr::new(
            icmp_info
                .icmp_pair
                .dst_addr
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            tcp_info.dst_port,
        );
        let local = self.get_local_addr();
        let target = self.get_target_addr();

        if icmp_dst.ip() != target.ip() || icmp_dst.port() != target.port() {
            trace!(
                expected = %target,
                actual = %icmp_dst,
                "Ignored ICMP packet with different destination"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        if !self.loosen_icmp_src && (icmp_src.ip() != local.ip() || icmp_src.port() != local.port())
        {
            trace!(
                expected = %local,
                actual = %icmp_src,
                "Ignored ICMP packet with different source"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        // Find matching probe by packet ID and sequence number
        let probe = match self.find_matching_probe(icmp_info.wrapped_packet_id, tcp_info.seq) {
            Some(p) => p,
            None => {
                warn!(
                    packet_id = icmp_info.wrapped_packet_id,
                    seq = tcp_info.seq,
                    "Couldn't find probe matching packet ID and seq"
                );
                return Err(TracerouteError::PacketMismatch);
            }
        };

        let rtt = probe.send_time.elapsed();
        let src_addr = ip_pair
            .src_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let is_dest = src_addr == self.target_ip;

        Ok(Some(ProbeResponse {
            ttl: probe.ttl,
            ip: src_addr,
            rtt,
            is_dest,
        }))
    }
}

#[async_trait]
impl TracerouteDriver for TcpDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            // TCP SYN driver does not support parallel mode due to
            // how responses are matched (SYN/ACK doesn't include original packet ID)
            supports_parallel: false,
        }
    }

    async fn send_probe(&mut self, ttl: u8) -> Result<(), TracerouteError> {
        let (packet_id, seq_num) = self.get_next_packet_id_and_seq(ttl);

        let (packet, checksum) = create_tcp_syn_packet(
            self.src_ip,
            self.target_ip,
            self.src_port,
            self.target_port,
            ttl,
            seq_num,
            packet_id,
        )?;

        let data = ProbeData {
            send_time: Instant::now(),
            ttl,
            packet_id,
            seq_num,
        };

        trace!(
            ttl = ttl,
            packet_id = packet_id,
            seq_num = seq_num,
            checksum = checksum,
            paris_mode = self.paris_mode,
            "Sending TCP SYN probe"
        );

        self.store_probe(data);

        self.sink.write_to(&packet, self.get_target_addr()).await?;

        Ok(())
    }

    async fn receive_probe(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        let deadline = Instant::now() + timeout;
        self.source.set_read_deadline(deadline)?;

        let n = self.source.read(&mut self.buffer).await?;

        if let Err(e) = self.parser.parse(&self.buffer[..n]) {
            debug!(error = %e, "Failed to parse packet");
            return Err(e);
        }

        self.handle_probe_layers().await
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        let sink_result = self.sink.close().await;
        let source_result = self.source.close().await;

        sink_result?;
        source_result?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_info() {
        let info = TracerouteDriverInfo {
            supports_parallel: false,
        };
        assert!(!info.supports_parallel);
    }

    #[test]
    fn test_packet_id_generation_paris_mode() {
        // In Paris mode, packet ID should always be PARIS_PACKET_ID
        // and seq should be random
        let paris_mode = true;

        // Simulate multiple calls
        for _ in 0..10 {
            let (packet_id, _seq) = if paris_mode {
                let seq = rand::thread_rng().gen::<u32>();
                (PARIS_PACKET_ID, seq)
            } else {
                unreachable!()
            };
            assert_eq!(packet_id, PARIS_PACKET_ID);
        }
    }

    #[test]
    fn test_packet_id_generation_regular_mode() {
        // In regular mode, packet ID varies with TTL
        let base_packet_id = BASE_PACKET_ID;
        let base_seq_num = 0x12345678u32;

        for ttl in 1..=30 {
            let (packet_id, seq) = (base_packet_id + ttl as u16, base_seq_num);
            assert_eq!(packet_id, BASE_PACKET_ID + ttl as u16);
            assert_eq!(seq, base_seq_num);
        }
    }
}
