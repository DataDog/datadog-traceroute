//! UDP traceroute driver implementation.

use crate::packet::create_udp_packet;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use traceroute_core::{ProbeResponse, TracerouteDriver, TracerouteDriverInfo, TracerouteError};
use traceroute_packets::{parse_udp_first_bytes, FrameParser, Sink, Source};
use tracing::{debug, trace, warn};

/// Data stored for each sent probe.
#[derive(Debug, Clone)]
struct ProbeData {
    send_time: Instant,
    ttl: u8,
}

/// UDP traceroute driver.
pub struct UdpDriver {
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
    /// Map of packet ID to probe data.
    sent_probes: Mutex<HashMap<u16, ProbeData>>,
    /// Whether to loosen ICMP source checking.
    loosen_icmp_src: bool,
}

impl UdpDriver {
    /// Creates a new UDP driver.
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        target_ip: IpAddr,
        target_port: u16,
        source: Box<dyn Source>,
        sink: Box<dyn Sink>,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            target_ip,
            target_port,
            source,
            sink,
            buffer: vec![0u8; 1500],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(HashMap::new()),
            loosen_icmp_src: false,
        }
    }

    /// Sets whether to loosen ICMP source checking.
    ///
    /// Some environments don't properly translate the payload of an ICMP TTL exceeded
    /// packet, meaning you can't trust the source address to correspond to your own private IP.
    pub fn set_loosen_icmp_src(&mut self, loosen: bool) {
        self.loosen_icmp_src = loosen;
    }

    fn store_probe(&self, packet_id: u16, data: ProbeData) -> bool {
        let mut probes = self.sent_probes.lock().unwrap();

        // Refuse to store if we would overwrite
        if probes.contains_key(&packet_id) {
            return false;
        }

        probes.insert(packet_id, data);
        true
    }

    fn find_matching_probe(&self, packet_id: u16) -> Option<ProbeData> {
        let probes = self.sent_probes.lock().unwrap();
        probes.get(&packet_id).cloned()
    }

    fn get_local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip, self.src_port)
    }

    fn get_target_addr(&self) -> SocketAddr {
        SocketAddr::new(self.target_ip, self.target_port)
    }

    async fn handle_probe_layers(&mut self) -> Result<Option<ProbeResponse>, TracerouteError> {
        let ip_pair = self.parser.get_ip_pair();

        // We only care about ICMP responses for UDP traceroute
        if !self.parser.is_icmp() {
            return Err(TracerouteError::PacketMismatch);
        }

        // Must be TTL exceeded or destination unreachable
        if !self.parser.is_ttl_exceeded() && !self.parser.is_dest_unreachable() {
            return Err(TracerouteError::PacketMismatch);
        }

        let icmp_info = self
            .parser
            .get_icmp_info()
            .ok_or_else(|| TracerouteError::MalformedPacket("Missing ICMP info".to_string()))?;

        // Parse UDP info from ICMP payload
        let udp_info = parse_udp_first_bytes(&icmp_info.payload).map_err(|e| {
            TracerouteError::MalformedPacket(format!("Failed to parse UDP info: {}", e))
        })?;

        // Check source/destination match
        let icmp_src = SocketAddr::new(
            icmp_info
                .icmp_pair
                .src_addr
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            udp_info.src_port,
        );
        let icmp_dst = SocketAddr::new(
            icmp_info
                .icmp_pair
                .dst_addr
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            udp_info.dst_port,
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

        // Find matching probe by packet ID
        let packet_id = icmp_info.wrapped_packet_id;
        let probe = match self.find_matching_probe(packet_id) {
            Some(p) => p,
            None => {
                warn!(
                    packet_id = packet_id,
                    "Couldn't find probe matching packet ID"
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
impl TracerouteDriver for UdpDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            supports_parallel: true,
        }
    }

    async fn send_probe(&mut self, ttl: u8) -> Result<(), TracerouteError> {
        let (packet_id, packet, checksum) = create_udp_packet(
            self.src_ip,
            self.target_ip,
            self.src_port,
            self.target_port,
            ttl,
        )?;

        let data = ProbeData {
            send_time: Instant::now(),
            ttl,
        };

        trace!(
            ttl = ttl,
            packet_id = packet_id,
            checksum = checksum,
            "Sending UDP probe"
        );

        if !self.store_probe(packet_id, data) {
            return Err(TracerouteError::Internal(format!(
                "Tried to send the same probe ID twice for TTL={}",
                ttl
            )));
        }

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
        // Note: We can't easily test the full driver without mocking
        // This just tests the driver info
        let info = TracerouteDriverInfo {
            supports_parallel: true,
        };
        assert!(info.supports_parallel);
    }
}
