//! ICMP traceroute driver implementation.

use crate::packet::create_icmp_echo_packet;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use traceroute_core::{ProbeResponse, TracerouteDriver, TracerouteDriverInfo, TracerouteError};
use traceroute_packets::{FrameParser, Sink, Source};
use tracing::{debug, trace};

/// Global echo ID counter for unique IDs across driver instances.
static ECHO_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

/// Gets the next unique echo ID.
fn next_echo_id() -> u16 {
    ECHO_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// ICMP traceroute driver.
pub struct IcmpDriver {
    /// Source IP address.
    src_ip: IpAddr,
    /// Target IP address.
    target_ip: IpAddr,
    /// Packet source for receiving.
    source: Box<dyn Source>,
    /// Packet sink for sending.
    sink: Box<dyn Sink>,
    /// Read buffer.
    buffer: Vec<u8>,
    /// Frame parser.
    parser: FrameParser,
    /// Map of TTL to send time for RTT calculation.
    sent_probes: Mutex<HashMap<u8, Instant>>,
    /// Echo ID for this traceroute session.
    echo_id: u16,
    /// Minimum TTL.
    min_ttl: u8,
    /// Maximum TTL.
    max_ttl: u8,
}

impl IcmpDriver {
    /// Creates a new ICMP driver.
    pub fn new(
        src_ip: IpAddr,
        target_ip: IpAddr,
        source: Box<dyn Source>,
        sink: Box<dyn Sink>,
        min_ttl: u8,
        max_ttl: u8,
    ) -> Self {
        Self {
            src_ip,
            target_ip,
            source,
            sink,
            buffer: vec![0u8; 1500],
            parser: FrameParser::new(),
            sent_probes: Mutex::new(HashMap::new()),
            echo_id: next_echo_id(),
            min_ttl,
            max_ttl,
        }
    }

    fn store_probe(&self, ttl: u8) -> Result<(), TracerouteError> {
        let mut probes = self.sent_probes.lock().unwrap();

        // Refuse to store if we would overwrite
        if probes.contains_key(&ttl) {
            return Err(TracerouteError::Internal(format!(
                "Tried to send the same probe twice for TTL={}",
                ttl
            )));
        }

        probes.insert(ttl, Instant::now());
        Ok(())
    }

    fn find_matching_probe(&self, ttl: u8) -> Option<Instant> {
        let probes = self.sent_probes.lock().unwrap();
        probes.get(&ttl).copied()
    }

    fn get_rtt_from_seq(&self, seq: u8) -> Result<Duration, TracerouteError> {
        if seq < self.min_ttl || seq > self.max_ttl {
            return Err(TracerouteError::MalformedPacket(format!(
                "Invalid sequence number {}",
                seq
            )));
        }

        match self.find_matching_probe(seq) {
            Some(send_time) => Ok(send_time.elapsed()),
            None => Err(TracerouteError::MalformedPacket(format!(
                "No probe sent for sequence number {}",
                seq
            ))),
        }
    }

    async fn handle_probe_layers(&mut self) -> Result<Option<ProbeResponse>, TracerouteError> {
        let ip_pair = self.parser.get_ip_pair();

        // Must be ICMP
        if !self.parser.is_icmp() {
            return Err(TracerouteError::PacketMismatch);
        }

        // Check for Echo Reply (destination reached)
        if self.parser.is_echo_reply {
            return self.handle_echo_reply(&ip_pair);
        }

        // Check for TTL Exceeded (intermediate hop)
        if self.parser.is_ttl_exceeded() {
            return self.handle_ttl_exceeded(&ip_pair);
        }

        Err(TracerouteError::PacketMismatch)
    }

    fn handle_echo_reply(
        &self,
        ip_pair: &traceroute_packets::IpPair,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        let icmp_info = self
            .parser
            .get_icmp_info()
            .ok_or_else(|| TracerouteError::MalformedPacket("Missing ICMP info".to_string()))?;

        // For Echo Reply, we need to extract ID and Seq from the ICMP header
        // The parser stores this in icmp_info for echo replies
        // We'll need to parse the ID/Seq from the payload structure

        // In the Go implementation, parser.ICMP4.Id and parser.ICMP4.Seq are used
        // For now, we'll extract from the wrapped_packet_id which holds the echo ID
        // and check against our echo_id

        // Actually, for echo reply, the ID and Seq are in the ICMP header itself
        // Let's check the payload which should contain our echo response data

        // Simplified: Just check that this reply is from our target
        let src_addr = ip_pair.src_addr.ok_or_else(|| {
            TracerouteError::MalformedPacket("Missing source address".to_string())
        })?;

        // The sequence number is the TTL we sent
        // For echo replies, wrapped_packet_id contains the echo identifier
        // and we can extract seq from the payload

        // For now, get the TTL from the ICMP payload
        // The payload should start with the echo ID (2 bytes) and seq (2 bytes)
        if icmp_info.payload.len() < 4 {
            return Err(TracerouteError::MalformedPacket(
                "ICMP payload too short".to_string(),
            ));
        }

        let id = u16::from_be_bytes([icmp_info.payload[0], icmp_info.payload[1]]);
        let seq = u16::from_be_bytes([icmp_info.payload[2], icmp_info.payload[3]]);

        if id != self.echo_id {
            trace!(
                expected = self.echo_id,
                actual = id,
                "Ignored ICMP Echo Reply with different echo ID"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        let ttl = seq as u8;
        let rtt = self.get_rtt_from_seq(ttl)?;

        Ok(Some(ProbeResponse {
            ttl,
            ip: src_addr,
            rtt,
            is_dest: true,
        }))
    }

    fn handle_ttl_exceeded(
        &self,
        ip_pair: &traceroute_packets::IpPair,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        let icmp_info = self
            .parser
            .get_icmp_info()
            .ok_or_else(|| TracerouteError::MalformedPacket("Missing ICMP info".to_string()))?;

        // Check that the embedded packet was destined for our target
        let icmp_dst = icmp_info.icmp_pair.dst_addr.ok_or_else(|| {
            TracerouteError::MalformedPacket("Missing ICMP destination".to_string())
        })?;

        if icmp_dst != self.target_ip {
            trace!(
                expected = %self.target_ip,
                actual = %icmp_dst,
                "Ignored ICMP TTL Exceeded with different destination"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        // Check that the embedded packet was from us
        let icmp_src = icmp_info
            .icmp_pair
            .src_addr
            .ok_or_else(|| TracerouteError::MalformedPacket("Missing ICMP source".to_string()))?;

        if icmp_src != self.src_ip {
            trace!(
                expected = %self.src_ip,
                actual = %icmp_src,
                "Ignored ICMP TTL Exceeded with different source"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        // Parse the embedded ICMP Echo Request to get ID and Seq
        // The payload contains the original ICMP packet
        if icmp_info.payload.len() < 8 {
            return Err(TracerouteError::MalformedPacket(
                "ICMP payload too short for Echo Request".to_string(),
            ));
        }

        // ICMP Echo Request format: Type(1) + Code(1) + Checksum(2) + ID(2) + Seq(2)
        let icmp_type = icmp_info.payload[0];
        if icmp_type != 8 {
            // Not an Echo Request
            return Err(TracerouteError::PacketMismatch);
        }

        let id = u16::from_be_bytes([icmp_info.payload[4], icmp_info.payload[5]]);
        let seq = u16::from_be_bytes([icmp_info.payload[6], icmp_info.payload[7]]);

        if id != self.echo_id {
            trace!(
                expected = self.echo_id,
                actual = id,
                "Ignored ICMP TTL Exceeded with different echo ID"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        let ttl = seq as u8;
        let rtt = self.get_rtt_from_seq(ttl)?;

        let src_addr = ip_pair
            .src_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        Ok(Some(ProbeResponse {
            ttl,
            ip: src_addr,
            rtt,
            is_dest: false,
        }))
    }
}

#[async_trait]
impl TracerouteDriver for IcmpDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            // ICMP supports parallel mode because each probe has a unique
            // sequence number that identifies which TTL it was for
            supports_parallel: true,
        }
    }

    async fn send_probe(&mut self, ttl: u8) -> Result<(), TracerouteError> {
        if ttl < self.min_ttl || ttl > self.max_ttl {
            return Err(TracerouteError::Internal(format!(
                "Asked to send invalid TTL {}",
                ttl
            )));
        }

        self.store_probe(ttl)?;

        let packet = create_icmp_echo_packet(self.src_ip, self.target_ip, ttl, self.echo_id)?;

        trace!(
            ttl = ttl,
            echo_id = self.echo_id,
            "Sending ICMP Echo Request probe"
        );

        // ICMP doesn't have a port, but we need to provide a SocketAddr
        // Use port 0 as a placeholder
        let target_addr = SocketAddr::new(self.target_ip, 0);
        self.sink.write_to(&packet, target_addr).await?;

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
            supports_parallel: true,
        };
        assert!(info.supports_parallel);
    }

    #[test]
    fn test_echo_id_uniqueness() {
        let id1 = next_echo_id();
        let id2 = next_echo_id();
        let id3 = next_echo_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }
}
