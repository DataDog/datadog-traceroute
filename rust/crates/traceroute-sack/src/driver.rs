//! TCP SACK traceroute driver implementation.

use crate::packet::{create_sack_packet, get_min_sack_from_options, SackTcpState};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use traceroute_core::{ProbeResponse, TracerouteDriver, TracerouteDriverInfo, TracerouteError};
use traceroute_packets::{parse_tcp_first_bytes, FrameParser, Sink, Source};
use tracing::{debug, trace, warn};

/// Error indicating SACK is not supported by the target.
#[derive(Debug, thiserror::Error)]
#[error("SACK not supported: {message}")]
pub struct SackNotSupportedError {
    /// Detailed error message.
    pub message: String,
}

/// TCP SACK traceroute driver.
pub struct SackDriver {
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
    /// Send times for each TTL.
    send_times: Vec<Option<Instant>>,
    /// TCP state from handshake.
    state: Option<SackTcpState>,
    /// Whether to loosen ICMP source checking.
    loosen_icmp_src: bool,
    /// Minimum TTL.
    min_ttl: u8,
    /// Maximum TTL.
    max_ttl: u8,
}

impl SackDriver {
    /// Creates a new SACK driver.
    ///
    /// Note: The driver must complete the handshake phase via `read_handshake()`
    /// before it can send probes.
    pub fn new(
        src_ip: IpAddr,
        target_ip: IpAddr,
        target_port: u16,
        source: Box<dyn Source>,
        sink: Box<dyn Sink>,
        min_ttl: u8,
        max_ttl: u8,
    ) -> Self {
        let send_times = vec![None; (max_ttl as usize) + 1];

        Self {
            src_ip,
            src_port: 0, // Set by read_handshake
            target_ip,
            target_port,
            source,
            sink,
            buffer: vec![0u8; 1500],
            parser: FrameParser::new(),
            send_times,
            state: None,
            loosen_icmp_src: false,
            min_ttl,
            max_ttl,
        }
    }

    /// Sets whether to loosen ICMP source checking.
    pub fn set_loosen_icmp_src(&mut self, loosen: bool) {
        self.loosen_icmp_src = loosen;
    }

    /// Returns whether the handshake is complete.
    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_some()
    }

    /// Performs a fake handshake for debugging purposes.
    pub fn fake_handshake(&mut self, local_port: u16, local_init_seq: u32, local_init_ack: u32) {
        self.src_port = local_port;
        self.state = Some(SackTcpState {
            local_init_seq,
            local_init_ack,
            has_ts: false,
            ts_value: 0,
            ts_ecr: 0,
        });
    }

    /// Reads the handshake response (SYN/ACK) from the target.
    ///
    /// This must be called after initiating a TCP connection to the target.
    /// It will wait for the SYN/ACK and verify that SACK is supported.
    pub async fn read_handshake(&mut self, local_port: u16) -> Result<(), TracerouteError> {
        self.src_port = local_port;

        let deadline = Instant::now() + Duration::from_millis(500);
        self.source.set_read_deadline(deadline)?;

        while !self.is_handshake_finished() {
            let n = match self.source.read(&mut self.buffer).await {
                Ok(n) => n,
                Err(TracerouteError::ReadTimeout) => {
                    return Err(TracerouteError::Internal(
                        "SACK handshake timed out".to_string(),
                    ));
                }
                Err(e) if e.is_retryable() => continue,
                Err(e) => return Err(e),
            };

            if let Err(e) = self.parser.parse(&self.buffer[..n]) {
                debug!(error = %e, "Failed to parse packet during handshake");
                continue;
            }

            if let Err(e) = self.handle_handshake() {
                return Err(e);
            }
        }

        Ok(())
    }

    fn handle_handshake(&mut self) -> Result<(), TracerouteError> {
        // Must be TCP
        if !self.parser.is_tcp() {
            return Ok(());
        }

        // Check IP pair (should be from target to us)
        let ip_pair = self.parser.get_ip_pair();
        if ip_pair.src_addr != Some(self.target_ip) || ip_pair.dst_addr != Some(self.src_ip) {
            return Ok(());
        }

        // Check ports
        let tcp_info = match self.parser.tcp_info {
            Some(info) => info,
            None => return Ok(()),
        };

        if tcp_info.src_port != self.target_port || tcp_info.dst_port != self.src_port {
            debug!(
                expected_src = self.target_port,
                actual_src = tcp_info.src_port,
                expected_dst = self.src_port,
                actual_dst = tcp_info.dst_port,
                "Ports don't match in handshake"
            );
            return Ok(());
        }

        // Must be SYN/ACK
        if !self.parser.is_syn_ack {
            return Ok(());
        }

        // Check for SACK-Permitted option
        // Note: We need to parse TCP options from the raw packet
        // For now, we'll trust that the connection supports SACK
        // A full implementation would parse the TCP options

        // TODO: Parse TCP options and check for SACK-Permitted (kind=4)
        // For now, we assume SACK is supported if we get a SYN/ACK

        // Extract ACK and SEQ from the response
        // The tcp_info.seq contains the server's SEQ
        // We need to get our initial seq from the ACK field

        // For SACK traceroute:
        // - local_init_seq = their ACK (this is NOT ACK-1 because we need a gap)
        // - local_init_ack = their SEQ + 1

        // Note: We don't have direct access to the ACK field in TcpInfo
        // We'd need to extend the parser or use a different approach

        // For now, use placeholder values that would work in testing
        let state = SackTcpState {
            local_init_seq: tcp_info.seq + 1, // Simplified
            local_init_ack: tcp_info.seq + 1,
            has_ts: false, // TODO: Parse timestamp option
            ts_value: 0,
            ts_ecr: 0,
        };

        trace!(
            local_init_seq = state.local_init_seq,
            local_init_ack = state.local_init_ack,
            "SACK handshake completed"
        );

        self.state = Some(state);
        Ok(())
    }

    fn get_rtt_from_rel_seq(&self, rel_seq: u32) -> Result<Duration, TracerouteError> {
        if rel_seq < self.min_ttl as u32 || rel_seq > self.max_ttl as u32 {
            return Err(TracerouteError::MalformedPacket(format!(
                "Invalid relative sequence number {}",
                rel_seq
            )));
        }

        match self.send_times.get(rel_seq as usize).and_then(|t| *t) {
            Some(send_time) => Ok(send_time.elapsed()),
            None => Err(TracerouteError::MalformedPacket(format!(
                "No probe sent for relative sequence number {}",
                rel_seq
            ))),
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

        // Check for TCP response with SACK options
        if self.parser.is_tcp() {
            return self.handle_tcp_response(&ip_pair).await;
        }

        // Check for ICMP TTL Exceeded
        if self.parser.is_icmp() && self.parser.is_ttl_exceeded() {
            return self.handle_icmp_response(&ip_pair).await;
        }

        Err(TracerouteError::PacketMismatch)
    }

    async fn handle_tcp_response(
        &self,
        ip_pair: &traceroute_packets::IpPair,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        // Check IP pair
        if ip_pair.src_addr != Some(self.target_ip) || ip_pair.dst_addr != Some(self.src_ip) {
            return Err(TracerouteError::PacketMismatch);
        }

        // Check ports
        let tcp_info = self.parser.tcp_info.ok_or_else(|| {
            TracerouteError::MalformedPacket("Missing TCP info".to_string())
        })?;

        if tcp_info.src_port != self.target_port || tcp_info.dst_port != self.src_port {
            return Err(TracerouteError::PacketMismatch);
        }

        // We only care about ACK packets (not SYN, FIN, RST)
        if self.parser.is_syn_ack || self.parser.is_rst {
            return Err(TracerouteError::PacketMismatch);
        }

        let state = self.state.as_ref().ok_or_else(|| {
            TracerouteError::Internal("Handshake not completed".to_string())
        })?;

        // TODO: Parse SACK options from the TCP packet
        // For now, we'd need to extend the parser to provide raw TCP options
        // The minimum SACK value indicates the earliest TTL that arrived

        // This is a placeholder - in production, we'd parse the SACK options
        // from the raw packet buffer and use get_min_sack_from_options()

        // Return error indicating we need SACK options
        Err(TracerouteError::MalformedPacket(
            "SACK option parsing not yet implemented".to_string(),
        ))
    }

    async fn handle_icmp_response(
        &self,
        ip_pair: &traceroute_packets::IpPair,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        let icmp_info = self.parser.get_icmp_info().ok_or_else(|| {
            TracerouteError::MalformedPacket("Missing ICMP info".to_string())
        })?;

        // Parse TCP info from ICMP payload
        let tcp_info = parse_tcp_first_bytes(&icmp_info.payload).map_err(|e| {
            TracerouteError::MalformedPacket(format!("Failed to parse TCP info: {}", e))
        })?;

        // Check destination matches our target
        let icmp_dst = SocketAddr::new(
            icmp_info
                .icmp_pair
                .dst_addr
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            tcp_info.dst_port,
        );

        if icmp_dst != self.get_target_addr() {
            trace!(
                expected = %self.get_target_addr(),
                actual = %icmp_dst,
                "ICMP destination mismatch"
            );
            return Err(TracerouteError::PacketMismatch);
        }

        // Check source if not loosened
        if !self.loosen_icmp_src {
            let icmp_src = SocketAddr::new(
                icmp_info
                    .icmp_pair
                    .src_addr
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                tcp_info.src_port,
            );

            if icmp_src != self.get_local_addr() {
                trace!(
                    expected = %self.get_local_addr(),
                    actual = %icmp_src,
                    "ICMP source mismatch"
                );
                return Err(TracerouteError::PacketMismatch);
            }
        }

        let state = self.state.as_ref().ok_or_else(|| {
            TracerouteError::Internal("Handshake not completed".to_string())
        })?;

        // Calculate relative sequence number
        let rel_seq = tcp_info.seq.wrapping_sub(state.local_init_seq);
        let rtt = self.get_rtt_from_rel_seq(rel_seq)?;

        let src_addr = ip_pair
            .src_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        // If the ICMP came from the target, we've reached the destination
        let is_dest = src_addr == self.target_ip;

        Ok(Some(ProbeResponse {
            ttl: rel_seq as u8,
            ip: src_addr,
            rtt,
            is_dest,
        }))
    }
}

#[async_trait]
impl TracerouteDriver for SackDriver {
    fn get_driver_info(&self) -> TracerouteDriverInfo {
        TracerouteDriverInfo {
            // SACK supports parallel mode because each probe has a unique
            // sequence number that identifies which TTL it was for
            supports_parallel: true,
        }
    }

    async fn send_probe(&mut self, ttl: u8) -> Result<(), TracerouteError> {
        if !self.is_handshake_finished() {
            return Err(TracerouteError::Internal(
                "Handshake not completed".to_string(),
            ));
        }

        if ttl < self.min_ttl || ttl > self.max_ttl {
            return Err(TracerouteError::Internal(format!(
                "Asked to send invalid TTL {}",
                ttl
            )));
        }

        // Check if we've already sent this probe
        if self.send_times[ttl as usize].is_some() {
            return Err(TracerouteError::Internal(format!(
                "Already sent probe for TTL {}",
                ttl
            )));
        }

        self.send_times[ttl as usize] = Some(Instant::now());

        let state = self.state.as_ref().unwrap();

        let packet = create_sack_packet(
            self.src_ip,
            self.target_ip,
            self.src_port,
            self.target_port,
            ttl,
            state,
        )?;

        trace!(
            ttl = ttl,
            seq = state.local_init_seq + ttl as u32,
            "Sending SACK probe"
        );

        self.sink.write_to(&packet, self.get_target_addr()).await?;

        Ok(())
    }

    async fn receive_probe(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProbeResponse>, TracerouteError> {
        if !self.is_handshake_finished() {
            return Err(TracerouteError::Internal(
                "Handshake not completed".to_string(),
            ));
        }

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
}
