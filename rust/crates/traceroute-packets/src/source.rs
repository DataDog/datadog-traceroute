//! Packet capture source trait.

use async_trait::async_trait;
use std::time::Instant;
use traceroute_core::TracerouteError;

/// Filter type for packet capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    /// Filter for ICMP packets.
    Icmp,
    /// Filter for UDP packets.
    Udp,
    /// Filter for TCP packets.
    Tcp,
    /// Filter for TCP SYN/ACK packets.
    SynAck,
}

/// Specification for packet filtering.
#[derive(Debug, Clone)]
pub struct PacketFilterSpec {
    /// Type of filter to apply.
    pub filter_type: FilterType,
    /// Source port to filter on (if applicable).
    pub src_port: Option<u16>,
    /// Destination port to filter on (if applicable).
    pub dst_port: Option<u16>,
}

/// Trait for packet capture sources.
#[async_trait]
pub trait Source: Send + Sync {
    /// Sets the read deadline for subsequent read operations.
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError>;

    /// Reads a packet (starting at IP layer) into the buffer.
    /// Returns the number of bytes read.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TracerouteError>;

    /// Closes the source.
    async fn close(&mut self) -> Result<(), TracerouteError>;

    /// Sets a packet filter (BPF on Linux/macOS, driver filter on Windows).
    fn set_packet_filter(&mut self, spec: PacketFilterSpec) -> Result<(), TracerouteError>;
}
