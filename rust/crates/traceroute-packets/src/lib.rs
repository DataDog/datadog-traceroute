//! Packet I/O abstraction for datadog-traceroute.
//!
//! Provides platform-agnostic interfaces for sending and receiving raw packets.

pub mod parser;
pub mod platform;
pub mod sink;
pub mod source;

pub use parser::{
    parse_tcp_first_bytes, parse_udp_first_bytes, FrameParser, IcmpInfo, IpPair, TcpInfo, UdpInfo,
};
pub use sink::Sink;
pub use source::{FilterType, PacketFilterSpec, Source};

/// Handle containing both source and sink for packet I/O.
pub struct SourceSinkHandle {
    /// Packet capture source.
    pub source: Box<dyn Source>,
    /// Packet transmission sink.
    pub sink: Box<dyn Sink>,
    /// Whether the port must be closed before receiving (Windows-specific).
    pub must_close_port: bool,
}

/// Creates a Source and Sink appropriate for the current platform.
pub async fn new_source_sink(
    target_addr: std::net::IpAddr,
    use_driver: bool,
) -> Result<SourceSinkHandle, traceroute_core::TracerouteError> {
    platform::new_source_sink(target_addr, use_driver).await
}
