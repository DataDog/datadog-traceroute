//! Packet transmission sink trait.

use async_trait::async_trait;
use std::net::SocketAddr;
use traceroute_core::TracerouteError;

/// Trait for packet transmission.
#[async_trait]
pub trait Sink: Send + Sync {
    /// Writes an IP packet to the given address.
    async fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<(), TracerouteError>;

    /// Closes the sink.
    async fn close(&mut self) -> Result<(), TracerouteError>;
}
