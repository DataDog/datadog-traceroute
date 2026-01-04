//! Core traits for traceroute driver implementations.

use crate::{ProbeResponse, TracerouteError};
use async_trait::async_trait;
use std::time::Duration;

/// Metadata about a TracerouteDriver implementation.
#[derive(Debug, Clone, Copy)]
pub struct TracerouteDriverInfo {
    /// Whether this driver supports parallel probe sending.
    pub supports_parallel: bool,
}

/// Core trait for traceroute implementations (TCP, UDP, ICMP, SACK).
///
/// Each protocol driver implements this trait to provide a consistent
/// interface for sending probes and receiving responses.
#[async_trait]
pub trait TracerouteDriver: Send + Sync {
    /// Returns metadata about this driver.
    fn get_driver_info(&self) -> TracerouteDriverInfo;

    /// Sends a traceroute probe with the specified TTL.
    async fn send_probe(&mut self, ttl: u8) -> Result<(), TracerouteError>;

    /// Receives a probe response with timeout.
    ///
    /// Returns `Ok(None)` if no matching response was received within the timeout.
    /// Returns `Err` for fatal errors that should stop the traceroute.
    async fn receive_probe(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProbeResponse>, TracerouteError>;

    /// Closes the driver, releasing resources.
    async fn close(&mut self) -> Result<(), TracerouteError>;
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
