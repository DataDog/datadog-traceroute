//! Error types for traceroute operations.

use std::net::IpAddr;
use thiserror::Error;

/// Main error type for traceroute operations.
#[derive(Error, Debug)]
pub enum TracerouteError {
    // Socket/IO errors
    #[error("Failed to create socket: {0}")]
    SocketCreation(#[source] std::io::Error),

    #[error("Failed to bind to address {addr}: {source}")]
    SocketBind {
        addr: IpAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("Read timeout exceeded")]
    ReadTimeout,

    #[error("Write failed: {0}")]
    WriteFailed(#[source] std::io::Error),

    // Packet errors
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Failed to parse {layer} layer: {reason}")]
    PacketParseFailed { layer: &'static str, reason: String },

    #[error("Packet did not match traceroute")]
    PacketMismatch,

    #[error("Malformed packet: {0}")]
    MalformedPacket(String),

    // Protocol errors
    #[error("SACK not supported by target {target}")]
    SackNotSupported { target: IpAddr },

    #[error("Handshake timeout")]
    HandshakeTimeout,

    #[error("Connection refused by {target}")]
    ConnectionRefused { target: IpAddr },

    // Driver errors
    #[error("Driver not available on this platform")]
    DriverNotAvailable,

    #[error("Driver initialization failed: {0}")]
    DriverInitFailed(String),

    #[error("Parallel execution not supported by this driver")]
    ParallelNotSupported,

    // DNS errors
    #[error("Failed to resolve hostname {hostname}: {source}")]
    DnsResolutionFailed {
        hostname: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // Configuration errors
    #[error("Invalid TTL range: min={min_ttl}, max={max_ttl}")]
    InvalidTtlRange { min_ttl: u8, max_ttl: u8 },

    #[error("Invalid port: {0}")]
    InvalidPort(u16),

    #[error("Unknown protocol: {0}")]
    UnknownProtocol(String),

    // Internal errors
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Operation cancelled")]
    Cancelled,
}

impl TracerouteError {
    /// Returns true if this error is retryable (e.g., timeout, packet mismatch, parse failure).
    ///
    /// Retryable errors indicate that we should continue reading packets rather than
    /// giving up. This is important because raw sockets may capture packets that aren't
    /// relevant to our traceroute (e.g., other traffic on the network).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ReadTimeout
                | Self::PacketMismatch
                | Self::MalformedPacket(_)
                | Self::PacketParseFailed { .. }
                | Self::PacketTooShort { .. }
        )
    }
}

impl From<std::io::Error> for TracerouteError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::TimedOut => TracerouteError::ReadTimeout,
            std::io::ErrorKind::WouldBlock => TracerouteError::ReadTimeout,
            _ => TracerouteError::Internal(err.to_string()),
        }
    }
}

/// Result type alias for traceroute operations.
pub type TracerouteResult<T> = Result<T, TracerouteError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retryable_errors() {
        assert!(TracerouteError::ReadTimeout.is_retryable());
        assert!(TracerouteError::PacketMismatch.is_retryable());
        assert!(TracerouteError::MalformedPacket("test".into()).is_retryable());
        assert!(TracerouteError::PacketParseFailed {
            layer: "IP",
            reason: "test".into()
        }
        .is_retryable());
        assert!(TracerouteError::PacketTooShort {
            expected: 20,
            actual: 10
        }
        .is_retryable());
        assert!(!TracerouteError::DriverNotAvailable.is_retryable());
    }
}
