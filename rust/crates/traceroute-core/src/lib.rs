//! Core types, traits, and error handling for datadog-traceroute.
//!
//! This crate provides the fundamental abstractions used throughout the
//! traceroute implementation:
//!
//! - [`TracerouteDriver`] trait for protocol implementations
//! - [`ProbeResponse`] and other core types
//! - [`TracerouteError`] for error handling
//! - Result types for traceroute output

pub mod error;
pub mod execution;
pub mod result;
pub mod traits;
pub mod types;

pub use error::TracerouteError;
pub use result::{
    DestinationInfo, PublicIpInfo, ResultDestination, Results, SourceInfo, Stats, TracerouteHop,
    TracerouteResults, TracerouteRun,
};
pub use traits::{TracerouteDriver, TracerouteDriverInfo};
pub use types::{ProbeResponse, Protocol, TcpMethod, TracerouteConfig, TracerouteParams};
