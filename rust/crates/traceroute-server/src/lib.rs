//! HTTP REST API server for datadog-traceroute.

mod handlers;
mod runner;

pub use handlers::create_router;
pub use runner::run_traceroute;

/// Default server port (IANA Remote Traceroute).
pub const DEFAULT_PORT: u16 = 3765;
