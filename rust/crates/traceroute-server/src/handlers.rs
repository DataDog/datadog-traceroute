//! HTTP request handlers.

use crate::runner;
use axum::{
    extract::Query,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use traceroute_core::{Protocol, Results, TracerouteConfig, TracerouteParams};

/// Query parameters for the traceroute endpoint.
#[derive(Debug, Deserialize)]
pub struct TracerouteQuery {
    /// Target hostname or IP address.
    pub target: String,
    /// Protocol to use (udp, tcp, icmp).
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Destination port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Maximum TTL.
    #[serde(default = "default_max_ttl")]
    pub max_ttl: Option<u8>,
    /// Timeout per probe in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout: Option<u64>,
    /// Number of traceroute queries.
    #[serde(default = "default_queries")]
    pub queries: Option<usize>,
    /// Use IPv6.
    #[serde(default)]
    pub ipv6: bool,
}

fn default_protocol() -> String {
    "udp".to_string()
}

fn default_port() -> u16 {
    33434
}

fn default_max_ttl() -> Option<u8> {
    Some(30)
}

fn default_timeout() -> Option<u64> {
    Some(3000)
}

fn default_queries() -> Option<usize> {
    Some(3)
}

/// Error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Creates the Axum router with all endpoints.
pub fn create_router() -> Router {
    Router::new()
        .route("/traceroute", get(handle_traceroute))
        .route("/health", get(handle_health))
}

/// Health check endpoint.
async fn handle_health() -> &'static str {
    "ok"
}

/// Handles the GET /traceroute endpoint.
async fn handle_traceroute(
    Query(params): Query<TracerouteQuery>,
) -> Result<Json<Results>, (StatusCode, Json<ErrorResponse>)> {
    // Parse protocol
    let protocol: Protocol = params.protocol.parse().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid protocol: {}", e),
            }),
        )
    })?;

    // Build config
    let config = TracerouteConfig {
        hostname: params.target,
        port: params.port,
        protocol,
        params: TracerouteParams {
            min_ttl: 1,
            max_ttl: params.max_ttl.unwrap_or(30),
            timeout: Duration::from_millis(params.timeout.unwrap_or(3000)),
            poll_frequency: Duration::from_millis(100),
            send_delay: Duration::from_millis(50),
        },
        tcp_method: traceroute_core::TcpMethod::Syn,
        want_v6: params.ipv6,
        reverse_dns: false,
        collect_source_public_ip: false,
        traceroute_queries: params.queries.unwrap_or(3),
        e2e_queries: 0,
        use_windows_driver: false,
        skip_private_hops: false,
    };

    // Run traceroute
    match runner::run_traceroute(config).await {
        Ok(results) => Ok(Json(results)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Traceroute failed: {}", e),
            }),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(default_protocol(), "udp");
        assert_eq!(default_port(), 33434);
        assert_eq!(default_max_ttl(), Some(30));
    }
}
