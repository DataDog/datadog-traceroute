//! HTTP server entrypoint for datadog-traceroute.

use axum::{
    Router,
    extract::{Query, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::Parser;
use datadog_traceroute_common::{
    DEFAULT_DELAY_MS, DEFAULT_MAX_TTL, DEFAULT_MIN_TTL, DEFAULT_NETWORK_PATH_TIMEOUT_MS,
    DEFAULT_NUM_E2E_PROBES, DEFAULT_PORT, DEFAULT_PROTOCOL, DEFAULT_SKIP_PRIVATE_HOPS,
    DEFAULT_TCP_METHOD, DEFAULT_TRACEROUTE_QUERIES, DEFAULT_USE_WINDOWS_DRIVER,
};
use datadog_traceroute_core::{TracerouteParams, TracerouteRunner};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "datadog-traceroute-server")]
#[command(about = "Datadog traceroute HTTP server", long_about = None)]
struct Args {
    #[arg(short = 'a', long = "addr", default_value = ":3765")]
    addr: String,

    #[arg(short = 'l', long = "log-level", default_value = "info")]
    log_level: String,
}

#[derive(Clone)]
struct AppState {
    runner: Arc<TracerouteRunner>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let filter = match args.log_level.as_str() {
        "error" => EnvFilter::new("error"),
        "warn" => EnvFilter::new("warn"),
        "debug" => EnvFilter::new("debug"),
        "trace" => EnvFilter::new("trace"),
        _ => EnvFilter::new("info"),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let state = AppState {
        runner: Arc::new(TracerouteRunner::new()),
    };

    let app = Router::new()
        .route("/traceroute", any(traceroute_handler))
        .with_state(state);

    let addr: SocketAddr = args.addr.parse().unwrap_or_else(|err| {
        eprintln!("Failed to parse addr {}: {}", args.addr, err);
        process::exit(1);
    });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("Failed to bind {}: {}", addr, err);
            process::exit(1);
        });
    tracing::info!("Starting HTTP server on {}", addr);
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("HTTP server failed: {}", err);
        process::exit(1);
    }
}

async fn traceroute_handler(
    State(state): State<AppState>,
    method: Method,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if method != Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response();
    }

    let params = match parse_traceroute_params(&query) {
        Ok(params) => params,
        Err(err) => {
            let message = format!("Invalid parameters: {}", err);
            return (StatusCode::BAD_REQUEST, message).into_response();
        }
    };

    if params.use_windows_driver {
        if let Err(err) = datadog_traceroute_packets::start_driver() {
            let message = format!("Traceroute failed: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
    }

    let runner = Arc::clone(&state.runner);
    let result = tokio::task::spawn_blocking(move || runner.run_traceroute(params)).await;
    let results = match result {
        Ok(Ok(results)) => results,
        Ok(Err(err)) => {
            let message = format!("Traceroute failed: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
        Err(err) => {
            let message = format!("Traceroute failed: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
    };

    let json = match serde_json::to_string(&results) {
        Ok(json) => json,
        Err(err) => {
            let message = format!("Failed to encode response: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
    };

    let mut response = (StatusCode::OK, json).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

fn parse_traceroute_params(query: &HashMap<String, String>) -> Result<TracerouteParams, String> {
    let hostname = query
        .get("target")
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();
    if hostname.is_empty() {
        return Err("missing required parameter: target".to_string());
    }

    let protocol = get_string(query, "protocol", DEFAULT_PROTOCOL);
    let port = get_u16(query, "port", DEFAULT_PORT);
    let traceroute_queries = get_usize(query, "traceroute-queries", DEFAULT_TRACEROUTE_QUERIES);
    let max_ttl = get_u8(query, "max-ttl", DEFAULT_MAX_TTL);
    let timeout_ms = get_u64(query, "timeout", DEFAULT_NETWORK_PATH_TIMEOUT_MS);
    let tcp_method = get_string(query, "tcp-method", DEFAULT_TCP_METHOD);
    let e2e_queries = get_usize(query, "e2e-queries", DEFAULT_NUM_E2E_PROBES);

    let want_v6 = get_bool(query, "ipv6", false);
    let reverse_dns = get_bool(query, "reverse-dns", false);
    let source_public_ip = get_bool(query, "source-public-ip", false);
    let use_windows_driver = get_bool(query, "windows-driver", DEFAULT_USE_WINDOWS_DRIVER);
    let skip_private_hops = get_bool(query, "skip-private-hops", DEFAULT_SKIP_PRIVATE_HOPS);

    Ok(TracerouteParams {
        hostname,
        port,
        protocol,
        min_ttl: DEFAULT_MIN_TTL,
        max_ttl,
        delay_ms: DEFAULT_DELAY_MS,
        timeout: Duration::from_millis(timeout_ms),
        tcp_method,
        want_v6,
        tcp_syn_paris_traceroute_mode: false,
        reverse_dns,
        collect_source_public_ip: source_public_ip,
        traceroute_queries,
        e2e_queries,
        use_windows_driver,
        skip_private_hops,
    })
}

fn get_string(query: &HashMap<String, String>, key: &str, default: &str) -> String {
    query
        .get(key)
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn get_u16(query: &HashMap<String, String>, key: &str, default: u16) -> u16 {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn get_u8(query: &HashMap<String, String>, key: &str, default: u8) -> u8 {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn get_u64(query: &HashMap<String, String>, key: &str, default: u64) -> u64 {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn get_usize(query: &HashMap<String, String>, key: &str, default: usize) -> usize {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn get_bool(query: &HashMap<String, String>, key: &str, default: bool) -> bool {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
