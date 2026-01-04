//! HTTP server binary for datadog-traceroute.

use clap::Parser;
use std::net::SocketAddr;
use traceroute_server::{create_router, DEFAULT_PORT};

/// Datadog Traceroute HTTP Server.
#[derive(Parser, Debug)]
#[command(name = "datadog-traceroute-server")]
#[command(version)]
#[command(about = "HTTP REST API server for Datadog Traceroute")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:3765")]
    addr: String,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long = "log-level", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    let filter = match args.log_level.to_lowercase().as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "info" => "info",
        "warn" => "warn",
        "error" => "error",
        _ => "info",
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let addr: SocketAddr = args.addr.parse().unwrap_or_else(|_| {
        eprintln!("Invalid address: {}", args.addr);
        std::process::exit(1);
    });

    tracing::info!("Starting HTTP server on {}", addr);

    let router = create_router();

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    tracing::info!("HTTP server listening on {}", addr);

    axum::serve(listener, router).await.unwrap_or_else(|e| {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    });
}
