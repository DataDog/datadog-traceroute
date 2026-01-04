//! CLI entrypoint for datadog-traceroute.

use clap::Parser;
use datadog_traceroute_common::{
    DEFAULT_DELAY_MS, DEFAULT_MAX_TTL, DEFAULT_MIN_TTL, DEFAULT_NETWORK_PATH_TIMEOUT_MS,
    DEFAULT_NUM_E2E_PROBES, DEFAULT_PORT, DEFAULT_PROTOCOL, DEFAULT_TCP_METHOD,
    DEFAULT_TRACEROUTE_QUERIES,
};
use datadog_traceroute_core::{TracerouteParams, TracerouteRunner};
use std::process;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "datadog-traceroute")]
#[command(about = "Datadog traceroute CLI", long_about = None)]
struct Args {
    #[arg(value_name = "target")]
    target: String,

    #[arg(short = 'P', long = "proto", default_value = DEFAULT_PROTOCOL)]
    protocol: String,

    #[arg(short = 'p', long = "port", default_value_t = DEFAULT_PORT)]
    port: u16,

    #[arg(short = 'q', long = "traceroute-queries", default_value_t = DEFAULT_TRACEROUTE_QUERIES)]
    traceroute_queries: usize,

    #[arg(short = 'm', long = "max-ttl", default_value_t = DEFAULT_MAX_TTL)]
    max_ttl: u8,

    #[arg(short = 'v', long = "verbose", default_value_t = false)]
    verbose: bool,

    #[arg(long = "tcp-method", default_value = DEFAULT_TCP_METHOD)]
    tcp_method: String,

    #[arg(long = "ipv6", default_value_t = false)]
    ipv6: bool,

    #[arg(long = "timeout", default_value_t = 0)]
    timeout_ms: u64,

    #[arg(long = "reverse-dns", default_value_t = false)]
    reverse_dns: bool,

    #[arg(long = "source-public-ip", default_value_t = false)]
    source_public_ip: bool,

    #[arg(short = 'Q', long = "e2e-queries", default_value_t = DEFAULT_NUM_E2E_PROBES)]
    e2e_queries: usize,

    #[arg(long = "windows-driver", default_value_t = false)]
    windows_driver: bool,

    #[arg(long = "skip-private-hops", default_value_t = false)]
    skip_private_hops: bool,
}

fn main() {
    let args = Args::parse();

    if args.verbose {
        // TODO: wire verbose output once logging is implemented for Rust.
    }

    if args.windows_driver {
        if let Err(err) = datadog_traceroute_packets::start_driver() {
            eprintln!("Failed to start Windows driver: {}", err);
            process::exit(1);
        }
    }

    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_NETWORK_PATH_TIMEOUT_MS
    } else {
        args.timeout_ms
    };

    let params = TracerouteParams {
        hostname: args.target,
        port: args.port,
        protocol: args.protocol,
        min_ttl: DEFAULT_MIN_TTL,
        max_ttl: args.max_ttl,
        delay_ms: DEFAULT_DELAY_MS,
        timeout: Duration::from_millis(timeout_ms),
        tcp_method: args.tcp_method,
        want_v6: args.ipv6,
        tcp_syn_paris_traceroute_mode: false,
        reverse_dns: args.reverse_dns,
        collect_source_public_ip: args.source_public_ip,
        traceroute_queries: args.traceroute_queries,
        e2e_queries: args.e2e_queries,
        use_windows_driver: args.windows_driver,
        skip_private_hops: args.skip_private_hops,
    };

    let runner = TracerouteRunner::new();
    let results = match runner.run_traceroute(params) {
        Ok(results) => results,
        Err(err) => {
            eprintln!("Traceroute failed: {}", err);
            process::exit(1);
        }
    };

    let json = match serde_json::to_string_pretty(&results) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("Failed to encode response: {}", err);
            process::exit(1);
        }
    };

    println!("{json}");
}
