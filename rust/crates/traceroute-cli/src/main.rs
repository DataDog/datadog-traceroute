//! CLI for datadog-traceroute.

mod runner;

use clap::Parser;
use std::process::ExitCode;
use std::time::Duration;
use traceroute_core::{Protocol, TcpMethod, TracerouteConfig, TracerouteParams};

/// Datadog Traceroute - Network path analysis tool.
#[derive(Parser, Debug)]
#[command(name = "datadog-traceroute")]
#[command(version)]
#[command(about = "Datadog Traceroute - Network path analysis tool")]
pub struct Args {
    /// Target hostname or IP address.
    #[arg(required = true)]
    pub target: String,

    /// Protocol to use.
    #[arg(short = 'P', long, default_value = "udp")]
    pub proto: String,

    /// Destination port.
    #[arg(short, long, default_value = "33434")]
    pub port: u16,

    /// Number of traceroute queries.
    #[arg(short = 'q', long = "traceroute-queries", default_value = "3")]
    pub traceroute_queries: usize,

    /// Maximum TTL.
    #[arg(short = 'm', long = "max-ttl", default_value = "30")]
    pub max_ttl: u8,

    /// Enable verbose logging.
    #[arg(short, long)]
    pub verbose: bool,

    /// TCP method (syn, sack, prefer_sack).
    #[arg(long = "tcp-method", default_value = "syn")]
    pub tcp_method: String,

    /// Use IPv6.
    #[arg(long)]
    pub ipv6: bool,

    /// Timeout per probe in milliseconds.
    #[arg(long, default_value = "3000")]
    pub timeout: u64,

    /// Perform reverse DNS lookups.
    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    /// Collect source public IP.
    #[arg(long = "source-public-ip")]
    pub source_public_ip: bool,

    /// Number of end-to-end probes.
    #[arg(short = 'Q', long = "e2e-queries", default_value = "50")]
    pub e2e_queries: usize,

    /// Use Windows driver (Windows only).
    #[arg(long = "windows-driver")]
    pub windows_driver: bool,

    /// Skip private hops in output.
    #[arg(long = "skip-private-hops")]
    pub skip_private_hops: bool,
}

impl Args {
    /// Convert CLI args to TracerouteConfig.
    fn to_config(&self) -> Result<TracerouteConfig, String> {
        let protocol: Protocol = self
            .proto
            .parse()
            .map_err(|e| format!("Invalid protocol: {}", e))?;

        let tcp_method: TcpMethod = self
            .tcp_method
            .parse()
            .map_err(|e| format!("Invalid TCP method: {}", e))?;

        Ok(TracerouteConfig {
            hostname: self.target.clone(),
            port: self.port,
            protocol,
            params: TracerouteParams {
                min_ttl: 1,
                max_ttl: self.max_ttl,
                timeout: Duration::from_millis(self.timeout),
                poll_frequency: Duration::from_millis(100),
                send_delay: Duration::from_millis(50),
            },
            tcp_method,
            want_v6: self.ipv6,
            reverse_dns: self.reverse_dns,
            collect_source_public_ip: self.source_public_ip,
            traceroute_queries: self.traceroute_queries,
            e2e_queries: self.e2e_queries,
            use_windows_driver: self.windows_driver,
            skip_private_hops: self.skip_private_hops,
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter("info")
            .init();
    }

    let config = match args.to_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        target = %config.hostname,
        protocol = %config.protocol,
        port = config.port,
        "Starting traceroute"
    );

    match runner::run_traceroute(config).await {
        Ok(results) => {
            match results.to_json() {
                Ok(json) => {
                    println!("{}", json);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed to serialize results: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("Traceroute failed: {}", e);
            ExitCode::FAILURE
        }
    }
}
