use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::config::Transport;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Stdout,
    Json,
    Log,
}

#[derive(Debug, Parser)]
#[command(
    name = "dnsblast",
    version,
    about = "Concurrent comparative DNS/DNSSEC performance testing",
    long_about = "Pummel one or more authorized DNS servers with the same query plan and compare throughput, latency, errors, response codes, and DNSSEC behavior."
)]
pub struct Cli {
    /// Target server; repeat for comparisons (example: bind=192.0.2.53:53)
    #[arg(
        short = 's',
        long = "server",
        required = true,
        value_name = "LABEL=IP[:PORT]"
    )]
    pub servers: Vec<String>,

    /// DNS name to query; repeat for a mixed workload
    #[arg(short = 'n', long = "name", value_name = "DOMAIN")]
    pub names: Vec<String>,

    /// Newline-delimited names; blank lines and # comments are ignored
    #[arg(long, value_name = "PATH")]
    pub names_file: Option<PathBuf>,

    /// Record type; repeat or comma-separate. ALL expands to the documented preset
    #[arg(short = 't', long = "type", default_value = "A", value_name = "TYPE")]
    pub record_types: Vec<String>,

    /// DNS transport
    #[arg(long, value_enum, default_value_t = Transport::Udp)]
    pub transport: Transport,

    /// Measured requests per target (default: 1000)
    #[arg(short = 'r', long, value_name = "COUNT")]
    pub requests: Option<u64>,

    /// Measured duration per target, such as 30s or 5m
    #[arg(short = 'd', long, value_name = "DURATION")]
    pub duration: Option<String>,

    /// In-flight queries per target
    #[arg(short = 'c', long, default_value_t = 32)]
    pub concurrency: usize,

    /// Maximum queries per second per target
    #[arg(long, value_name = "QPS")]
    pub rate: Option<u64>,

    /// Timeout for each network operation
    #[arg(long, default_value = "2s", value_name = "DURATION")]
    pub timeout: String,

    /// Unmeasured warmup queries per target
    #[arg(long, default_value_t = 0)]
    pub warmup: u64,

    /// Set EDNS DNSSEC OK and report DNSSEC observations
    #[arg(long)]
    pub dnssec: bool,

    /// Advertised EDNS UDP payload size
    #[arg(long, default_value_t = 1232)]
    pub edns_payload: u16,

    /// Tokio runtime worker threads
    #[arg(long, default_value_t = default_workers())]
    pub workers: usize,

    /// Deterministic query-plan offset
    #[arg(long, default_value_t = 0)]
    pub seed: u64,

    /// Result format
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Stdout)]
    pub output: OutputFormat,

    /// Write JSON/log output atomically to this path
    #[arg(long, value_name = "PATH")]
    pub output_file: Option<PathBuf>,
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}
