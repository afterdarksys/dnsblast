use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use hickory_proto::rr::{Name, RecordType};
use serde::Serialize;

use crate::cli::Cli;

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub label: String,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, Copy, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy)]
pub enum RunLimit {
    Requests(u64),
    Duration(Duration),
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub targets: Vec<Target>,
    pub names: Vec<Name>,
    pub record_types: Vec<RecordType>,
    pub transport: Transport,
    pub limit: RunLimit,
    pub concurrency: usize,
    pub rate: Option<u64>,
    pub timeout: Duration,
    pub warmup: u64,
    pub dnssec: bool,
    pub edns_payload: u16,
    pub workers: usize,
    pub seed: u64,
}

impl RunConfig {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let mut targets = Vec::with_capacity(cli.servers.len());
        let mut labels = HashSet::new();
        for raw in &cli.servers {
            let target = parse_target(raw)?;
            if !labels.insert(target.label.to_ascii_lowercase()) {
                bail!("duplicate server label {:?}", target.label);
            }
            targets.push(target);
        }

        let mut raw_names = cli.names.clone();
        if let Some(path) = &cli.names_file {
            raw_names.extend(read_names(path)?);
        }
        let names = parse_names(&raw_names)?;
        let record_types = parse_record_types(&cli.record_types)?;

        let limit = match (cli.requests, cli.duration.as_deref()) {
            (Some(_), Some(_)) => bail!("use either --requests or --duration, not both"),
            (Some(requests), None) => RunLimit::Requests(requests),
            (None, Some(raw)) => RunLimit::Duration(
                humantime::parse_duration(raw)
                    .with_context(|| format!("invalid --duration {raw:?}"))?,
            ),
            (None, None) => RunLimit::Requests(1_000),
        };
        let timeout = humantime::parse_duration(&cli.timeout)
            .with_context(|| format!("invalid --timeout {:?}", cli.timeout))?;

        let config = Self {
            targets,
            names,
            record_types,
            transport: cli.transport,
            limit,
            concurrency: cli.concurrency,
            rate: cli.rate,
            timeout,
            warmup: cli.warmup,
            dnssec: cli.dnssec,
            edns_payload: cli.edns_payload,
            workers: cli.workers,
            seed: cli.seed,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            bail!("at least one --server LABEL=IP[:PORT] is required");
        }
        if self.names.is_empty() {
            bail!("at least one --name or a non-empty --names-file is required");
        }
        if self.record_types.is_empty() {
            bail!("at least one --type is required");
        }
        if self.concurrency == 0 {
            bail!("--concurrency must be greater than zero");
        }
        if self.workers == 0 {
            bail!("--workers must be greater than zero");
        }
        if self.timeout.is_zero() {
            bail!("--timeout must be greater than zero");
        }
        if self.rate == Some(0) {
            bail!("--rate must be greater than zero");
        }
        if !(512..=65_535).contains(&self.edns_payload) {
            bail!("--edns-payload must be between 512 and 65535");
        }
        match self.limit {
            RunLimit::Requests(0) => bail!("--requests must be greater than zero"),
            RunLimit::Duration(duration) if duration.is_zero() => {
                bail!("--duration must be greater than zero")
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn parse_target(raw: &str) -> Result<Target> {
    let (label, address) = raw
        .split_once('=')
        .with_context(|| format!("invalid server {raw:?}; expected LABEL=IP[:PORT]"))?;
    if label.trim().is_empty() {
        bail!("server label cannot be empty in {raw:?}");
    }
    let address = if let Ok(socket) = SocketAddr::from_str(address) {
        socket
    } else if let Ok(ip) = IpAddr::from_str(address) {
        SocketAddr::new(ip, 53)
    } else {
        bail!("invalid server address {address:?}; use an IP, IPv4:port, or [IPv6]:port");
    };
    Ok(Target {
        label: label.trim().to_owned(),
        address,
    })
}

fn read_names(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read names file {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn parse_names(raw_names: &[String]) -> Result<Vec<Name>> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    for raw in raw_names {
        let canonical = if raw.ends_with('.') {
            raw.to_owned()
        } else {
            format!("{raw}.")
        };
        let name =
            Name::from_str(&canonical).with_context(|| format!("invalid DNS name {raw:?}"))?;
        if seen.insert(name.to_ascii().to_ascii_lowercase()) {
            names.push(name);
        }
    }
    Ok(names)
}

pub fn parse_record_types(raw_types: &[String]) -> Result<Vec<RecordType>> {
    let mut types = Vec::new();
    let mut seen = HashSet::new();
    for raw_group in raw_types {
        for raw in raw_group
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if raw.eq_ignore_ascii_case("ALL") {
                for record_type in all_record_types() {
                    if seen.insert(record_type) {
                        types.push(record_type);
                    }
                }
                continue;
            }
            let upper = raw.to_ascii_uppercase();
            let record_type = if let Some(number) = upper.strip_prefix("TYPE") {
                RecordType::from(
                    number
                        .parse::<u16>()
                        .with_context(|| format!("invalid numeric DNS record type {raw:?}"))?,
                )
            } else if let Ok(number) = upper.parse::<u16>() {
                RecordType::from(number)
            } else {
                RecordType::from_str(&upper)
                    .with_context(|| format!("invalid DNS record type {raw:?}"))?
            };
            if record_type.is_zero() || record_type == RecordType::OPT {
                bail!("record type {raw:?} cannot be used as a standalone question");
            }
            if seen.insert(record_type) {
                types.push(record_type);
            }
        }
    }
    if types.is_empty() {
        bail!("at least one DNS record type is required");
    }
    Ok(types)
}

pub fn record_type_label(record_type: RecordType) -> String {
    match record_type {
        RecordType::Unknown(number) => format!("TYPE{number}"),
        known => known.to_string(),
    }
}

pub fn all_record_types() -> Vec<RecordType> {
    use RecordType::*;
    vec![
        A, AAAA, ANAME, ANY, AXFR, CAA, CDS, CDNSKEY, CERT, CNAME, CSYNC, DNSKEY, DS, HINFO, HTTPS,
        IXFR, KEY, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM, NULL, OPENPGPKEY, PTR, RRSIG, SIG,
        SMIMEA, SOA, SRV, SSHFP, SVCB, TLSA, TSIG, TXT,
    ]
}
