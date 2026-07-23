use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use hickory_proto::rr::RecordType;
use serde::Serialize;
use tokio::{
    sync::Barrier,
    task::JoinSet,
    time::{Instant as TokioInstant, sleep_until, timeout},
};

use crate::{
    config::{RunConfig, RunLimit, Target, record_type_label},
    dns::{DnsClient, build_query, inspect_response},
    report::{RankingEntry, rank_results},
    stats::{Aggregate, TargetResult},
};

#[derive(Debug, Clone, Serialize)]
pub struct ConfigSnapshot {
    pub targets: Vec<Target>,
    pub names: Vec<String>,
    pub record_types: Vec<String>,
    pub transport: String,
    pub requests: Option<u64>,
    pub duration_ms: Option<u64>,
    pub concurrency: usize,
    pub rate: Option<u64>,
    pub timeout_ms: u64,
    pub warmup: u64,
    pub dnssec: bool,
    pub edns_payload: u16,
    pub workers: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub schema_version: u32,
    pub started_at: DateTime<Utc>,
    pub config: ConfigSnapshot,
    pub results: Vec<TargetResult>,
    pub ranking: Vec<RankingEntry>,
    pub interrupted: bool,
}

pub async fn run(config: RunConfig) -> Result<RunResult> {
    config.validate()?;
    let started_at = Utc::now();
    let cancelled = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));

    let signal_cancelled = Arc::clone(&cancelled);
    let signal_interrupted = Arc::clone(&interrupted);
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_interrupted.store(true, Ordering::Relaxed);
            signal_cancelled.store(true, Ordering::Release);
        }
    });

    let barrier = Arc::new(Barrier::new(config.targets.len() + 1));
    let config = Arc::new(config);
    let mut targets = JoinSet::new();
    for target in config.targets.iter().cloned() {
        let worker_config = Arc::clone(&config);
        let worker_barrier = Arc::clone(&barrier);
        let worker_cancelled = Arc::clone(&cancelled);
        targets.spawn(async move {
            run_target(target, worker_config, worker_barrier, worker_cancelled).await
        });
    }

    barrier.wait().await;
    let mut results = Vec::with_capacity(config.targets.len());
    while let Some(joined) = targets.join_next().await {
        match joined {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(error)) => eprintln!("dnsblast: target worker failed: {error:#}"),
            Err(error) => eprintln!("dnsblast: target task failed: {error}"),
        }
    }
    signal_task.abort();
    results.sort_by(|left, right| left.target.label.cmp(&right.target.label));
    let ranking = rank_results(&results);

    Ok(RunResult {
        schema_version: 1,
        started_at,
        config: ConfigSnapshot::from(config.as_ref()),
        results,
        ranking,
        interrupted: interrupted.load(Ordering::Relaxed),
    })
}

async fn run_target(
    target: Target,
    config: Arc<RunConfig>,
    barrier: Arc<Barrier>,
    cancelled: Arc<AtomicBool>,
) -> Result<TargetResult> {
    run_warmup(&target, &config, Arc::clone(&cancelled)).await;
    barrier.wait().await;
    let started = Instant::now();
    let next_index = Arc::new(AtomicU64::new(0));
    let shard_count = config.workers.min(config.concurrency).max(1);
    let shards: Vec<_> = (0..shard_count)
        .map(|_| Aggregate::new(&config.record_types).map(|value| Arc::new(Mutex::new(value))))
        .collect::<Result<_>>()?;
    let mut workers = JoinSet::new();

    for worker_id in 0..config.concurrency {
        let worker_target = target.clone();
        let worker_config = Arc::clone(&config);
        let worker_index = Arc::clone(&next_index);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_aggregate = Arc::clone(&shards[worker_id % shard_count]);
        workers.spawn(async move {
            run_worker(
                worker_id,
                worker_target,
                worker_config,
                worker_index,
                worker_cancelled,
                worker_aggregate,
                started,
            )
            .await
        });
    }

    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("dnsblast: worker for {} failed: {error:#}", target.label),
            Err(error) => eprintln!("dnsblast: worker task for {} failed: {error}", target.label),
        }
    }
    let mut aggregate = Aggregate::new(&config.record_types)?;
    for shard in shards {
        let shard = shard
            .lock()
            .map_err(|_| anyhow::anyhow!("aggregation shard was poisoned"))?;
        aggregate.merge(&shard)?;
    }
    Ok(aggregate.finish(target, started.elapsed()))
}

async fn run_warmup(target: &Target, config: &RunConfig, cancelled: Arc<AtomicBool>) {
    if config.warmup == 0 {
        return;
    }
    let next = Arc::new(AtomicU64::new(0));
    let mut workers = JoinSet::new();
    let worker_count = config.concurrency.min(config.warmup as usize);
    for worker_id in 0..worker_count {
        let target = target.clone();
        let config = config.clone();
        let next = Arc::clone(&next);
        let cancelled = Arc::clone(&cancelled);
        workers.spawn(async move {
            let mut client = DnsClient::new(config.transport, target.address);
            loop {
                if cancelled.load(Ordering::Acquire) {
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= config.warmup {
                    break;
                }
                let (name, record_type) = select_query(&config, index);
                let id = transaction_id(config.seed, worker_id, index);
                if let Ok(query) =
                    build_query(id, name, record_type, config.dnssec, config.edns_payload)
                    && timeout(config.timeout, client.exchange(&query))
                        .await
                        .is_err()
                {
                    client.invalidate();
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
}

async fn run_worker(
    worker_id: usize,
    target: Target,
    config: Arc<RunConfig>,
    next_index: Arc<AtomicU64>,
    cancelled: Arc<AtomicBool>,
    aggregate: Arc<Mutex<Aggregate>>,
    started: Instant,
) -> Result<()> {
    let mut client = DnsClient::new(config.transport, target.address);
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        if let RunLimit::Duration(duration) = config.limit
            && started.elapsed() >= duration
        {
            break;
        }
        let index = next_index.fetch_add(1, Ordering::Relaxed);
        if let RunLimit::Requests(requests) = config.limit
            && index >= requests
        {
            break;
        }
        if let Some(rate) = config.rate {
            let due = started + Duration::from_secs_f64(index as f64 / rate as f64);
            if let RunLimit::Duration(duration) = config.limit
                && due >= started + duration
            {
                break;
            }
            sleep_until_cancelled(TokioInstant::from_std(due), &cancelled).await;
            if cancelled.load(Ordering::Acquire) {
                break;
            }
            if let RunLimit::Duration(duration) = config.limit
                && started.elapsed() >= duration
            {
                break;
            }
        }

        let (name, record_type) = select_query(&config, index);
        let id = transaction_id(config.seed, worker_id, index);
        let query = match build_query(id, name, record_type, config.dnssec, config.edns_payload) {
            Ok(query) => query,
            Err(_) => {
                aggregate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("aggregation shard was poisoned"))?
                    .record_error(record_type, 0);
                continue;
            }
        };
        let sent = query.len() as u64;
        let query_started = Instant::now();
        match timeout(config.timeout, client.exchange(&query)).await {
            Err(_) => {
                client.invalidate();
                aggregate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("aggregation shard was poisoned"))?
                    .record_timeout(record_type, sent);
            }
            Ok(Err(_)) => {
                client.invalidate();
                aggregate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("aggregation shard was poisoned"))?
                    .record_error(record_type, sent);
            }
            Ok(Ok(response)) => match inspect_response(id, &response) {
                Ok(observation) => aggregate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("aggregation shard was poisoned"))?
                    .record_response(
                        record_type,
                        query_started
                            .elapsed()
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64,
                        sent,
                        response.len() as u64,
                        &observation.response_code,
                        observation.truncated,
                        observation.authenticated_data,
                        observation.dnssec_records,
                        observation.rrsig_response,
                    ),
                Err(_) => {
                    client.invalidate();
                    aggregate
                        .lock()
                        .map_err(|_| anyhow::anyhow!("aggregation shard was poisoned"))?
                        .record_error(record_type, sent);
                }
            },
        }
        if matches!(record_type, RecordType::AXFR | RecordType::IXFR) {
            // Zone transfers can contain multiple framed responses. This benchmark records
            // the first response and reconnects so transfer frames cannot leak into the
            // next request on a persistent TCP connection.
            client.invalidate();
        }
    }
    Ok(())
}

async fn sleep_until_cancelled(due: TokioInstant, cancelled: &AtomicBool) {
    const CANCELLATION_POLL: Duration = Duration::from_millis(25);
    loop {
        if cancelled.load(Ordering::Acquire) || TokioInstant::now() >= due {
            return;
        }
        sleep_until(std::cmp::min(due, TokioInstant::now() + CANCELLATION_POLL)).await;
    }
}

fn select_query(config: &RunConfig, index: u64) -> (&hickory_proto::rr::Name, RecordType) {
    let combinations = (config.names.len() * config.record_types.len()) as u64;
    let selected = (index.wrapping_add(config.seed) % combinations) as usize;
    let name_index = selected / config.record_types.len();
    let type_index = selected % config.record_types.len();
    (&config.names[name_index], config.record_types[type_index])
}

fn transaction_id(seed: u64, worker_id: usize, index: u64) -> u16 {
    let mixed = seed
        .wrapping_add(index)
        .wrapping_add((worker_id as u64).wrapping_mul(0x9E37_79B9));
    (mixed ^ (mixed >> 16) ^ (mixed >> 32)) as u16
}

impl From<&RunConfig> for ConfigSnapshot {
    fn from(config: &RunConfig) -> Self {
        let (requests, duration_ms) = match config.limit {
            RunLimit::Requests(requests) => (Some(requests), None),
            RunLimit::Duration(duration) => (
                None,
                Some(duration.as_millis().min(u128::from(u64::MAX)) as u64),
            ),
        };
        Self {
            targets: config.targets.clone(),
            names: config.names.iter().map(ToString::to_string).collect(),
            record_types: config
                .record_types
                .iter()
                .copied()
                .map(record_type_label)
                .collect(),
            transport: match config.transport {
                crate::config::Transport::Udp => "udp",
                crate::config::Transport::Tcp => "tcp",
            }
            .to_owned(),
            requests,
            duration_ms,
            concurrency: config.concurrency,
            rate: config.rate,
            timeout_ms: config.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            warmup: config.warmup,
            dnssec: config.dnssec,
            edns_payload: config.edns_payload,
            workers: config.workers,
            seed: config.seed,
        }
    }
}
