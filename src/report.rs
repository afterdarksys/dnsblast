use std::{
    cmp::Ordering,
    fmt::Write as _,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{cli::OutputFormat, engine::RunResult, stats::TargetResult};

#[derive(Debug, Clone, Serialize)]
pub struct RankingEntry {
    pub rank: usize,
    pub target: String,
    pub qps: f64,
}

pub fn rank_results(results: &[TargetResult]) -> Vec<RankingEntry> {
    let mut ranked: Vec<_> = results.iter().collect();
    ranked.sort_by(|left, right| {
        right
            .qps
            .partial_cmp(&left.qps)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.target.label.cmp(&right.target.label))
    });
    ranked
        .into_iter()
        .enumerate()
        .map(|(index, result)| RankingEntry {
            rank: index + 1,
            target: result.target.label.clone(),
            qps: result.qps,
        })
        .collect()
}

pub fn emit(result: &RunResult, format: OutputFormat, output_file: Option<&Path>) -> Result<()> {
    match format {
        OutputFormat::Stdout => {
            if output_file.is_some() {
                bail!("--output-file is supported with --output json or --output log");
            }
            print!("{}", render_human(result));
        }
        OutputFormat::Json => {
            let rendered =
                serde_json::to_string_pretty(result).context("failed to serialize JSON results")?;
            if let Some(path) = output_file {
                atomic_write(path, format!("{rendered}\n").as_bytes())?;
            } else {
                println!("{rendered}");
            }
        }
        OutputFormat::Log => {
            let path = output_file.context("--output log requires --output-file PATH")?;
            atomic_write(path, render_human(result).as_bytes())?;
        }
    }
    Ok(())
}

pub fn validate_output(format: OutputFormat, output_file: Option<&Path>) -> Result<()> {
    match format {
        OutputFormat::Stdout if output_file.is_some() => {
            bail!("--output-file is supported with --output json or --output log")
        }
        OutputFormat::Log if output_file.is_none() => {
            bail!("--output log requires --output-file PATH")
        }
        _ => {}
    }
    let Some(path) = output_file else {
        return Ok(());
    };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("output directory {} does not exist", parent.display());
    }
    let probe = parent.join(format!(".dnsblast-write-test-{}", std::process::id()));
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
        .with_context(|| format!("output directory {} is not writable", parent.display()))?;
    fs::remove_file(&probe)
        .with_context(|| format!("failed to remove output write probe {}", probe.display()))?;
    Ok(())
}

pub fn render_human(result: &RunResult) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "DNSBlast comparison — {} target(s), {} transport, {}",
        result.results.len(),
        result.config.transport.to_ascii_uppercase(),
        result.started_at.to_rfc3339()
    );
    let _ = writeln!(
        output,
        "{:<4} {:<18} {:>11} {:>10} {:>9} {:>9} {:>9} {:>10} {:>10} {:>10}",
        "RANK", "TARGET", "QPS", "ATTEMPTS", "RESP", "OK", "TIMEOUT", "ERROR", "P50(us)", "P99(us)"
    );
    for ranking in &result.ranking {
        if let Some(item) = result
            .results
            .iter()
            .find(|item| item.target.label == ranking.target)
        {
            let _ = writeln!(
                output,
                "{:<4} {:<18} {:>11.2} {:>10} {:>9} {:>9} {:>9} {:>10} {:>10} {:>10}",
                ranking.rank,
                item.target.label,
                item.qps,
                item.attempts,
                item.responses,
                item.successes,
                item.timeouts,
                item.errors,
                display_latency(item.latency.p50_us),
                display_latency(item.latency.p99_us),
            );
        }
    }
    for item in &result.results {
        let _ = writeln!(
            output,
            "\n{} ({}) — elapsed {:.3}s, bytes sent/received {}/{}, TC {}, AD {}, RRSIG responses {}, DNSSEC records {}",
            item.target.label,
            item.target.address,
            item.elapsed_ms as f64 / 1_000.0,
            item.bytes_sent,
            item.bytes_received,
            item.truncated,
            item.authenticated_data,
            item.rrsig_responses,
            item.dnssec_records,
        );
        let codes = item
            .response_codes
            .iter()
            .map(|(code, count)| format!("{code}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            output,
            "  response codes: {}",
            if codes.is_empty() { "none" } else { &codes }
        );
        if item.by_record_type.len() > 1 {
            let _ = writeln!(
                output,
                "  {:<12} {:>10} {:>10} {:>10} {:>10} {:>10}",
                "TYPE", "QPS", "ATTEMPTS", "RESP", "P50(us)", "P99(us)"
            );
            for (record_type, stats) in &item.by_record_type {
                let _ = writeln!(
                    output,
                    "  {:<12} {:>10.2} {:>10} {:>10} {:>10} {:>10}",
                    record_type,
                    stats.qps,
                    stats.attempts,
                    stats.responses,
                    display_latency(stats.latency.p50_us),
                    display_latency(stats.latency.p99_us),
                );
            }
        }
    }
    if result.interrupted {
        let _ = writeln!(
            output,
            "\nRun interrupted; partial completed results shown."
        );
    }
    output
}

fn display_latency(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("output path must include a file name")?
        .to_string_lossy();
    let temporary: PathBuf = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    fs::write(&temporary, content)
        .with_context(|| format!("failed to write temporary output {}", temporary.display()))?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("failed to replace output {}", path.display()));
    }
    Ok(())
}
