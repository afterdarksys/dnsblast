use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use hickory_proto::rr::RecordType;
use serde::Serialize;

use crate::config::{Target, record_type_label};

const MAX_LATENCY_US: u64 = 60_000_000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LatencySummary {
    pub min_us: Option<u64>,
    pub mean_us: Option<f64>,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub max_us: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeResult {
    pub attempts: u64,
    pub responses: u64,
    pub successes: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub qps: f64,
    pub latency: LatencySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetResult {
    pub target: Target,
    pub elapsed_ms: u64,
    pub attempts: u64,
    pub responses: u64,
    pub successes: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub truncated: u64,
    pub authenticated_data: u64,
    pub rrsig_responses: u64,
    pub dnssec_records: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub response_codes: BTreeMap<String, u64>,
    pub latency: LatencySummary,
    pub qps: f64,
    pub by_record_type: BTreeMap<String, TypeResult>,
}

impl TargetResult {
    pub fn empty(target: Target, qps: f64) -> Self {
        Self {
            target,
            elapsed_ms: 0,
            attempts: 0,
            responses: 0,
            successes: 0,
            timeouts: 0,
            errors: 0,
            truncated: 0,
            authenticated_data: 0,
            rrsig_responses: 0,
            dnssec_records: 0,
            bytes_sent: 0,
            bytes_received: 0,
            response_codes: BTreeMap::new(),
            latency: empty_latency(),
            qps,
            by_record_type: BTreeMap::new(),
        }
    }
}

pub struct Aggregate {
    total: Bucket,
    by_type: BTreeMap<String, Bucket>,
}

impl Aggregate {
    pub fn new(record_types: &[RecordType]) -> Result<Self> {
        let mut by_type = BTreeMap::new();
        for record_type in record_types {
            by_type.insert(record_type_label(*record_type), Bucket::new()?);
        }
        Ok(Self {
            total: Bucket::new()?,
            by_type,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_response(
        &mut self,
        record_type: RecordType,
        latency_us: u64,
        bytes_sent: u64,
        bytes_received: u64,
        response_code: &str,
        truncated: bool,
        authenticated_data: bool,
        dnssec_records: u64,
        rrsig_response: bool,
    ) {
        self.total.record_response(
            latency_us,
            bytes_sent,
            bytes_received,
            response_code,
            truncated,
            authenticated_data,
            dnssec_records,
            rrsig_response,
        );
        if let Some(bucket) = self.by_type.get_mut(&record_type_label(record_type)) {
            bucket.record_response(
                latency_us,
                bytes_sent,
                bytes_received,
                response_code,
                truncated,
                authenticated_data,
                dnssec_records,
                rrsig_response,
            );
        }
    }

    pub fn record_timeout(&mut self, record_type: RecordType, bytes_sent: u64) {
        self.total.record_timeout(bytes_sent);
        if let Some(bucket) = self.by_type.get_mut(&record_type_label(record_type)) {
            bucket.record_timeout(bytes_sent);
        }
    }

    pub fn record_error(&mut self, record_type: RecordType, bytes_sent: u64) {
        self.total.record_error(bytes_sent);
        if let Some(bucket) = self.by_type.get_mut(&record_type_label(record_type)) {
            bucket.record_error(bytes_sent);
        }
    }

    pub fn merge(&mut self, other: &Self) -> Result<()> {
        self.total.merge(&other.total)?;
        for (record_type, bucket) in &other.by_type {
            if let Some(ours) = self.by_type.get_mut(record_type) {
                ours.merge(bucket)?;
            }
        }
        Ok(())
    }

    pub fn finish(self, target: Target, elapsed: Duration) -> TargetResult {
        let seconds = elapsed.as_secs_f64();
        let latency = self.total.latency_summary();
        let qps = if seconds > 0.0 {
            self.total.responses as f64 / seconds
        } else {
            0.0
        };
        let by_record_type = self
            .by_type
            .into_iter()
            .map(|(name, bucket)| {
                let type_qps = if seconds > 0.0 {
                    bucket.responses as f64 / seconds
                } else {
                    0.0
                };
                (
                    name,
                    TypeResult {
                        attempts: bucket.attempts,
                        responses: bucket.responses,
                        successes: bucket.successes,
                        timeouts: bucket.timeouts,
                        errors: bucket.errors,
                        qps: type_qps,
                        latency: bucket.latency_summary(),
                    },
                )
            })
            .collect();
        TargetResult {
            target,
            elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
            attempts: self.total.attempts,
            responses: self.total.responses,
            successes: self.total.successes,
            timeouts: self.total.timeouts,
            errors: self.total.errors,
            truncated: self.total.truncated,
            authenticated_data: self.total.authenticated_data,
            rrsig_responses: self.total.rrsig_responses,
            dnssec_records: self.total.dnssec_records,
            bytes_sent: self.total.bytes_sent,
            bytes_received: self.total.bytes_received,
            response_codes: self.total.response_codes,
            latency,
            qps,
            by_record_type,
        }
    }
}

struct Bucket {
    attempts: u64,
    responses: u64,
    successes: u64,
    timeouts: u64,
    errors: u64,
    truncated: u64,
    authenticated_data: u64,
    rrsig_responses: u64,
    dnssec_records: u64,
    bytes_sent: u64,
    bytes_received: u64,
    response_codes: BTreeMap<String, u64>,
    histogram: Histogram<u64>,
}

impl Bucket {
    fn new() -> Result<Self> {
        Ok(Self {
            attempts: 0,
            responses: 0,
            successes: 0,
            timeouts: 0,
            errors: 0,
            truncated: 0,
            authenticated_data: 0,
            rrsig_responses: 0,
            dnssec_records: 0,
            bytes_sent: 0,
            bytes_received: 0,
            response_codes: BTreeMap::new(),
            histogram: Histogram::new_with_bounds(1, MAX_LATENCY_US, 3)
                .context("failed to initialize latency histogram")?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record_response(
        &mut self,
        latency_us: u64,
        bytes_sent: u64,
        bytes_received: u64,
        response_code: &str,
        truncated: bool,
        authenticated_data: bool,
        dnssec_records: u64,
        rrsig_response: bool,
    ) {
        self.attempts = self.attempts.saturating_add(1);
        self.responses = self.responses.saturating_add(1);
        self.successes = self
            .successes
            .saturating_add(u64::from(response_code == "NoError"));
        self.truncated = self.truncated.saturating_add(u64::from(truncated));
        self.authenticated_data = self
            .authenticated_data
            .saturating_add(u64::from(authenticated_data));
        self.rrsig_responses = self
            .rrsig_responses
            .saturating_add(u64::from(rrsig_response));
        self.dnssec_records = self.dnssec_records.saturating_add(dnssec_records);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes_sent);
        self.bytes_received = self.bytes_received.saturating_add(bytes_received);
        *self
            .response_codes
            .entry(response_code.to_owned())
            .or_default() += 1;
        let clamped = latency_us.clamp(1, MAX_LATENCY_US);
        let _ = self.histogram.record(clamped);
    }

    fn record_timeout(&mut self, bytes_sent: u64) {
        self.attempts = self.attempts.saturating_add(1);
        self.timeouts = self.timeouts.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes_sent);
    }

    fn record_error(&mut self, bytes_sent: u64) {
        self.attempts = self.attempts.saturating_add(1);
        self.errors = self.errors.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes_sent);
    }

    fn merge(&mut self, other: &Self) -> Result<()> {
        self.attempts = self.attempts.saturating_add(other.attempts);
        self.responses = self.responses.saturating_add(other.responses);
        self.successes = self.successes.saturating_add(other.successes);
        self.timeouts = self.timeouts.saturating_add(other.timeouts);
        self.errors = self.errors.saturating_add(other.errors);
        self.truncated = self.truncated.saturating_add(other.truncated);
        self.authenticated_data = self
            .authenticated_data
            .saturating_add(other.authenticated_data);
        self.rrsig_responses = self.rrsig_responses.saturating_add(other.rrsig_responses);
        self.dnssec_records = self.dnssec_records.saturating_add(other.dnssec_records);
        self.bytes_sent = self.bytes_sent.saturating_add(other.bytes_sent);
        self.bytes_received = self.bytes_received.saturating_add(other.bytes_received);
        for (code, count) in &other.response_codes {
            let ours = self.response_codes.entry(code.clone()).or_default();
            *ours = ours.saturating_add(*count);
        }
        self.histogram
            .add(&other.histogram)
            .context("failed to merge latency histograms")
    }

    fn latency_summary(&self) -> LatencySummary {
        if self.histogram.is_empty() {
            return empty_latency();
        }
        LatencySummary {
            min_us: Some(self.histogram.min()),
            mean_us: Some(self.histogram.mean()),
            p50_us: Some(self.histogram.value_at_quantile(0.50)),
            p95_us: Some(self.histogram.value_at_quantile(0.95)),
            p99_us: Some(self.histogram.value_at_quantile(0.99)),
            max_us: Some(self.histogram.max()),
        }
    }
}

fn empty_latency() -> LatencySummary {
    LatencySummary {
        min_us: None,
        mean_us: None,
        p50_us: None,
        p95_us: None,
        p99_us: None,
        max_us: None,
    }
}
