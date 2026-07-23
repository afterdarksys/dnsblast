# DNSBlast Carrier-Grade DNS Performance Toolkit

## Metadata

**Author:** Codex, from the user-supplied product brief  
**Date:** 2026-07-23  
**Status:** Approved — implementation contract derived directly from the requested feature set  
**Reviewers:** Project owner

## Context

DNS operators need to compare authoritative and recursive DNS implementations under the
same repeatable workload. Existing generic load tools often hide DNS response semantics,
make multi-server comparisons awkward, or retain every sample and distort long-running
tests.

DNSBlast is a Rust command-line tool that drives one or more DNS servers concurrently,
using the same names and record-type plan for each target. It reports throughput, latency,
errors, response codes, and DNSSEC signals without retaining individual responses. It is
intended for controlled performance tests against systems the operator is authorized to
test.

The initial release prioritizes a dependable UDP/TCP benchmarking core, bounded memory,
machine-readable output, and fair side-by-side comparisons. It observes DNSSEC response
properties; cryptographic chain validation is explicitly separated from load generation
to avoid contaminating server-performance measurements with client CPU cost.

## Functional Requirements

- FR-1: The CLI MUST accept one or more named servers in `LABEL=IP[:PORT]` form.
- FR-2: The CLI MUST accept one or more query names directly and from a newline-delimited file.
- FR-3: The CLI MUST accept repeated/comma-delimited DNS record types and an `ALL` preset covering common address, service, delegation, policy, transfer, and DNSSEC types.
- FR-4: The engine MUST support UDP and TCP DNS queries.
- FR-5: The engine MUST run targets concurrently and MUST apply the configured concurrency independently to each target.
- FR-6: The engine MUST support both fixed request-count and fixed-duration runs.
- FR-7: The engine MUST support an optional per-target queries-per-second limit.
- FR-8: The engine MUST set the EDNS DNSSEC OK bit when DNSSEC mode is enabled.
- FR-9: Results MUST include DNSSEC observations: authenticated-data responses, RRSIG-bearing responses, and DNSSEC response record counts.
- FR-10: Results MUST include attempts, responses, success count, timeout count, error count, truncation count, response-code counts, bytes, elapsed time, QPS, and latency min/mean/p50/p95/p99/max.
- FR-11: Results MUST be emitted as a human-readable stdout table, pretty JSON, or a human-readable log file.
- FR-12: Comparative results MUST include every configured target and a throughput ranking.
- FR-13: The engine MUST use bounded-memory aggregation rather than storing every response.
- FR-14: The CLI MUST expose runtime worker-thread count, concurrency, timeout, EDNS payload size, warmup request count, and deterministic query-plan seed.
- FR-15: Warmup requests MUST be excluded from measured results.
- FR-16: Invalid servers, names, record types, zero-valued limits, and unwritable output paths MUST fail with an actionable non-zero CLI error.
- FR-17: The process MUST handle Ctrl-C by stopping new work and reporting completed samples.

## Non-Functional Requirements

- **NFR-1:** Result memory MUST be `O(targets × record-types × runtime-workers)` and independent of request count and blast concurrency.
- **NFR-2:** Every network operation MUST be bounded by the configured timeout.
- **NFR-3:** A worker failure MUST NOT prevent results from other workers or targets being reported.
- **NFR-4:** JSON output MUST be versioned and stable enough for automation.
- **NFR-5:** The default configuration MUST be safe for a small local smoke test: 1,000 requests, concurrency 32, timeout 2 seconds.
- **NFR-6:** Unit tests MUST cover parsing, query construction, aggregation, percentile reporting, and comparison ranking.
- **NFR-7:** The release build MUST compile without warnings on the repository toolchain.

## Acceptance Criteria

### AC-1: Multi-target comparison (FR-1, FR-5, FR-12)
Given three named loopback test servers. When a run starts. Then all three receive queries during overlapping time windows and all three appear in the ranking.

### AC-2: Query-plan inputs (FR-2, FR-3)
Given CLI names, a names file, repeated types, and comma-delimited types. When configuration is built. Then the deduplicated cross-product is available to every target.

### AC-3: All-types preset (FR-3)
Given `--type ALL`. When configuration is built. Then the documented common and DNSSEC record-type preset is selected.

### AC-4: Bounded transports (FR-4, NFR-2)
Given UDP or TCP transport and an unresponsive endpoint. When a query is made. Then it terminates within the configured timeout and is counted as a timeout/error.

### AC-5: Run limits (FR-6)
Given `--requests N` or `--duration D`. When the run executes. Then exactly N measured attempts per target are scheduled or attempts continue until the shared deadline, respectively.

### AC-6: Target pacing (FR-7)
Given a QPS limit. When multiple targets run. Then the engine applies pacing independently to each target.

### AC-7: DNSSEC observations (FR-8, FR-9)
Given DNSSEC mode. When queries and responses are processed. Then emitted queries contain EDNS with DO set and parsed responses update AD, RRSIG, and DNSSEC-record counters.

### AC-8: Bounded aggregation (FR-10, FR-13, NFR-1)
Given any request count. When samples are aggregated. Then bounded histograms produce all required summary fields without retaining response bodies.

### AC-9: Output formats (FR-11, NFR-4)
Given each output format. When output is rendered. Then the same run summary is a table, versioned valid JSON, or a human-readable log.

### AC-10: Runtime and warmup (FR-14, FR-15)
Given warmup and runtime settings. When a run starts. Then warmup traffic is sent first and omitted from counts while configured thread/timeout/EDNS/seed values govern the measured run.

### AC-11: Validation (FR-16)
Given malformed or zero-valued input. When configuration is validated. Then validation fails before network traffic with a useful message.

### AC-12: Cancellation and isolation (FR-17, NFR-3)
Given cancellation or an isolated worker failure. When shutdown begins. Then the run stops cleanly and preserves completed aggregates.

## Edge Cases

- EC-1: A UDP response with the truncated bit is counted; DNSBlast does not silently retry over TCP.
- EC-2: Malformed DNS responses count as protocol errors and do not crash a worker.
- EC-3: A TCP peer that connects but never returns a full length-prefixed message times out.
- EC-4: Empty/comment-only names files are rejected when no direct names exist.
- EC-5: Duplicate target labels, names, and record types are rejected or deduplicated deterministically as appropriate.
- EC-6: Latency values outside histogram range are clamped and counted, never panicked.
- EC-7: NXDOMAIN and other valid DNS responses are responses, with success defined separately as `NOERROR`.
- EC-8: Partial output files are replaced only after a complete result has been serialized.

## API Contracts

```typescript
type Transport = "udp" | "tcp";
type OutputFormat = "stdout" | "json" | "log";

interface Target {
  label: string;
  address: string; // validated socket address
}

interface RunConfig {
  targets: Target[];
  names: string[];
  record_types: string[];
  transport: Transport;
  requests?: number;
  duration_ms?: number;
  concurrency: number; // per target
  rate?: number;       // per target QPS
  timeout_ms: number;
  warmup: number;      // per target
  dnssec: boolean;
  edns_payload: number;
  workers: number;
  seed: number;
}

interface LatencySummary {
  min_us: number | null;
  mean_us: number | null;
  p50_us: number | null;
  p95_us: number | null;
  p99_us: number | null;
  max_us: number | null;
}

interface TargetResult {
  target: Target;
  elapsed_ms: number;
  attempts: number;
  responses: number;
  successes: number;
  timeouts: number;
  errors: number;
  truncated: number;
  authenticated_data: number;
  rrsig_responses: number;
  dnssec_records: number;
  bytes_sent: number;
  bytes_received: number;
  response_codes: Record<string, number>;
  latency: LatencySummary;
  qps: number;
}

interface RunResult {
  schema_version: 1;
  started_at: string;
  config: RunConfig;
  results: TargetResult[];
  ranking: Array<{rank: number; target: string; qps: number}>;
  interrupted: boolean;
}
```

Errors are written to stderr and produce a non-zero process exit. Successful JSON output
contains only the `RunResult` document on stdout.

HTTP endpoints are intentionally absent; `GET /not-applicable` MUST NOT be exposed because
this is a local command-line application.

## Data Models

| Entity | Field | Type | Constraints |
|---|---|---|---|
| Target | label | string | non-empty, unique |
| Target | address | socket address | IPv4/IPv6 with default port 53 |
| QueryPlan | names | DNS names | non-empty, canonicalized |
| QueryPlan | record_types | record type enum | non-empty, deterministic order |
| Aggregate | counters | u64 | saturating additions |
| Aggregate | latency | HDR histogram | microseconds, bounded range |
| RunResult | schema_version | integer | exactly 1 |
| Ranking | qps | float | descending, stable target-label tie break |

## Out of Scope

- OS-1: DoH, DoT, and DoQ are deferred; transport-specific TLS/QUIC setup would require a separate comparison contract.
- OS-2: Cryptographic DNSSEC chain-of-trust validation is excluded from the hot load path; DNSBlast tests DNSSEC query/response behavior and record availability.
- OS-3: Dynamic DNS updates and zone mutation are excluded because the tool is read-only.
- OS-4: Distributed load generation across multiple hosts is deferred.
- OS-5: A graphical dashboard and persistent metrics database are deferred; JSON is the integration surface.
- OS-6: Automatic authorization or safe-target discovery is impossible; operators are responsible for testing only systems they own or are authorized to test.
