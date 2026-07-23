# DNSBlast

DNSBlast is a modern Rust toolkit for high-concurrency DNS performance testing.
It runs the same deterministic workload against multiple DNS servers at once,
making comparisons between your server, BIND, NSD, or other implementations
straightforward.

It supports:

- simultaneous named targets with independent concurrency and rate limits;
- UDP and persistent TCP workers;
- fixed-request and fixed-duration runs;
- individual, repeated, comma-delimited, or `ALL` record types;
- EDNS DNSSEC OK queries and AD, RRSIG, and DNSSEC-record observations;
- streaming counters and worker-bounded sharded HDR latency histograms;
- stdout tables, versioned JSON, and atomic human-readable log files;
- warmup traffic, deterministic query plans, Ctrl-C partial results, and
  per-record-type breakdowns.

Only load-test systems you own or are explicitly authorized to test.

## Build

DNSBlast requires Rust 1.88 or newer.

```bash
cargo build --release
./target/release/dnsblast --help
```

For the least client-side overhead, benchmark with the release binary.

## Compare several DNS servers

```bash
./target/release/dnsblast \
  --server mine=10.10.0.10 \
  --server bind=10.10.0.11:53 \
  --server nsd=10.10.0.12 \
  --name example.net \
  --name www.example.net \
  --type A,AAAA,MX,NS,SOA,DNSKEY \
  --dnssec \
  --duration 60s \
  --warmup 10000 \
  --concurrency 512 \
  --workers 8
```

Each server receives its own 512-query concurrency pool. Targets finish the
warmup phase before a shared start barrier releases measured traffic, so one
target does not get a head start.

Example summary:

```text
DNSBlast comparison — 3 target(s), UDP, 2026-07-23T18:00:00+00:00
RANK TARGET                     QPS   ATTEMPTS      RESP        OK   TIMEOUT      ERROR    P50(us)    P99(us)
1    mine                 812345.12   48740707  48740707  48740707         0          0         91        420
2    nsd                  779120.30   46747218  46747218  46747218         0          0         98        451
3    bind                 741005.82   44460349  44460349  44460349         0          0        103        487
```

## Workloads

Use direct names, a file, or both:

```bash
./target/release/dnsblast \
  -s auth-a=192.0.2.10 -s auth-b=192.0.2.11 \
  --names-file zones.txt \
  --type ALL \
  --requests 1000000 \
  --concurrency 256 \
  --seed 20260723 \
  --output json \
  --output-file results.json
```

Names files contain one DNS name per line. Empty lines and lines starting with
`#` are ignored. Names and types are deduplicated while preserving their first
appearance. The seed rotates the cross-product of names and record types,
allowing exact workload reproduction.

`ALL` currently expands to:

```text
A AAAA ANAME ANY AXFR CAA CDS CDNSKEY CERT CNAME CSYNC DNSKEY DS HINFO
HTTPS IXFR KEY MX NAPTR NS NSEC NSEC3 NSEC3PARAM NULL OPENPGPKEY PTR
RRSIG SIG SMIMEA SOA SRV SSHFP SVCB TLSA TSIG TXT
```

Any 16-bit QTYPE not named in that preset can be requested with RFC 3597-style
`TYPE<number>` syntax (for example, `TYPE256` for URI) or as a bare number.

`AXFR` and `IXFR` metrics cover the first response message. DNSBlast reconnects
after those queries so additional transfer frames cannot be mistaken for the
next response. Full-zone transfer throughput is a distinct benchmark and is
not measured by this release.

## TCP and rate-controlled tests

```bash
./target/release/dnsblast \
  -s recursive=2001:db8::53 \
  -n example.org \
  -t A -t AAAA \
  --transport tcp \
  --duration 5m \
  --concurrency 128 \
  --rate 50000 \
  --timeout 1s
```

The rate is queries per second **per target**. TCP workers retain their
connections until an I/O/protocol failure or transfer query requires a clean
reconnect.

## Results

Human output is the default:

```bash
dnsblast ... --output stdout
```

JSON can go to stdout or an atomically replaced file:

```bash
dnsblast ... --output json
dnsblast ... --output json --output-file run-01.json
```

Human-readable log output requires a file:

```bash
dnsblast ... --output log --output-file run-01.log
```

JSON has `schema_version: 1` and includes the effective configuration, every
target aggregate, per-record-type summaries, and QPS ranking. Valid DNS replies
such as `NXDOMAIN` count as responses; only `NOERROR` counts as success.
Timeouts and transport/protocol errors have separate counters. Latency
percentiles describe parsed DNS responses, while QPS is parsed responses per
elapsed second.

## DNSSEC scope

With `--dnssec`, DNSBlast:

- emits EDNS with the DO bit and configured payload size;
- counts responses with the AD bit;
- counts responses containing RRSIG;
- counts DNSSEC record instances across response sections;
- can directly query DNSKEY, DS, RRSIG, NSEC, NSEC3, and related types.

It intentionally does not cryptographically validate the chain of trust in the
load-generation hot path. That would mix client cryptographic CPU cost into the
server benchmark. Use a validating resolver or a dedicated validation pass when
chain correctness—not server response behavior—is the measurement target.

## Benchmark discipline

For carrier-grade measurements:

1. Run the release build from dedicated generator hardware.
2. Keep targets on equivalent network paths and synchronize host clocks.
3. Raise file-descriptor and ephemeral-port limits for very high concurrency.
4. Warm caches deliberately, or flush all target caches before cold-cache runs.
5. Start below saturation with `--rate`, then increase in controlled steps.
6. Repeat runs, alternate target ordering/topology, and compare distributions,
   not a single peak QPS number.
7. Watch generator CPU, NIC drops, socket errors, and link utilization so the
   load generator does not become the bottleneck.

The complete implementation contract is in [docs/SPEC.md](docs/SPEC.md).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

The engine integration tests open loopback UDP and TCP sockets.
