use std::{net::SocketAddr, str::FromStr, time::Duration};

use dnsblast::{
    cli::OutputFormat,
    config::{RunConfig, RunLimit, Target, Transport, parse_record_types, parse_target},
    dns::{build_query, inspect_response},
    engine::{ConfigSnapshot, RunResult},
    report::{emit, rank_results},
    stats::{Aggregate, TargetResult},
};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};

#[test]
fn ac2_target_and_query_plan_inputs_are_deterministic() {
    let target = parse_target("bind=127.0.0.1").unwrap();
    assert_eq!(target.label, "bind");
    assert_eq!(target.address, "127.0.0.1:53".parse().unwrap());

    let types = parse_record_types(&["A,AAAA".into(), "A".into()]).unwrap();
    assert_eq!(types, vec![RecordType::A, RecordType::AAAA]);
    let numeric = parse_record_types(&["TYPE256,29".into()]).unwrap();
    assert_eq!(
        numeric,
        vec![RecordType::Unknown(256), RecordType::Unknown(29)]
    );
}

#[test]
fn ac3_all_preset_contains_dnssec_and_service_types() {
    let types = parse_record_types(&["ALL".into()]).unwrap();
    for required in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::SRV,
        RecordType::DNSKEY,
        RecordType::DS,
        RecordType::RRSIG,
        RecordType::NSEC3,
    ] {
        assert!(types.contains(&required), "ALL omitted {required}");
    }
}

#[test]
fn ac7_dnssec_query_sets_do_and_response_is_observed() {
    let name = Name::from_str("example.test.").unwrap();
    let wire = build_query(42, &name, RecordType::A, true, 1232).unwrap();
    let parsed = Message::from_vec(&wire).unwrap();
    assert_eq!(parsed.metadata.id, 42);
    assert!(parsed.edns.as_ref().unwrap().flags().dnssec_ok);

    let mut response = Message::new(42, MessageType::Response, OpCode::Query);
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.authentic_data = true;
    response.set_edns(Edns::new());
    response.add_answer(Record::from_rdata(
        name,
        60,
        RData::A("192.0.2.1".parse().unwrap()),
    ));
    let observation = inspect_response(42, &response.to_vec().unwrap()).unwrap();
    assert!(observation.authenticated_data);
    assert_eq!(observation.response_code, "NoError");
}

#[test]
fn ac8_aggregation_is_bounded_and_percentiles_work() {
    let mut aggregate = Aggregate::new(&[RecordType::A]).unwrap();
    aggregate.record_response(
        RecordType::A,
        100,
        31,
        80,
        "NoError",
        false,
        false,
        0,
        false,
    );
    aggregate.record_response(
        RecordType::A,
        300,
        31,
        80,
        "NXDomain",
        true,
        false,
        0,
        false,
    );
    let summary = aggregate.finish(
        Target {
            label: "test".into(),
            address: "127.0.0.1:53".parse().unwrap(),
        },
        Duration::from_secs(1),
    );
    assert_eq!(summary.attempts, 2);
    assert_eq!(summary.responses, 2);
    assert_eq!(summary.successes, 1);
    assert_eq!(summary.truncated, 1);
    assert_eq!(summary.latency.min_us, Some(100));
    assert_eq!(summary.latency.max_us, Some(300));
    assert_eq!(summary.qps, 2.0);
}

#[test]
fn ac11_configuration_rejects_zero_concurrency() {
    let config = RunConfig {
        targets: vec![Target {
            label: "test".into(),
            address: SocketAddr::from(([127, 0, 0, 1], 53)),
        }],
        names: vec![Name::from_str("example.test.").unwrap()],
        record_types: vec![RecordType::A],
        transport: Transport::Udp,
        limit: RunLimit::Requests(1),
        concurrency: 0,
        rate: None,
        timeout: Duration::from_secs(1),
        warmup: 0,
        dnssec: false,
        edns_payload: 1232,
        workers: 1,
        seed: 1,
    };
    assert!(config.validate().is_err());
}

#[test]
fn ac1_ranking_is_qps_descending_with_stable_ties() {
    let result = |label: &str, qps: f64| {
        TargetResult::empty(
            Target {
                label: label.into(),
                address: "127.0.0.1:53".parse().unwrap(),
            },
            qps,
        )
    };
    let ranking = rank_results(&[
        result("nsd", 9.0),
        result("bind", 10.0),
        result("mine", 10.0),
    ]);
    let labels: Vec<_> = ranking.iter().map(|entry| entry.target.as_str()).collect();
    assert_eq!(labels, vec!["bind", "mine", "nsd"]);
}

#[test]
fn ac9_json_output_is_versioned_and_atomically_written() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("result.json");
    let target = Target {
        label: "test".into(),
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let result = RunResult {
        schema_version: 1,
        started_at: chrono::Utc::now(),
        config: ConfigSnapshot {
            targets: vec![target.clone()],
            names: vec!["example.test.".into()],
            record_types: vec!["A".into()],
            transport: "udp".into(),
            requests: Some(1),
            duration_ms: None,
            concurrency: 1,
            rate: None,
            timeout_ms: 100,
            warmup: 0,
            dnssec: false,
            edns_payload: 1232,
            workers: 1,
            seed: 0,
        },
        results: vec![TargetResult::empty(target, 0.0)],
        ranking: Vec::new(),
        interrupted: false,
    };

    emit(&result, OutputFormat::Json, Some(&path)).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert!(!directory.path().read_dir().unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}
