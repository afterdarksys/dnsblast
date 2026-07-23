use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dnsblast::{
    config::{RunConfig, RunLimit, Target, Transport},
    engine,
};
use hickory_proto::{
    op::{Message, OpCode},
    rr::{Name, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

fn config(targets: Vec<Target>, transport: Transport, requests: u64) -> RunConfig {
    RunConfig {
        targets,
        names: vec![Name::from_str("example.test.").unwrap()],
        record_types: vec![RecordType::A, RecordType::AAAA],
        transport,
        limit: RunLimit::Requests(requests),
        concurrency: 4,
        rate: None,
        timeout: Duration::from_millis(200),
        warmup: 2,
        dnssec: true,
        edns_payload: 1232,
        workers: 2,
        seed: 7,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ac1_ac5_ac10_udp_targets_run_concurrently_with_exact_counts_and_warmup_excluded() {
    let (first_address, first_seen, first_server) = udp_server().await;
    let (second_address, second_seen, second_server) = udp_server().await;
    let result = engine::run(config(
        vec![
            Target {
                label: "bind".into(),
                address: first_address,
            },
            Target {
                label: "nsd".into(),
                address: second_address,
            },
        ],
        Transport::Udp,
        40,
    ))
    .await
    .unwrap();

    first_server.abort();
    second_server.abort();
    assert_eq!(result.results.len(), 2);
    assert_eq!(result.ranking.len(), 2);
    for target in &result.results {
        assert_eq!(target.attempts, 40);
        assert_eq!(target.responses, 40);
        assert_eq!(target.successes, 40);
        assert_eq!(target.errors, 0);
        assert_eq!(target.timeouts, 0);
    }
    assert_eq!(first_seen.load(Ordering::Relaxed), 42);
    assert_eq!(second_seen.load(Ordering::Relaxed), 42);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ac4_tcp_transport_reuses_connections_and_completes() {
    let (address, seen, server) = tcp_server().await;
    let result = engine::run(config(
        vec![Target {
            label: "tcp".into(),
            address,
        }],
        Transport::Tcp,
        20,
    ))
    .await
    .unwrap();

    server.abort();
    assert_eq!(result.results[0].attempts, 20);
    assert_eq!(result.results[0].responses, 20);
    assert_eq!(seen.load(Ordering::Relaxed), 22);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac4_unresponsive_target_is_bounded_by_timeout() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unused = socket.local_addr().unwrap();
    drop(socket);
    let mut test_config = config(
        vec![Target {
            label: "down".into(),
            address: unused,
        }],
        Transport::Udp,
        4,
    );
    test_config.warmup = 0;
    test_config.timeout = Duration::from_millis(30);
    let started = Instant::now();
    let result = engine::run(test_config).await.unwrap();

    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(result.results[0].attempts, 4);
    assert_eq!(result.results[0].timeouts + result.results[0].errors, 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac5_ac6_duration_and_rate_are_enforced_per_target() {
    let (address, seen, server) = udp_server().await;
    let mut test_config = config(
        vec![Target {
            label: "paced".into(),
            address,
        }],
        Transport::Udp,
        1,
    );
    test_config.limit = RunLimit::Duration(Duration::from_millis(160));
    test_config.rate = Some(100);
    test_config.warmup = 0;
    let started = Instant::now();
    let result = engine::run(test_config).await.unwrap();
    let elapsed = started.elapsed();

    server.abort();
    assert!(elapsed >= Duration::from_millis(120));
    assert!(elapsed < Duration::from_secs(1));
    assert!((10..=25).contains(&result.results[0].attempts));
    assert_eq!(seen.load(Ordering::Relaxed), result.results[0].attempts);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ac12_one_unresponsive_target_does_not_hide_healthy_results() {
    let (healthy_address, _, healthy_server) = udp_server().await;
    let unused_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unused_address = unused_socket.local_addr().unwrap();
    drop(unused_socket);
    let mut test_config = config(
        vec![
            Target {
                label: "healthy".into(),
                address: healthy_address,
            },
            Target {
                label: "down".into(),
                address: unused_address,
            },
        ],
        Transport::Udp,
        8,
    );
    test_config.warmup = 0;
    test_config.timeout = Duration::from_millis(30);
    let result = engine::run(test_config).await.unwrap();

    healthy_server.abort();
    let healthy = result
        .results
        .iter()
        .find(|result| result.target.label == "healthy")
        .unwrap();
    let down = result
        .results
        .iter()
        .find(|result| result.target.label == "down")
        .unwrap();
    assert_eq!(healthy.responses, 8);
    assert_eq!(down.timeouts + down.errors, 8);
}

async fn udp_server() -> (SocketAddr, Arc<AtomicU64>, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let seen = Arc::new(AtomicU64::new(0));
    let task_seen = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            task_seen.fetch_add(1, Ordering::Relaxed);
            let response = response_for(&buffer[..length]);
            if socket.send_to(&response, peer).await.is_err() {
                break;
            }
        }
    });
    (address, seen, task)
}

async fn tcp_server() -> (SocketAddr, Arc<AtomicU64>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicU64::new(0));
    let task_seen = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let connection_seen = Arc::clone(&task_seen);
            tokio::spawn(handle_tcp(stream, connection_seen));
        }
    });
    (address, seen, task)
}

async fn handle_tcp(mut stream: TcpStream, seen: Arc<AtomicU64>) {
    while let Ok(length) = stream.read_u16().await {
        let mut query = vec![0_u8; length as usize];
        if stream.read_exact(&mut query).await.is_err() {
            break;
        }
        seen.fetch_add(1, Ordering::Relaxed);
        let response = response_for(&query);
        if stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .is_err()
            || stream.write_all(&response).await.is_err()
        {
            break;
        }
    }
}

fn response_for(wire: &[u8]) -> Vec<u8> {
    let request = Message::from_vec(wire).unwrap();
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries);
    if let Some(edns) = request.edns {
        response.set_edns(edns);
    }
    response.to_vec().unwrap()
}
