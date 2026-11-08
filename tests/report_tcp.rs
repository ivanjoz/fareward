//! The report opcode end to end: a real store behind a real server, read over an authenticated
//! socket the way the Go client reads it.

use std::{sync::Arc, time::Duration};

use colbin::Colbin;
use fareward::{
    limiter::{
        block::Rejections,
        quota::{CreditLimits, LimitPolicy, RateLimiter, ScopeLimits, Windows},
        storage::StoredUserAccess,
    },
    lock::registry::{LockLimits, LockRegistry},
    service::{auth::DOMAIN, protocol::ReplyShape, server},
    siphash::{SipHasher24, derive_key},
    store::{
        FjallStore,
        grants::{GrantEntry, encode_grant_batch},
        limiter::StoreBackend,
        query::{ReportQueryFrame, parse_report_query},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

const SECRET: &[u8] = b"report-test-secret";
const OPCODE_REPORT: u8 = 0x09;

async fn start(store: FjallStore) -> (String, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let limits = CreditLimits {
        short: 1_000,
        long: 10_000,
    };
    let scope = ScopeLimits {
        cpu: limits,
        inference: limits,
    };
    let limiter = Arc::new(RateLimiter::new(
        2,
        LimitPolicy {
            company: scope,
            user: scope,
            company_extra_daily_cpu: 0,
            user_daily_share_pct: 100,
            disable_user_limit: false,
            windows: Windows::default(),
        },
        // The grants come from the same store, as in the daemon.
        Arc::new(StoreBackend::new(store.clone(), Arc::new(store))),
        600,
    ));
    let locks = Arc::new(LockRegistry::new(
        2,
        LockLimits {
            max_keys: 8,
            max_total_waiters: 8,
            max_lease: Duration::from_secs(60),
        },
    ));
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    tokio::spawn(server::run(
        listener,
        None,
        limiter,
        locks,
        Arc::new(SECRET.to_vec()),
        Duration::from_secs(5),
        8,
        8,
        shutdown_receiver,
    ));
    (address, shutdown_sender)
}

/// Sends one report frame on a fresh connection and returns `(shape, body)`.
async fn ask(address: &str, frame: ReportQueryFrame) -> (u8, Vec<u8>) {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let mut nonce = [0_u8; 8];
    socket.read_exact(&mut nonce).await.unwrap();

    let payload = frame.encode();
    let mut bytes = vec![OPCODE_REPORT];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    let mut hasher = SipHasher24::new(&derive_key(SECRET));
    hasher.write(DOMAIN);
    hasher.write(&nonce);
    hasher.write(&0_u64.to_be_bytes());
    hasher.write(&bytes);
    bytes.extend_from_slice(&hasher.finish().to_be_bytes());
    socket.write_all(&bytes).await.unwrap();

    let mut head = [0_u8; 3];
    socket.read_exact(&mut head).await.unwrap();
    assert_eq!(u16::from_be_bytes([head[1], head[2]]), 0, "correlation");
    if head[0] != ReplyShape::Report as u8 {
        return (head[0], Vec::new());
    }
    let mut length = [0_u8; 4];
    socket.read_exact(&mut length).await.unwrap();
    let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
    socket.read_exact(&mut body).await.unwrap();
    (head[0], body)
}

#[tokio::test]
async fn reports_answer_from_the_store() {
    let directory = tempfile::tempdir().unwrap();
    let store = FjallStore::open(directory.path()).unwrap();
    for company in [0, 7, 9] {
        store
            .put_usage(company, None, 200_000_010, vec![0, 4, 1, 2])
            .unwrap();
    }
    store
        .put_usage(7, Some(42), 200_000_010, vec![0, 4, 5, 0])
        .unwrap();
    store
        .add_rejections(
            7,
            200_000_010,
            Rejections {
                short: 4,
                long: 0,
                no_funds: 1,
            },
        )
        .unwrap();
    let (address, _shutdown) = start(store.clone()).await;

    let frames = [
        (1, 7, 0), // one company
        (2, 7, 0), // every user of it
        (3, 0, 0), // every company
        (4, 0, 0), // every budget: none
    ];
    for (kind, company_id, user_id) in frames {
        let (shape, body) = ask(
            &address,
            ReportQueryFrame {
                kind,
                company_id,
                user_id,
                first: 200_000_000,
                last: 200_000_020,
            },
        )
        .await;
        assert_eq!(shape, ReplyShape::Report as u8, "kind {kind}");
        // The socket answers exactly what the store answers.
        let query = parse_report_query(
            &ReportQueryFrame {
                kind,
                company_id,
                user_id,
                first: 200_000_000,
                last: 200_000_020,
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(body, query.answer(&store).unwrap(), "kind {kind}");
        let rows = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
        let expected = match kind {
            1 | 2 => 1,
            3 => 3,
            _ => 0,
        };
        assert_eq!(rows, expected, "kind {kind}");
    }
}

/// An invalid query is a protocol error: the daemon closes the connection, as for any other
/// authenticated frame it cannot parse.
#[tokio::test]
async fn an_invalid_query_closes_the_connection() {
    let directory = tempfile::tempdir().unwrap();
    let store = FjallStore::open(directory.path()).unwrap();
    let (address, _shutdown) = start(store).await;

    let mut socket = TcpStream::connect(&address).await.unwrap();
    let mut nonce = [0_u8; 8];
    socket.read_exact(&mut nonce).await.unwrap();
    let payload = ReportQueryFrame {
        kind: 1,
        company_id: 1,
        user_id: 0,
        first: 10,
        last: 9,
    }
    .encode();
    let mut bytes = vec![OPCODE_REPORT];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    let mut hasher = SipHasher24::new(&derive_key(SECRET));
    hasher.write(DOMAIN);
    hasher.write(&nonce);
    hasher.write(&0_u64.to_be_bytes());
    hasher.write(&bytes);
    bytes.extend_from_slice(&hasher.finish().to_be_bytes());
    socket.write_all(&bytes).await.unwrap();
    let mut buffer = [0_u8; 1];
    assert_eq!(
        socket.read(&mut buffer).await.unwrap(),
        0,
        "closed without a reply"
    );
}

/// Serves a seeded store for a real Go client: `FAREWARD_REPORT_E2E_ADDR` names the address to
/// write, `FAREWARD_REPORT_E2E_SECONDS` how long to serve. Run by hand.
#[tokio::test]
#[ignore]
async fn serve_for_a_go_client() {
    let directory = tempfile::tempdir().unwrap();
    let store = FjallStore::open(directory.path()).unwrap();
    store
        .put_usage(0, None, 100_000_010, vec![0, 4, 1, 2])
        .unwrap();
    store
        .put_usage(7, None, 200_000_010, vec![0, 4, 1, 2])
        .unwrap();
    store
        .put_usage(7, Some(42), 200_000_010, vec![0, 4, 5, 0])
        .unwrap();
    store
        .add_rejections(
            7,
            200_000_010,
            Rejections {
                short: 4,
                long: 0,
                no_funds: 1,
            },
        )
        .unwrap();
    store
        .put_budget(fareward::limiter::storage::StoredBudget {
            company_id: 7,
            daily: fareward::limiter::credits_blob::Credits {
                cpu: 1 << 40,
                inference: 3,
            },
            ..Default::default()
        })
        .unwrap();
    store
        .put_metrics(
            100,
            2,
            &fareward::sysmetrics::MetricsSample {
                cpu_percent: 2_345,
                ..Default::default()
            },
        )
        .unwrap();
    let (address, _shutdown) = start(store).await;
    std::fs::write(std::env::var("FAREWARD_REPORT_E2E_ADDR").unwrap(), &address).unwrap();
    let seconds: u64 = std::env::var("FAREWARD_REPORT_E2E_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(30);
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

/// A pushed batch is acknowledged only once stored, and the limiter then reads it.
#[tokio::test]
async fn pushed_grants_are_stored_and_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let store = FjallStore::open(directory.path()).unwrap();
    let (address, _shutdown) = start(store.clone()).await;

    let access = StoredUserAccess {
        grants_blob: vec![0x01, 0x39],
        sub_grants_blob: Vec::new(),
        status: 1,
    };
    let payload = encode_grant_batch(&[GrantEntry {
        company_id: 7,
        user_id: 42,
        access: Some(access.clone()),
    }]);
    let mut socket = TcpStream::connect(&address).await.unwrap();
    let mut nonce = [0_u8; 8];
    socket.read_exact(&mut nonce).await.unwrap();
    let mut bytes = vec![0x0A];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    let mut hasher = SipHasher24::new(&derive_key(SECRET));
    hasher.write(DOMAIN);
    hasher.write(&nonce);
    hasher.write(&0_u64.to_be_bytes());
    hasher.write(&bytes);
    bytes.extend_from_slice(&hasher.finish().to_be_bytes());
    socket.write_all(&bytes).await.unwrap();

    let mut reply = [0_u8; 3];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], ReplyShape::Ack as u8);
    assert_eq!(store.user_grants(7, 42).unwrap(), Some(access));
}
