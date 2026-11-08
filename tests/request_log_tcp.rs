//! End-to-end behavior of opcode `0x04` over a real socket.
//!
//! The parser's own tests cover the payload in isolation. What can only be checked here is the
//! part that makes the design safe to put on a request's critical path: the frame is
//! length-prefixed and unanswered, so a client that writes one must be able to carry on
//! immediately, and a malformed or oversized one must not take down a connection that is also
//! carrying charges and locks.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use colbin::Colbin;
use async_trait::async_trait;
use fareward::{
    limiter::{
        aggregation::UsageKey,
        credits_blob::Credits,
        protocol::ChargeFrame,
        quota::{CreditLimits, LimitPolicy, RateLimiter, ScopeLimits},
        storage::{
            LimiterStore, StoredBudget, StoredBudgetRow, StoredBudgetUsage, StoredUsage,
            StoredUserAccess,
        },
        time_frame,
    },
    lock::registry::{LockLimits, LockRegistry},
    reqlog::{
        protocol::{ErrorEntry, REQUEST_LOG_MAX_PAYLOAD_SIZE, RequestLogRecord},
        writer::RequestLogSink,
    },
    service::{
        auth::DOMAIN,
        protocol::ReplyShape,
        server,
    },
    siphash::{SipHasher24, derive_key},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

const SECRET: &[u8] = b"request-log-test-secret";
const OPCODE_CHARGE: u8 = 0x01;
const OPCODE_LOG_REQUEST: u8 = 0x04;

struct EmptyStore;


#[async_trait]
impl LimiterStore for EmptyStore {
    async fn load_exact(&self, _key: UsageKey) -> Result<Option<StoredUsage>> {
        Ok(None)
    }
    async fn load_range(
        &self,
        _company_id: i32,
        _user_id: i32,
        _start_time_frame: i32,
        _end_time_frame: i32,
    ) -> Result<Vec<StoredUsage>> {
        Ok(vec![])
    }
    async fn upsert(&self, _key: UsageKey, _used_credits: Vec<u8>) -> Result<()> {
        Ok(())
    }
    async fn load_budget(&self, company_id: i32) -> Result<Option<StoredBudgetRow>> {
        let unix_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let unlimited = Credits {
            cpu: i64::MAX as u64,
            inference: i64::MAX as u64,
        };
        let budget = StoredBudget {
            company_id,
            daily: unlimited,
            budget_month_start_day: time_frame::month_start_day(unix_seconds)?,
            monthly_ceiling: unlimited,
            last_set: unlimited,
            updated: 0,
        };
        Ok(Some(StoredBudgetRow {
            budget,
            ..Default::default()
        }))
    }
    async fn upsert_budget(&self, _budget: StoredBudget) -> Result<()> {
        Ok(())
    }
    async fn upsert_budget_usage(&self, _usage: StoredBudgetUsage) -> Result<()> {
        Ok(())
    }
    async fn add_rejections(
        &self,
        _company_id: i32,
        _time_frame: i32,
        _rejections: fareward::limiter::block::Rejections,
    ) -> Result<()> {
        Ok(())
    }
    async fn load_user_access(&self, _c: i32, _u: i32) -> Result<Option<StoredUserAccess>> {
        Ok(None)
    }
}

struct TestServer {
    address: String,
    _shutdown: watch::Sender<bool>,
}

async fn start_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let limits = CreditLimits {
        ten_seconds: 1_000,
        hour: 10_000,
    };
    let generous = ScopeLimits {
        cpu: limits,
        inference: limits,
    };
    let limiter = Arc::new(RateLimiter::new(
        2,
        LimitPolicy {
            company: generous,
            user: generous,
            company_extra_daily_cpu: 0,
            // Neither test goes near a daily gate; the whole company allowance keeps this
            // fixture out of the way.
            user_daily_share_pct: 100,
            disable_user_limit: false,
        },
        Arc::new(EmptyStore),
        600,
    ));
    let locks = Arc::new(LockRegistry::new(
        2,
        LockLimits {
            max_keys: 64,
            max_total_waiters: 64,
            max_lease: Duration::from_secs(60),
        },
    ));
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    tokio::spawn(server::run(
        listener,
        None,
        limiter,
        locks,
        // No database in this harness: the sink accepts and discards, which is exactly what the
        // disabled configuration does in production. What is under test is the framing.
        RequestLogSink::disabled(),
        Arc::new(SECRET.to_vec()),
        Duration::from_secs(5),
        64,
        16,
        shutdown_receiver,
    ));
    TestServer {
        address,
        _shutdown: shutdown_sender,
    }
}

struct Client {
    socket: TcpStream,
    nonce: [u8; 8],
    sequence: u64,
}

impl Client {
    async fn connect(server: &TestServer) -> Self {
        let mut socket = TcpStream::connect(&server.address).await.unwrap();
        let mut nonce = [0_u8; 8];
        socket.read_exact(&mut nonce).await.unwrap();
        Self {
            socket,
            nonce,
            sequence: 0,
        }
    }

    /// Writes any frame whose body (the length header and everything after it, up to the tag) is
    /// already built. Tests that need a well-formed length call `write_length_prefixed`; this one
    /// stays raw so a frame can declare a length it does not carry.
    async fn write_frame(&mut self, opcode: u8, body: &[u8]) {
        let mut frame = vec![opcode];
        frame.extend_from_slice(body);
        let mut hasher = SipHasher24::new(&derive_key(SECRET));
        hasher.write(DOMAIN);
        hasher.write(&self.nonce);
        hasher.write(&self.sequence.to_be_bytes());
        hasher.write(&frame);
        frame.extend_from_slice(&hasher.finish().to_be_bytes());
        self.sequence += 1;
        self.socket.write_all(&frame).await.unwrap();
    }

    /// A request log frame: the two-byte length header followed by the payload.
    async fn write_request_log(&mut self, payload: &[u8]) {
        self.write_length_prefixed(OPCODE_LOG_REQUEST, payload).await;
    }

    /// A frame whose declared length disagrees with what follows it.
    async fn write_request_log_declaring(&mut self, declared: u16, payload: &[u8]) {
        let mut body = declared.to_be_bytes().to_vec();
        body.extend_from_slice(payload);
        self.write_frame(OPCODE_LOG_REQUEST, &body).await;
    }

    async fn write_length_prefixed(&mut self, opcode: u8, payload: &[u8]) {
        let mut body = (payload.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(payload);
        self.write_frame(opcode, &body).await;
    }

    /// The head is `[shape:1][correlation:u16]`, and the shape says how much body follows.
    /// Leaving any of it in the stream would desynchronize every reply after it.
    async fn read_reply(&mut self) -> (u16, ReplyShape, Vec<u8>) {
        let mut head = [0_u8; 3];
        self.socket.read_exact(&mut head).await.unwrap();
        let shape = ReplyShape::from_byte(head[0]).expect("a shape this daemon writes");
        let correlation = u16::from_be_bytes([head[1], head[2]]);
        let mut body = vec![0_u8; shape.body_size().expect("no test here grants a charge")];
        if !body.is_empty() {
            self.socket.read_exact(&mut body).await.unwrap();
        }
        (correlation, shape, body)
    }

    /// Authorization slots left empty: this test is about frame sequencing, not about grants.
    fn charge_payload() -> Vec<u8> {
        ChargeFrame {
            company_id: 1,
            user_id: 1,
            route_id: 1,
            cpu: 1,
            ..Default::default()
        }
        .encode()
    }
}

/// A well-formed record, matching what the Go client writes.
fn request_log_payload(error_count: u8) -> Vec<u8> {
    RequestLogRecord {
        date: 20_500,
        request_id: 1_767_225_600_123,
        route_id: 102,
        frame: 41,
        company_id: 7,
        user_id: 42,
        elapsed_ms: 318,
        errors: (0..error_count)
            .map(|index| ErrorEntry {
                id: 1_000 + i32::from(index),
                code_line: format!("responses.go:{}", 500 + u32::from(index)),
                text: "no se pudo obtener el registro".to_string(),
            })
            .collect(),
    }
    .encode()
}

/// The core claim of the fire-and-forget design: nothing comes back, so a caller that writes a
/// request log must not be left waiting. A charge sent afterwards is answered as if the log frame
/// had never been there — which also proves the reader consumed exactly its bytes and stayed in
/// sequence.
#[tokio::test]
async fn a_request_log_is_not_answered_and_does_not_desynchronize_the_stream() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client.write_request_log(&request_log_payload(2)).await;
    client
        .write_length_prefixed(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, shape, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the charge behind a request log was never answered");
    // Sequence 0 was the log frame, so the charge is sequence 1 — and the only reply.
    assert_eq!(correlation, 1);
    assert_eq!(shape, ReplyShape::ChargeAllowed);
}

#[tokio::test]
async fn a_request_log_with_no_errors_is_accepted() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client.write_request_log(&request_log_payload(0)).await;
    client
        .write_length_prefixed(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, shape, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the connection stalled after an error-free request log");
    assert_eq!(correlation, 1);
    assert_eq!(shape, ReplyShape::ChargeAllowed);
}

/// A log row is not worth a connection. A malformed payload is discarded and the connection keeps
/// serving the charges and locks that share it — unlike the other opcodes, where a bad frame means
/// the two sides disagree about something that decides whether a request is admitted.
#[tokio::test]
async fn a_malformed_request_log_does_not_close_the_connection() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    // Declares its true length, but the payload is far shorter than the header requires.
    client.write_request_log(&[0_u8; 4]).await;
    client
        .write_length_prefixed(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, shape, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the connection died on a malformed request log");
    assert_eq!(correlation, 1);
    assert_eq!(shape, ReplyShape::ChargeAllowed);
}

/// The ceiling is what stops a peer from making the daemon buffer without limit before its tag has
/// been checked. Past it the connection is closed, because a client claiming a payload that large
/// is not one this protocol can keep talking to.
#[tokio::test]
async fn an_oversized_declared_length_closes_the_connection() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client
        .write_request_log_declaring((REQUEST_LOG_MAX_PAYLOAD_SIZE + 1) as u16, &[])
        .await;

    let mut reply = [0_u8; 5];
    let outcome = timeout(Duration::from_secs(2), client.socket.read_exact(&mut reply)).await;
    let read = outcome.expect("the daemon neither answered nor closed the connection");
    assert!(
        read.is_err(),
        "an oversized frame was tolerated instead of ending the connection"
    );
}

/// Several request logs in a row are the normal case under load, and each one has to leave the
/// reader positioned exactly at the next opcode.
#[tokio::test]
async fn consecutive_request_logs_stay_in_frame() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    for errors in [0_u8, 1, 4, 2] {
        client.write_request_log(&request_log_payload(errors)).await;
    }
    client
        .write_length_prefixed(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, shape, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the stream desynchronized across consecutive request logs");
    assert_eq!(correlation, 4);
    assert_eq!(shape, ReplyShape::ChargeAllowed);
}
