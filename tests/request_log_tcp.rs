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
use async_trait::async_trait;
use fareward::{
    limiter::{
        aggregation::UsageKey,
        credits_blob::Credits,
        protocol::CHARGE_PAYLOAD_SIZE,
        quota::{CreditLimits, LimitPolicy, RateLimiter, ScopeLimits},
        storage::{
            LimiterStore, StoredBudget, StoredBudgetRow, StoredBudgetUsage, StoredUsage,
            StoredUserAccess,
        },
        time_frame,
    },
    lock::registry::{LockLimits, LockRegistry},
    reqlog::{protocol::REQUEST_LOG_MAX_PAYLOAD_SIZE, writer::RequestLogSink},
    sequence::{
        allocator::{SequenceAllocator, SequenceLimits},
        protocol::SEQUENCE_NAME_MAX,
        store::SequenceStore,
    },
    service::server,
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
const OPCODE_RESERVE_SEQUENCE: u8 = 0x07;
const OPCODE_SET_SEQUENCE: u8 = 0x08;

struct EmptyStore;

/// The counters live in memory: what is under test here is the framing, not the durability.
#[derive(Default)]
struct MemorySequenceStore(std::sync::Mutex<std::collections::HashMap<String, i64>>);

#[async_trait]
impl SequenceStore for MemorySequenceStore {
    async fn bump(&self, name: &str, by: i64) -> Result<()> {
        *self.0.lock().unwrap().entry(name.to_owned()).or_insert(0) += by;
        Ok(())
    }
    async fn read(&self, name: &str) -> Result<i64> {
        Ok(*self.0.lock().unwrap().get(name).unwrap_or(&0))
    }
}

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
        limiter,
        locks,
        // No database in this harness: the sink accepts and discards, which is exactly what the
        // disabled configuration does in production. What is under test is the framing.
        RequestLogSink::disabled(),
        Arc::new(SequenceAllocator::new(
            Arc::new(MemorySequenceStore::default()),
            2,
            SequenceLimits {
                block_size: 8,
                max_tracked_names: 64,
            },
        )),
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

    /// Writes any frame whose body (everything between the opcode and the tag) is already built.
    async fn write_frame(&mut self, opcode: u8, body: &[u8]) {
        let mut frame = vec![opcode];
        frame.extend_from_slice(body);
        let mut hasher = SipHasher24::new(&derive_key(SECRET));
        hasher.write(b"fareward:v9");
        hasher.write(&self.nonce);
        hasher.write(&self.sequence.to_be_bytes());
        hasher.write(&frame);
        frame.extend_from_slice(&hasher.finish().to_be_bytes());
        self.sequence += 1;
        self.socket.write_all(&frame).await.unwrap();
    }

    /// A request log frame: the two-byte length header followed by the payload.
    async fn write_request_log(&mut self, payload: &[u8]) {
        let mut body = (payload.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(payload);
        self.write_frame(OPCODE_LOG_REQUEST, &body).await;
    }

    /// A frame whose declared length disagrees with what follows it.
    async fn write_request_log_declaring(&mut self, declared: u16, payload: &[u8]) {
        let mut body = declared.to_be_bytes().to_vec();
        body.extend_from_slice(payload);
        self.write_frame(OPCODE_LOG_REQUEST, &body).await;
    }

    /// A reservation frame: the same length header, then the increment and the counter name.
    async fn write_reserve_sequence(&mut self, name: &str, increment: u32) {
        let mut payload = increment.to_be_bytes().to_vec();
        payload.extend_from_slice(name.as_bytes());
        self.write_length_prefixed(OPCODE_RESERVE_SEQUENCE, &payload)
            .await;
    }

    /// A set frame: the same shape, with an absolute i64 where the increment was.
    async fn write_set_sequence(&mut self, name: &str, value: i64) {
        let mut payload = value.to_be_bytes().to_vec();
        payload.extend_from_slice(name.as_bytes());
        self.write_length_prefixed(OPCODE_SET_SEQUENCE, &payload)
            .await;
    }

    async fn write_length_prefixed(&mut self, opcode: u8, payload: &[u8]) {
        let mut body = (payload.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(payload);
        self.write_frame(opcode, &body).await;
    }

    /// The head is six bytes, the sixth being the tail's length. Reading five and leaving that byte
    /// in the stream would desynchronize every reply after it.
    async fn read_reply(&mut self) -> (u16, u8, u16, Vec<u8>) {
        let mut reply = [0_u8; 6];
        self.socket.read_exact(&mut reply).await.unwrap();
        let mut extra = vec![0_u8; usize::from(reply[5])];
        if !extra.is_empty() {
            self.socket.read_exact(&mut extra).await.unwrap();
        }
        (
            u16::from_be_bytes([reply[0], reply[1]]),
            reply[2],
            u16::from_be_bytes([reply[3], reply[4]]),
            extra,
        )
    }

    /// Authorization slots left empty: this test is about frame sequencing, not about grants.
    fn charge_payload() -> Vec<u8> {
        let mut payload = Vec::with_capacity(CHARGE_PAYLOAD_SIZE);
        payload.extend_from_slice(&[0, 0, 1]);
        payload.extend_from_slice(&[0, 0, 1]);
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.resize(CHARGE_PAYLOAD_SIZE, 0);
        payload
    }
}

/// A well-formed record with one error, matching what the Go client writes.
fn request_log_payload(error_count: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&20_500_i16.to_be_bytes());
    payload.extend_from_slice(&1_767_225_600_123_i64.to_be_bytes());
    payload.extend_from_slice(&102_i16.to_be_bytes());
    payload.push(41);
    payload.extend_from_slice(&[0, 0, 7]);
    payload.extend_from_slice(&42_i32.to_be_bytes());
    payload.extend_from_slice(&318_i16.to_be_bytes());
    payload.push(error_count);
    for index in 0..error_count {
        payload.extend_from_slice(&(1_000 + index as i32).to_be_bytes());
        let code_line = format!("responses.go:{}", 500 + index as u32);
        payload.push(code_line.len() as u8);
        payload.extend_from_slice(code_line.as_bytes());
        let text = "no se pudo obtener el registro";
        payload.extend_from_slice(&(text.len() as u16).to_be_bytes());
        payload.extend_from_slice(text.as_bytes());
    }
    payload
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
        .write_frame(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, status, _, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the charge behind a request log was never answered");
    // Sequence 0 was the log frame, so the charge is sequence 1 — and the only reply.
    assert_eq!(correlation, 1);
    assert_eq!(status, 0);
}

#[tokio::test]
async fn a_request_log_with_no_errors_is_accepted() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client.write_request_log(&request_log_payload(0)).await;
    client
        .write_frame(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, status, _, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the connection stalled after an error-free request log");
    assert_eq!((correlation, status), (1, 0));
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
        .write_frame(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, status, _, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the connection died on a malformed request log");
    assert_eq!((correlation, status), (1, 0));
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
        .write_frame(OPCODE_CHARGE, &Client::charge_payload())
        .await;

    let (correlation, status, _, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the stream desynchronized across consecutive request logs");
    assert_eq!((correlation, status), (4, 0));
}

/// The reservation opcode is the first that is both length-prefixed and answered, so it is the only
/// place where a variable-width request and an eight-byte reply tail meet on the same connection.
#[tokio::test]
async fn a_reservation_answers_with_the_first_value_in_the_tail() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client.write_reserve_sequence("x1_ventas_0", 3).await;
    let (correlation, status, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the daemon did not answer a reservation");
    assert_eq!((correlation, status), (0, 0));
    assert_eq!(extra.len(), 8, "the reserved value must fill the tail");
    assert_eq!(i64::from_be_bytes(extra.try_into().unwrap()), 1);

    // The three values just reserved are gone, so the next caller starts past them.
    client.write_reserve_sequence("x1_ventas_0", 1).await;
    let (_, _, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the stream desynchronized after a reply with a tail");
    assert_eq!(i64::from_be_bytes(extra.try_into().unwrap()), 4);
}

/// A reservation that cannot be parsed is answered rather than discarded: unlike a request log,
/// somebody is parked waiting for a value, and silence would hang them until their own timeout.
#[tokio::test]
async fn a_malformed_reservation_is_refused_without_closing_the_connection() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    // A zero increment reserves nothing and still would have to answer with some value.
    client.write_reserve_sequence("x1_ventas_0", 0).await;
    let (correlation, status, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the daemon did not answer a malformed reservation");
    assert_eq!(correlation, 0);
    assert_ne!(status, 0, "a malformed reservation must not report success");
    assert!(extra.is_empty());

    // The connection is still usable, so a bad frame costs one request and not the socket.
    client.write_reserve_sequence("x1_ventas_0", 1).await;
    let (correlation, status, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("a refused reservation took the connection with it");
    assert_eq!((correlation, status), (1, 0));
    assert_eq!(i64::from_be_bytes(extra.try_into().unwrap()), 1);
}

/// The reason `0x08` exists rather than the caller writing the row itself: over a live connection
/// the daemon is holding a block derived from the old value, and moving the counter under it has to
/// drop that block or the next reservation hands out values this one already issued.
#[tokio::test]
async fn a_set_moves_the_counter_and_abandons_the_live_block() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    // block_size is 8 in this harness, so one reservation leaves a live block with room to spare.
    client.write_reserve_sequence("x1_ventas_0", 2).await;
    let (_, status, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the daemon did not answer a reservation");
    assert_eq!(status, 0);
    assert_eq!(i64::from_be_bytes(extra.try_into().unwrap()), 1);

    // A restore finds the partition really only holds rows up to id 4.
    client.write_set_sequence("x1_ventas_0", 4).await;
    let (correlation, status, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the daemon did not answer a set");
    assert_eq!((correlation, status), (1, 0));
    // The reply reports what was replaced — the whole block, not the two values handed out.
    assert_eq!(i64::from_be_bytes(extra.try_into().unwrap()), 8);

    // Re-derived from 4 instead of continuing the abandoned block at 3.
    client.write_reserve_sequence("x1_ventas_0", 1).await;
    let (_, _, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the daemon did not answer the reservation after a set");
    assert_eq!(i64::from_be_bytes(extra.try_into().unwrap()), 5);
}

/// A negative counter would hand out non-positive primary keys, so it is refused like any other
/// malformed payload — with a status, not by dropping the connection.
#[tokio::test]
async fn a_set_to_a_negative_value_is_refused() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client.write_set_sequence("x1_ventas_0", -5).await;
    let (correlation, status, _, extra) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the daemon did not answer a negative set");
    assert_eq!(correlation, 0);
    assert_ne!(status, 0);
    assert!(extra.is_empty());
}

/// The name ceiling bounds what an unauthenticated peer can make the daemon buffer, exactly as the
/// request log's does.
#[tokio::test]
async fn an_oversized_counter_name_closes_the_connection() {
    let server = start_server().await;
    let mut client = Client::connect(&server).await;

    client
        .write_reserve_sequence(&"n".repeat(SEQUENCE_NAME_MAX + 1), 1)
        .await;

    let mut reply = [0_u8; 6];
    let outcome = timeout(Duration::from_secs(2), client.socket.read_exact(&mut reply)).await;
    let read = outcome.expect("the daemon neither answered nor closed the connection");
    assert!(
        read.is_err(),
        "an oversized counter name was tolerated instead of ending the connection"
    );
}
