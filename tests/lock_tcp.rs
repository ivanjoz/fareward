//! End-to-end lock behavior over a real socket.
//!
//! The registry's own tests cover the queueing rules in isolation. What can only be checked
//! here is the part that makes the design safe: ownership is bound to the TCP connection, so a
//! client that disconnects or goes silent loses its lock without any sweeper running.

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
        budget::BudgetMutationFrame,
        protocol::ChargeFrame,
        quota::{CreditLimits, LimitPolicy, RateLimiter, ScopeLimits},
        storage::{
            LimiterStore, StoredBudget, StoredBudgetRow, StoredBudgetUsage, StoredUsage,
            StoredUserAccess,
        },
        time_frame,
    },
    lock::{
        protocol::{AcquireRequest, ReleaseRequest},
        registry::{LockLimits, LockRegistry},
    },
    reqlog::writer::RequestLogSink,
    sequence::{
        allocator::{SequenceAllocator, SequenceLimits},
        store::SequenceStore,
    },
    service::{auth::DOMAIN, protocol::ReplyShape, server},
    siphash::{SipHasher24, derive_key},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

const SECRET: &[u8] = b"lock-test-secret";
const ACTION: u16 = 7;

/// Neither the limiter nor the sequence allocator is under test here, but `server::run` needs
/// both, and neither may touch a database.
#[derive(Default)]
struct EmptyStore;

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
    async fn load_range(&self, _c: i32, _u: i32, _s: i32, _e: i32) -> Result<Vec<StoredUsage>> {
        Ok(Vec::new())
    }
    async fn upsert(&self, _key: UsageKey, _used: Vec<u8>) -> Result<()> {
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

async fn start_server(frame_timeout: Duration) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let limits = CreditLimits {
        ten_seconds: 1_000,
        hour: 10_000,
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
        // These tests drive locks and charges; request logs would be written to a database this
        // harness does not have, so the sink accepts and discards.
        RequestLogSink::disabled(),
        Arc::new(SequenceAllocator::new(
            Arc::new(MemorySequenceStore::default()),
            2,
            SequenceLimits {
                block_size: 64,
                max_tracked_names: 64,
            },
        )),
        Arc::new(SECRET.to_vec()),
        frame_timeout,
        64,
        16,
        shutdown_receiver,
    ));
    TestServer {
        address,
        _shutdown: shutdown_sender,
    }
}

/// One client connection, which is also one lock slot.
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

    /// Writes a frame without waiting for its reply, and returns the correlation to expect.
    ///
    /// Every opcode states its own payload length — there is no second, fixed-width framing any
    /// more — and the tag covers the length header, so a peer cannot make the daemon buffer a
    /// different amount than the one it signed.
    async fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> u16 {
        let mut frame = vec![opcode];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        let mut hasher = SipHasher24::new(&derive_key(SECRET));
        hasher.write(DOMAIN);
        hasher.write(&self.nonce);
        hasher.write(&self.sequence.to_be_bytes());
        hasher.write(&frame);
        frame.extend_from_slice(&hasher.finish().to_be_bytes());
        let correlation = self.sequence as u16;
        self.sequence += 1;
        self.socket.write_all(&frame).await.unwrap();
        correlation
    }

    /// Returns `(correlation, shape, body)` of the next reply, skipping any push that arrives in
    /// between.
    ///
    /// A push has no correlation and can land at any moment — a lease this suite deliberately lets
    /// expire sends one — so a reader that did not step over it would hand the next test its
    /// neighbour's frame. `read_push` is what asserts they arrive; this is what keeps the
    /// request/reply tests from tripping over them.
    ///
    /// The body is always consumed. Leaving one in the socket would desynchronize every reply
    /// after it, which is exactly the failure the per-shape width exists to make impossible.
    async fn read_reply(&mut self) -> (u16, ReplyShape, Vec<u8>) {
        loop {
            let (correlation, shape, body) = self.read_frame().await;
            if !shape.is_push() {
                return (correlation, shape, body);
            }
        }
    }

    /// Reads exactly one frame, push or not.
    async fn read_frame(&mut self) -> (u16, ReplyShape, Vec<u8>) {
        let mut head = [0_u8; 3];
        self.socket.read_exact(&mut head).await.unwrap();
        let shape = ReplyShape::from_byte(head[0]).expect("a shape this daemon writes");
        let correlation = u16::from_be_bytes([head[1], head[2]]);
        // A push says how long it is, so an unknown one could be stepped over. A reply's width
        // comes from its shape, except for the one that counts its own sub bytes.
        let mut body = if shape.is_push() {
            let mut length = [0_u8; 1];
            self.socket.read_exact(&mut length).await.unwrap();
            vec![0_u8; usize::from(length[0])]
        } else {
            match shape.body_size() {
                Some(width) => vec![0_u8; width],
                None => vec![0_u8; 3],
            }
        };
        self.socket.read_exact(&mut body).await.unwrap();
        if !shape.is_push() && shape.body_size().is_none() {
            let mut sub_bytes = vec![0_u8; usize::from(body[2])];
            self.socket.read_exact(&mut sub_bytes).await.unwrap();
            body.extend_from_slice(&sub_bytes);
        }
        (correlation, shape, body)
    }

    /// Reads the next frame and requires it to be a push.
    async fn read_push(&mut self) -> (ReplyShape, Vec<u8>) {
        let (correlation, shape, body) = self.read_frame().await;
        assert!(
            shape.is_push(),
            "expected a push, got {shape:?} correlated to {correlation}"
        );
        (shape, body)
    }

    async fn send(&mut self, opcode: u8, payload: &[u8]) -> u8 {
        let expected = self.write_frame(opcode, payload).await;
        let (correlation, shape, body) = self.read_reply().await;
        assert_eq!(
            correlation, expected,
            "reply correlated to the wrong request"
        );
        outcome_code(shape, &body)
    }

    /// A minimal, always-admissible charge: company 1 / user 1 on route 1, with the four
    /// authorization slots left empty so nothing is asked of the (empty) access store.
    ///
    /// Built through the same struct the daemon decodes rather than by hand. A payload assembled
    /// here would only prove this file and the parser agree, and the Go client — the one peer that
    /// matters — is pinned separately by the vectors in service/auth.rs.
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

    fn budget_payload(operation: u8, cpu: u64, inference: u64) -> Vec<u8> {
        BudgetMutationFrame {
            company_id: 1,
            operation,
            cpu,
            inference,
        }
        .encode()
    }

    fn acquire_payload(identifier: i64, max_waiters: u8, wait_ms: u32, lease_ms: u32) -> Vec<u8> {
        AcquireRequest {
            action: ACTION,
            identifier,
            max_waiters,
            wait_ms,
            lease_ms,
        }
        .encode()
    }

    fn release_payload(identifier: i64, generation: u16) -> Vec<u8> {
        ReleaseRequest {
            action: ACTION,
            identifier,
            generation,
        }
        .encode()
    }

    /// Returns the status only; use `acquire_granting` when the generation is needed.
    async fn acquire(
        &mut self,
        identifier: i64,
        max_waiters: u8,
        wait_ms: u32,
        lease_ms: u32,
    ) -> u8 {
        self.acquire_granting(identifier, max_waiters, wait_ms, lease_ms)
            .await
            .0
    }

    /// Returns `(outcome, generation)`. The generation is what a later release must present, and
    /// it now rides in the `LockGranted` body rather than in a field a refusal also uses.
    async fn acquire_granting(
        &mut self,
        identifier: i64,
        max_waiters: u8,
        wait_ms: u32,
        lease_ms: u32,
    ) -> (u8, u16) {
        let payload = Self::acquire_payload(identifier, max_waiters, wait_ms, lease_ms);
        let expected = self.write_frame(0x02, &payload).await;
        let (correlation, shape, body) = self.read_reply().await;
        assert_eq!(
            correlation, expected,
            "reply correlated to the wrong request"
        );
        let generation = match shape {
            ReplyShape::LockGranted => u16::from_be_bytes([body[0], body[1]]),
            _ => 0,
        };
        (outcome_code(shape, &body), generation)
    }

    async fn release(&mut self, identifier: i64, generation: u16) -> u8 {
        let payload = Self::release_payload(identifier, generation);
        self.send(0x03, &payload).await
    }
}

/// The outcome code this suite asserts on, derived from the reply's shape.
///
/// Every assertion here is about lock *behaviour* — busy, misuse, hand-over — rather than about
/// byte layout, and the codes are the same ones the daemon still sends inside a `LockRefused`. So
/// the shape byte is resolved in exactly one place instead of restated fifty times, and the framing
/// itself is pinned by `every_reply_names_its_own_shape` and `an_expired_lease_pushes_lock_lost`
/// below, which assert on shapes directly.
fn outcome_code(shape: ReplyShape, body: &[u8]) -> u8 {
    match shape {
        // Success, whatever the operation was.
        ReplyShape::Ack | ReplyShape::ChargeAllowed | ReplyShape::ChargeGranted => 0,
        ReplyShape::LockGranted => 0,
        ReplyShape::SequenceValue => 0,
        // A refusal carries its reason as its whole body.
        ReplyShape::LockRefused
        | ReplyShape::BudgetRefused
        | ReplyShape::ChargeCreditViolation
        | ReplyShape::ChargeAccessDenied => body[0],
        ReplyShape::SequenceInvalid => 1,
        // What 0xFF used to mean when it was a status rather than a shape.
        ReplyShape::Unavailable => 0xFF,
        ReplyShape::LockLost => panic!("a push is not an outcome"),
    }
}

#[tokio::test]
async fn budget_mutations_and_charges_share_the_authenticated_connection() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut client = Client::connect(&server).await;

    assert_eq!(
        client
            .send(0x05, &Client::budget_payload(1, 100, 100))
            .await,
        0
    );
    assert_eq!(
        client
            .send(0x05, &Client::budget_payload(2, 100, 100))
            .await,
        0
    );
    assert_eq!(client.send(0x01, &Client::charge_payload()).await, 0);
}

/// Phase 4: the holder is *told* its lease elapsed, rather than inferring it from a timer it
/// started a round trip after the daemon did.
///
/// Before the push existed there was nothing on this socket at all — the daemon dropped the hold,
/// logged it, and the client went on believing it owned the key until its own timer fired.
#[tokio::test]
async fn an_expired_lease_pushes_lock_lost() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    let (outcome, _) = holder.acquire_granting(300, 0, 0, 150).await;
    assert_eq!(outcome, 0);

    // Nothing is sent and nothing is asked for: the next frame on this socket is the daemon's own.
    let (shape, body) = timeout(Duration::from_secs(2), holder.read_push())
        .await
        .expect("an elapsed lease must announce itself");
    assert_eq!(shape, ReplyShape::LockLost);
    assert_eq!(u16::from_be_bytes([body[0], body[1]]), ACTION, "action");
    assert_eq!(
        i64::from_be_bytes([
            body[2], body[3], body[4], body[5], body[6], body[7], body[8], body[9]
        ]),
        300,
        "identifier"
    );
}

/// Every outcome this port can produce, named by its shape rather than decoded out of a status
/// byte whose meaning depended on the request it answered.
#[tokio::test]
async fn every_reply_names_its_own_shape() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut client = Client::connect(&server).await;

    // A charge that asks for no authorization.
    let expected = client.write_frame(0x01, &Client::charge_payload()).await;
    let (correlation, shape, body) = client.read_reply().await;
    assert_eq!(correlation, expected);
    assert_eq!(shape, ReplyShape::ChargeAllowed);
    assert!(body.is_empty(), "an allowed charge says nothing more");

    // A budget mutation that lands.
    client
        .write_frame(0x05, &Client::budget_payload(1, 100, 100))
        .await;
    let (_, shape, body) = client.read_reply().await;
    assert_eq!(shape, ReplyShape::Ack);
    assert!(body.is_empty());

    // A granted lock, and the generation in its own body.
    let payload = Client::acquire_payload(400, 0, 0, 15000);
    client.write_frame(0x02, &payload).await;
    let (_, shape, body) = client.read_reply().await;
    assert_eq!(shape, ReplyShape::LockGranted);
    assert_eq!(body.len(), 2);
    let generation = u16::from_be_bytes([body[0], body[1]]);

    // A refusal, from a second connection that cannot have the same key.
    let mut rival = Client::connect(&server).await;
    rival.write_frame(0x02, &Client::acquire_payload(400, 0, 0, 15000)).await;
    let (_, shape, body) = rival.read_reply().await;
    assert_eq!(shape, ReplyShape::LockRefused);
    assert_eq!(body, vec![1], "busy");

    // A release, acknowledged.
    client
        .write_frame(0x03, &Client::release_payload(400, generation))
        .await;
    let (_, shape, _) = client.read_reply().await;
    assert_eq!(shape, ReplyShape::Ack);

    // A release of something this connection does not hold: refused, not acknowledged.
    client
        .write_frame(0x03, &Client::release_payload(999, generation))
        .await;
    let (_, shape, body) = client.read_reply().await;
    assert_eq!(shape, ReplyShape::LockRefused);
    assert_eq!(body, vec![4], "misuse");

    // A reserved counter value, in a body of its own rather than a tail.
    let mut reserve = 7_u32.to_be_bytes().to_vec();
    reserve.extend_from_slice(b"x1_tests_0");
    client.write_frame(0x07, &reserve).await;
    let (_, shape, body) = client.read_reply().await;
    assert_eq!(shape, ReplyShape::SequenceValue);
    assert_eq!(body.len(), 8);

    // And a malformed one, which no retry fixes.
    client
        .write_frame(0x07, &0_u32.to_be_bytes())
        .await;
    let (_, shape, body) = client.read_reply().await;
    assert_eq!(shape, ReplyShape::SequenceInvalid);
    assert!(body.is_empty());
}

#[tokio::test]
async fn the_second_client_waits_for_an_explicit_release() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    let (status, generation) = holder.acquire_granting(1, 4, 2000, 15000).await;
    assert_eq!(status, 0);

    let address = server.address.clone();
    let waiter = tokio::spawn(async move {
        let mut socket = TcpStream::connect(&address).await.unwrap();
        let mut nonce = [0_u8; 8];
        socket.read_exact(&mut nonce).await.unwrap();
        let mut client = Client {
            socket,
            nonce,
            sequence: 0,
        };
        client.acquire(1, 4, 2000, 15000).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !waiter.is_finished(),
        "the second client must still be queued"
    );
    assert_eq!(holder.release(1, generation).await, 0);
    assert_eq!(waiter.await.unwrap(), 0, "release must hand the lock over");
}

#[tokio::test]
async fn a_dropped_connection_releases_the_lock() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    assert_eq!(holder.acquire(2, 0, 0, 15000).await, 0);

    // A try-lock proves the key is really held: zero waiters, zero patience.
    let mut rival = Client::connect(&server).await;
    assert_eq!(rival.acquire(2, 0, 0, 15000).await, 1);

    // No release frame, no graceful close — exactly what a killed Lambda leaves behind.
    drop(holder);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        rival.acquire(2, 0, 0, 15000).await,
        0,
        "dropping the holder's connection must free the key"
    );
}

#[tokio::test]
async fn a_silent_holder_loses_the_lock_when_its_lease_expires() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    // A 150 ms lease with a 30 s idle timeout: only the lease can end this hold, which is what
    // proves the deadline swapped when the lock was granted.
    assert_eq!(holder.acquire(3, 0, 0, 150).await, 0);

    let mut rival = Client::connect(&server).await;
    assert_eq!(rival.acquire(3, 0, 0, 15000).await, 1);

    // The holder simply says nothing; its connection is still open.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        rival.acquire(3, 0, 0, 15000).await,
        0,
        "the lease must expire the hold without any release frame"
    );
}

#[tokio::test]
async fn a_queue_that_is_full_is_refused_immediately() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    assert_eq!(holder.acquire(4, 1, 5000, 15000).await, 0);

    let address = server.address.clone();
    let queued = tokio::spawn(async move {
        let mut socket = TcpStream::connect(&address).await.unwrap();
        let mut nonce = [0_u8; 8];
        socket.read_exact(&mut nonce).await.unwrap();
        let mut client = Client {
            socket,
            nonce,
            sequence: 0,
        };
        client.acquire(4, 1, 5000, 15000).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut refused = Client::connect(&server).await;
    // One waiter is already parked, so this one is answered rather than queued — and answered
    // fast, which is the whole point of the ceiling.
    let reply = timeout(
        Duration::from_millis(500),
        refused.acquire(4, 1, 5000, 15000),
    )
    .await
    .expect("a refused acquire must not block");
    assert_eq!(reply, 1);
    queued.abort();
}

#[tokio::test]
async fn waiting_past_the_client_patience_reports_a_timeout() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    assert_eq!(holder.acquire(5, 4, 0, 15000).await, 0);

    let mut waiter = Client::connect(&server).await;
    assert_eq!(waiter.acquire(5, 4, 100, 15000).await, 2);
}

#[tokio::test]
async fn one_connection_can_hold_several_locks() {
    // What the widened release frame buys: a single shared connection is no longer a single lock,
    // so one process can serialize several keys at once.
    let server = start_server(Duration::from_secs(30)).await;
    let mut client = Client::connect(&server).await;
    let (first_status, first_generation) = client.acquire_granting(6, 4, 1000, 15000).await;
    let (second_status, second_generation) = client.acquire_granting(7, 4, 1000, 15000).await;
    assert_eq!(first_status, 0);
    assert_eq!(
        second_status, 0,
        "a second key on one connection must be allowed"
    );

    // Both are really held: a rival cannot take either.
    let mut rival = Client::connect(&server).await;
    assert_eq!(rival.acquire(6, 0, 0, 15000).await, 1);
    assert_eq!(rival.acquire(7, 0, 0, 15000).await, 1);

    // Releasing one must not disturb the other.
    assert_eq!(client.release(6, first_generation).await, 0);
    assert_eq!(rival.acquire(6, 0, 0, 15000).await, 0);
    assert_eq!(
        rival.acquire(7, 0, 0, 15000).await,
        1,
        "the other key is still held"
    );
    assert_eq!(client.release(7, second_generation).await, 0);
}

#[tokio::test]
async fn a_release_must_name_a_lock_this_connection_actually_holds() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut client = Client::connect(&server).await;
    let (status, generation) = client.acquire_granting(8, 4, 1000, 15000).await;
    assert_eq!(status, 0);

    // Right key, wrong generation: this is the shape of a release from a caller that already
    // gave up, arriving after someone else took the key.
    assert_eq!(
        client.release(8, generation.wrapping_add(1)).await,
        4,
        "a superseded generation must not end the current hold"
    );
    // A key this connection never held.
    assert_eq!(client.release(999, generation).await, 4);
    // The real one still works, proving the refusals above left it alone.
    assert_eq!(client.release(8, generation).await, 0);
    // And releasing it twice is a client bug.
    assert_eq!(client.release(8, generation).await, 4);
}

#[tokio::test]
async fn a_stale_release_cannot_end_the_hold_that_replaced_it() {
    // The race the generation exists for: two callers sharing one connection, the first giving up
    // while its release is already in flight.
    let server = start_server(Duration::from_secs(30)).await;
    let mut client = Client::connect(&server).await;
    let (_, first_generation) = client.acquire_granting(9, 4, 1000, 15000).await;
    assert_eq!(client.release(9, first_generation).await, 0);

    // Same key, taken again on the same connection: a different hold, so a different generation.
    let (_, second_generation) = client.acquire_granting(9, 4, 1000, 15000).await;
    assert_ne!(
        first_generation, second_generation,
        "each grant of a key must be distinguishable"
    );

    // The stale release from the first hold must not free the second.
    assert_eq!(client.release(9, first_generation).await, 4);
    let mut rival = Client::connect(&server).await;
    assert_eq!(
        rival.acquire(9, 0, 0, 15000).await,
        1,
        "the second hold must have survived the stale release"
    );
}

#[tokio::test]
async fn different_identifiers_do_not_block_each_other() {
    let server = start_server(Duration::from_secs(30)).await;
    let mut first = Client::connect(&server).await;
    let mut second = Client::connect(&server).await;
    assert_eq!(first.acquire(100, 0, 0, 15000).await, 0);
    assert_eq!(second.acquire(200, 0, 0, 15000).await, 0);
}

#[tokio::test]
async fn a_queued_acquire_does_not_delay_a_later_charge() {
    // The whole point of multiplexing, and false before it: a request parked in a lock queue must
    // not hold up unrelated work sent after it on the same connection.
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    let (status, generation) = holder.acquire_granting(50, 4, 3000, 15000).await;
    assert_eq!(status, 0);

    let mut client = Client::connect(&server).await;
    // This one will sit in the queue for up to 3s behind the holder above.
    let acquire_id = client
        .write_frame(0x02, &Client::acquire_payload(50, 4, 3000, 15000))
        .await;
    let charge_id = client.write_frame(0x01, &Client::charge_payload()).await;

    // The charge must come back first, while the acquire is still waiting.
    let (first, shape, _) = timeout(Duration::from_millis(500), client.read_reply())
        .await
        .expect("the charge must be answered without waiting for the queued acquire");
    assert_eq!(
        first, charge_id,
        "replies did not overtake the parked acquire"
    );
    assert_eq!(
        shape,
        ReplyShape::ChargeAllowed,
        "the charge should have been admitted"
    );

    // And the acquire still gets its own answer once the holder releases.
    assert_eq!(holder.release(50, generation).await, 0);
    let (second, shape, _) = timeout(Duration::from_secs(2), client.read_reply())
        .await
        .expect("the queued acquire must still be answered");
    assert_eq!(second, acquire_id);
    assert_eq!(shape, ReplyShape::LockGranted);
}

#[tokio::test]
async fn a_lease_expires_even_while_the_connection_stays_busy() {
    // The case the old relative read deadline silently failed: traffic on the connection used to
    // push the lease forward, so a wedged holder kept its lock forever.
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    assert_eq!(holder.acquire(60, 0, 0, 200).await, 0);

    let mut rival = Client::connect(&server).await;
    assert_eq!(
        rival.acquire(60, 0, 0, 15000).await,
        1,
        "the key must be held"
    );

    // Keep the holder's connection busy across its own lease.
    for _ in 0..6 {
        assert_eq!(holder.send(0x01, &Client::charge_payload()).await, 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        rival.acquire(60, 0, 0, 15000).await,
        0,
        "traffic on the holder's connection must not extend its lease"
    );
    // Expiry must not have killed the holder's connection, only its lock.
    assert_eq!(
        holder.send(0x01, &Client::charge_payload()).await,
        0,
        "lease expiry must leave the connection usable"
    );
}

#[tokio::test]
async fn disconnecting_with_a_queued_acquire_does_not_strand_the_lock() {
    // A client that walks away while queued must not be handed the lock afterwards: nobody would
    // ever release it, and it would sit locked until its lease ran out.
    let server = start_server(Duration::from_secs(30)).await;
    let mut holder = Client::connect(&server).await;
    let (status, generation) = holder.acquire_granting(70, 4, 5000, 15000).await;
    assert_eq!(status, 0);

    let mut leaver = Client::connect(&server).await;
    leaver
        .write_frame(0x02, &Client::acquire_payload(70, 4, 5000, 15000))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(leaver);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(holder.release(70, generation).await, 0);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut newcomer = Client::connect(&server).await;
    assert_eq!(
        newcomer.acquire(70, 0, 0, 15000).await,
        0,
        "the abandoned queued acquire must not have taken the lock"
    );
}
