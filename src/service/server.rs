//! Raw TCP listener (plus an optional Unix domain socket), connection handshake, opcode dispatch,
//! and graceful stop coordination.
//!
//! Each connection is a **single state owner**: the reader task is the only thing that touches
//! the locks this connection holds. Handlers run as spawned tasks so a queued acquire cannot
//! delay anything behind it, but they never mutate that state — they report results back over a
//! channel. That is what removes the three-way race between release, lease expiry, and
//! disconnect: there is only ever one writer.

use std::{
    collections::HashMap,
    fs,
    io::{self, ErrorKind},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{
    limiter::{
        access::AccessVerdict,
        budget::{BudgetMutationReply, parse_budget_mutation},
        protocol::parse_charge,
        quota::{Decision, RateLimiter},
    },
    lock::{
        protocol::{LockReply, parse_acquire, parse_release},
        registry::{LockGuard, LockOutcome, LockRegistry},
    },
    service::{
        auth,
        protocol::{AUTH_TAG_SIZE, LENGTH_PREFIX_SIZE, MAX_FRAME_SIZE, OPCODE_SIZE, Opcode, Reply},
    },
    store::{grants::parse_grants, query::parse_report_query},
};

type LockKey = (u16, i64);

/// One lock this connection holds. The guard is what actually owns it; dropping this entry —
/// on release, on expiry, or when the connection ends — is the only way it is freed.
struct HeldLock {
    /// Held purely for its `Drop`: while this value exists the lock is ours, and removing the
    /// entry is what frees it. Never read, hence the underscore.
    _guard: LockGuard,
    /// Identifies this grant specifically, so a release from a caller that already gave up
    /// cannot end the hold that replaced it on the same key.
    generation: u16,
    expires_at: Instant,
}

/// What a spawned acquire reports back. `None` means it was refused or timed out, which the
/// reader still needs so it can drop its pending count.
struct AcquireOutcome {
    key: LockKey,
    granted: Option<HeldLock>,
}

/// One accepted connection from either listener. Both carry the identical protocol; the only
/// difference is that TCP needs Nagle turned off and has a peer address worth logging.
enum AcceptedSocket {
    Tcp(TcpStream),
    Unix(UnixStream),
}

/// Binds the Unix domain socket a backend on this same host dials instead of loopback TCP.
///
/// A socket file left by a crashed run would make bind fail with EADDRINUSE, so it is removed
/// first — but only when it IS a socket, never a regular file someone pointed the setting at.
/// 0660 keeps it to the daemon's user and group, which is the backend's under configure_fareward.
pub fn bind_unix_socket(socket_path: &Path) -> Result<UnixListener> {
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket() {
            return Err(anyhow!(
                "fareward.unix_socket {} exists and is not a socket",
                socket_path.display()
            ));
        }
        fs::remove_file(socket_path)
            .with_context(|| format!("failed to remove stale socket {}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("failed to set permissions on {}", socket_path.display()))?;
    Ok(listener)
}

/// Parks forever when no Unix socket is configured, so its `select!` branch simply never fires.
async fn accept_unix(listener: Option<&UnixListener>) -> io::Result<UnixStream> {
    match listener {
        Some(listener) => listener.accept().await.map(|(socket, _)| socket),
        None => std::future::pending().await,
    }
}

pub async fn run(
    listener: TcpListener,
    unix_listener: Option<UnixListener>,
    limiter: Arc<RateLimiter>,
    locks: Arc<LockRegistry>,
    secret: Arc<Vec<u8>>,
    frame_timeout: Duration,
    max_connections: usize,
    max_inflight: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let connection_slots = Arc::new(Semaphore::new(max_connections));
    let mut connections = JoinSet::new();
    info!(address = %listener.local_addr()?, max_connections, max_inflight, "fareward listening");
    if let Some(unix_listener) = &unix_listener {
        info!(socket = ?unix_listener.local_addr()?, "fareward listening on unix socket");
    }

    loop {
        // Both listeners feed the same connection budget and the same handler below.
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted.map(|(socket, _)| AcceptedSocket::Tcp(socket)),
            accepted = accept_unix(unix_listener.as_ref()) => accepted.map(AcceptedSocket::Unix),
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(join_error)) = completed {
                    warn!(error = %join_error, "connection task failed");
                }
                continue;
            }
        };

        // Transient accept failures (EMFILE when the fd limit is reached, a peer that vanished
        // between the SYN and the accept) must not take the whole listener down: propagating here
        // would silently stop serving every future connection.
        let socket = match accepted {
            Ok(socket) => socket,
            Err(accept_error) => {
                warn!(error = %accept_error, "accept failed, continuing to listen");
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let peer = match &socket {
            AcceptedSocket::Tcp(stream) => stream
                .peer_addr()
                .map_or_else(|_| "tcp".to_owned(), |address| address.to_string()),
            AcceptedSocket::Unix(_) => "unix".to_owned(),
        };
        let Ok(slot) = connection_slots.clone().try_acquire_owned() else {
            warn!(%peer, "rejecting connection because the connection limit is full");
            drop(socket);
            continue;
        };
        let limiter = limiter.clone();
        let locks = locks.clone();
        let secret = secret.clone();
        let connection_shutdown = shutdown.clone();
        // Split here rather than inside handle_connection: `into_split` gives lock-free owned
        // halves for both stream types, which `tokio::io::split` on a generic stream would not.
        let (reader, writer): (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ) = match socket {
            AcceptedSocket::Tcp(stream) => {
                stream
                    .set_nodelay(true)
                    .context("failed to set TCP_NODELAY")?;
                let (reader, writer) = stream.into_split();
                (Box::new(reader), Box::new(writer))
            }
            AcceptedSocket::Unix(stream) => {
                let (reader, writer) = stream.into_split();
                (Box::new(reader), Box::new(writer))
            }
        };
        connections.spawn(async move {
            let _slot = slot;
            if let Err(connection_error) = handle_connection(
                reader,
                writer,
                &peer,
                limiter,
                locks,
                &secret,
                frame_timeout,
                max_inflight,
                connection_shutdown,
            )
            .await
            {
                debug!(%peer, error = %connection_error, "connection closed with error");
            }
        });
    }

    // Connection tasks observe the same shutdown channel and drop their sockets promptly.
    while let Some(result) = connections.join_next().await {
        if let Err(join_error) = result {
            warn!(error = %join_error, "connection task failed during shutdown");
        }
    }
    Ok(())
}

async fn handle_connection(
    mut reader: Box<dyn AsyncRead + Send + Unpin>,
    mut writer: Box<dyn AsyncWrite + Send + Unpin>,
    peer: &str,
    limiter: Arc<RateLimiter>,
    locks: Arc<LockRegistry>,
    secret: &[u8],
    frame_timeout: Duration,
    max_inflight: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let nonce = auth::new_nonce()?;
    writer
        .write_all(&nonce)
        .await
        .context("failed to write connection nonce")?;
    debug!(%peer, "connection nonce sent");

    // Bounded on purpose. One request per socket used to provide backpressure for free;
    // multiplexing removes it, so replies and in-flight work each need an explicit ceiling or one
    // authenticated client could spawn tasks and buffer replies without limit.
    let (reply_sender, mut reply_receiver) = mpsc::channel::<Vec<u8>>(max_inflight);
    let writer_task = tokio::spawn(async move {
        while let Some(reply) = reply_receiver.recv().await {
            if writer.write_all(&reply).await.is_err() {
                break;
            }
        }
    });

    let (acquire_sender, mut acquire_receiver) = mpsc::channel::<AcquireOutcome>(max_inflight);
    let inflight = Arc::new(Semaphore::new(max_inflight));
    // Dropping this aborts every spawned handler, including an acquire still parked in the
    // registry's queue. Without that, a disconnected client's queued acquire would still be
    // granted a lock that nobody holds and nobody will release.
    let mut handlers = JoinSet::new();

    // Owned solely by this loop. Sharing it with the spawned handlers would defeat the crash
    // path: a task parked for `wait_ms` would keep it alive, so dropping it on disconnect would
    // not release anything until that task finished.
    let mut held: HashMap<LockKey, HeldLock> = HashMap::new();
    let mut sequence = 0_u64;
    let mut frame = [0_u8; MAX_FRAME_SIZE];

    let outcome = loop {
        // A JoinSet keeps every task it spawned until it is joined, finished or not. A pooled
        // connection lives as long as the backend does, so without reaping here each request it
        // ever carried stayed allocated: memory grew with the request count until the socket
        // closed. try_join_next never waits, and the in-flight permit already bounds what is live.
        while handlers.try_join_next().is_some() {}

        // Pushed before the read parks: the client is told the moment this loop notices, which is
        // its own lease deadline rather than the one the client started a round trip later.
        for (action, identifier) in drop_expired(&mut held, peer) {
            send_push(&reply_sender, Reply::LockLost { action, identifier }).await;
        }

        // Derived from stamped deadlines, never from the lease itself, so arriving traffic cannot
        // push a hold forward. A connection holding a lock is bounded by its earliest expiry and
        // not by the idle timeout: a caller legitimately holding a 30s lease is quiet, not dead.
        let idle_timeout = match held.values().map(|lock| lock.expires_at).min() {
            Some(expiry) => expiry.saturating_duration_since(Instant::now()),
            None => frame_timeout,
        };

        let read_result = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
                continue;
            }
            reported = acquire_receiver.recv() => {
                // The single writer of `held`.
                if let Some(outcome) = reported
                    && let Some(lock) = outcome.granted
                    && held.insert(outcome.key, lock).is_some()
                {
                    // The registry hands out one permit per key, so a second grant cannot arrive
                    // while the first is still held. If it ever does, the overwrite would drop a
                    // guard the client still believes it owns.
                    warn!(%peer, action = outcome.key.0, identifier = outcome.key.1,
                          "a grant replaced a hold this connection already had");
                }
                continue;
            }
            result = timeout(idle_timeout, reader.read_exact(&mut frame[..OPCODE_SIZE])) => result,
        };

        match read_result {
            // A lease elapsed. Never fatal: killing the socket here would drop every other lock
            // on it and fail every request still in flight.
            Err(_) if !held.is_empty() => continue,
            Err(_) => break Err(anyhow!("idle timeout waiting for an opcode")),
            Ok(Err(error)) if error.kind() == ErrorKind::UnexpectedEof => break Ok(()),
            Ok(Err(error)) => break Err(error).context("opcode read failed"),
            Ok(Ok(_)) => {}
        }

        let Some(opcode) = Opcode::from_byte(frame[0]) else {
            break Err(anyhow!("unknown opcode {}", frame[0]));
        };

        // How long the payload is. Every opcode states its own length, and every length is checked
        // against that opcode's ceiling before a single byte of payload is buffered — a length
        // header is an instruction from an unauthenticated peer until the tag at the end says
        // otherwise.
        if let Err(error) = timeout(
            frame_timeout,
            reader.read_exact(&mut frame[OPCODE_SIZE..OPCODE_SIZE + LENGTH_PREFIX_SIZE]),
        )
        .await
        .map_err(|_| anyhow!("frame length read timed out"))
        .and_then(|read| read.context("frame length read failed"))
        {
            break Err(error);
        }
        let payload_size =
            u16::from_be_bytes([frame[OPCODE_SIZE], frame[OPCODE_SIZE + 1]]) as usize;
        let maximum = opcode.max_payload_size();
        if payload_size > maximum {
            break Err(anyhow!(
                "frame declares a {payload_size}-byte payload, over the {maximum}-byte ceiling"
            ));
        }
        let payload_offset = OPCODE_SIZE + LENGTH_PREFIX_SIZE;
        let frame_size = payload_offset + payload_size + AUTH_TAG_SIZE;

        // The rest of the frame is already in flight, so an EOF here is a truncated frame and
        // not a clean disconnect.
        if let Err(error) = timeout(
            frame_timeout,
            reader.read_exact(&mut frame[payload_offset..frame_size]),
        )
        .await
        .map_err(|_| anyhow!("frame body read timed out"))
        .and_then(|read| read.context("frame body read failed"))
        {
            break Err(error);
        }

        let tag_offset = frame_size - AUTH_TAG_SIZE;
        let mut received_tag = [0_u8; AUTH_TAG_SIZE];
        received_tag.copy_from_slice(&frame[tag_offset..frame_size]);
        // The opcode is inside the signed bytes, so a frame cannot be replayed as another
        // operation, and the sequence keeps it from being replayed as itself.
        if !auth::verify_hash(
            secret,
            &nonce,
            sequence,
            &frame[..tag_offset],
            &received_tag,
        ) {
            warn!(%peer, sequence, opcode = frame[0], "frame authentication failed");
            break Ok(());
        }
        let frame_sequence = sequence;
        sequence = match sequence.checked_add(1) {
            Some(next) => next,
            None => break Err(anyhow!("frame sequence overflow")),
        };

        // Refusing beyond the ceiling keeps one connection from spawning without bound. Taken
        // before spawning so the permit's lifetime is exactly the handler's.
        let permit = inflight.clone().try_acquire_owned().ok();

        match opcode {
            Opcode::ChargeCredits => {
                let payload = &frame[payload_offset..tag_offset];
                let request = match parse_charge(payload) {
                    Ok(request) => request,
                    Err(error) => break Err(error).context("authenticated frame is invalid"),
                };
                let Some(permit) = permit else {
                    warn!(%peer, "in-flight ceiling reached, refusing a charge");
                    send_reply(&reply_sender, frame_sequence, Reply::Unavailable).await;
                    continue;
                };
                let limiter = limiter.clone();
                let reply_sender = reply_sender.clone();
                handlers.spawn(async move {
                    let _permit = permit;
                    // A cold subject loads its usage from the store, so this cannot be inlined in the
                    // reader without head-of-line blocking every other request behind it.
                    //
                    // The two refusals are two shapes rather than two fields of one: a credit
                    // violation and an authorization denial answer different questions, and
                    // because denial short-circuits the charge they can never both apply.
                    let reply = match limiter.admit(request).await {
                        Ok(Decision::Allowed(verdict)) => {
                            if request.requests_authorization() {
                                granted_reply(verdict)
                            } else {
                                Reply::ChargeAllowed
                            }
                        }
                        Ok(Decision::CreditViolation(violation)) => {
                            Reply::ChargeCreditViolation(violation.response_byte())
                        }
                        Ok(Decision::AccessDenied(denial)) => {
                            Reply::ChargeAccessDenied(denial.detail_code() as u8)
                        }
                        Err(admit_error) => {
                            // Including a failed grant read: "I could not answer" is already a
                            // shape the client fails closed on, so it needs no code of its own.
                            warn!(error = %admit_error, "charge admission failed");
                            Reply::Unavailable
                        }
                    };
                    send_reply(&reply_sender, frame_sequence, reply).await;
                });
            }
            Opcode::MutateCompanyBudget => {
                let payload = &frame[payload_offset..tag_offset];
                let mutation = match parse_budget_mutation(payload) {
                    Ok(mutation) => mutation,
                    Err(error) => break Err(error).context("authenticated frame is invalid"),
                };
                let Some(permit) = permit else {
                    warn!(%peer, "in-flight ceiling reached, refusing a budget mutation");
                    send_reply(&reply_sender, frame_sequence, Reply::Unavailable).await;
                    continue;
                };
                let limiter = limiter.clone();
                let reply_sender = reply_sender.clone();
                handlers.spawn(async move {
                    let _permit = permit;
                    let reply = match limiter.mutate_budget(mutation).await {
                        Ok(BudgetMutationReply::Ok) => Reply::Ack,
                        Ok(refusal) => Reply::BudgetRefused(refusal as u8),
                        Err(mutation_error) => {
                            warn!(error = %mutation_error, "budget mutation failed");
                            Reply::Unavailable
                        }
                    };
                    send_reply(&reply_sender, frame_sequence, reply).await;
                });
            }
            Opcode::Report => {
                let payload = &frame[payload_offset..tag_offset];
                let query = match parse_report_query(payload) {
                    Ok(query) => query,
                    Err(error) => break Err(error).context("authenticated frame is invalid"),
                };
                let Some(permit) = permit else {
                    warn!(%peer, "in-flight ceiling reached, refusing a report");
                    send_reply(&reply_sender, frame_sequence, Reply::Unavailable).await;
                    continue;
                };
                let limiter = limiter.clone();
                let reply_sender = reply_sender.clone();
                handlers.spawn(async move {
                    let _permit = permit;
                    let reply = match limiter.report(query).await {
                        Ok(body) => Reply::Report(body),
                        Err(report_error) => {
                            warn!(error = %report_error, ?query, "report failed");
                            Reply::Unavailable
                        }
                    };
                    send_reply(&reply_sender, frame_sequence, reply).await;
                });
            }
            Opcode::PutGrants => {
                let payload = &frame[payload_offset..tag_offset];
                let entries = match parse_grants(payload) {
                    Ok(entries) => entries,
                    Err(error) => break Err(error).context("authenticated frame is invalid"),
                };
                let Some(permit) = permit else {
                    warn!(%peer, "in-flight ceiling reached, refusing a grants push");
                    send_reply(&reply_sender, frame_sequence, Reply::Unavailable).await;
                    continue;
                };
                let limiter = limiter.clone();
                let reply_sender = reply_sender.clone();
                handlers.spawn(async move {
                    let _permit = permit;
                    let reply = match limiter.put_grants(entries).await {
                        Ok(()) => Reply::Ack,
                        Err(grants_error) => {
                            warn!(error = %grants_error, "grants push failed");
                            Reply::Unavailable
                        }
                    };
                    send_reply(&reply_sender, frame_sequence, reply).await;
                });
            }
            Opcode::LockAcquire => {
                let payload = &frame[payload_offset..tag_offset];
                let request = match parse_acquire(payload) {
                    Ok(request) => request,
                    Err(error) => break Err(error).context("authenticated frame is invalid"),
                };
                let Some(permit) = permit else {
                    warn!(%peer, "in-flight ceiling reached, refusing an acquire");
                    send_reply(
                        &reply_sender,
                        frame_sequence,
                        Reply::LockRefused(LockReply::Capacity as u8),
                    )
                    .await;
                    continue;
                };
                let key = (request.action, request.identifier);
                let lease = locks.clamp_lease(request.lease());
                let locks = locks.clone();
                let reply_sender = reply_sender.clone();
                let acquire_sender = acquire_sender.clone();
                handlers.spawn(async move {
                    let _permit = permit;
                    let (reply, granted) = match locks.acquire(request).await {
                        LockOutcome::Acquired(guard) => {
                            let generation = guard.generation();
                            (
                                Reply::LockGranted { generation },
                                Some(HeldLock {
                                    _guard: guard,
                                    generation,
                                    expires_at: Instant::now() + lease,
                                }),
                            )
                        }
                        LockOutcome::Busy => (Reply::LockRefused(LockReply::Busy as u8), None),
                        LockOutcome::WaitTimeout => {
                            (Reply::LockRefused(LockReply::WaitTimeout as u8), None)
                        }
                        LockOutcome::Capacity => {
                            (Reply::LockRefused(LockReply::Capacity as u8), None)
                        }
                    };
                    // Hand ownership to the reader before answering. If it is gone the guard
                    // drops here instead, which releases the lock rather than stranding it.
                    if acquire_sender
                        .send(AcquireOutcome { key, granted })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    send_reply(&reply_sender, frame_sequence, reply).await;
                });
            }
            Opcode::LockRelease => {
                let payload = &frame[payload_offset..tag_offset];
                let request = match parse_release(payload) {
                    Ok(request) => request,
                    Err(error) => break Err(error).context("authenticated frame is invalid"),
                };
                let key = (request.action, request.identifier);
                // Both the key and the generation must match. A caller that gave up while its
                // release was already in flight would otherwise end whichever hold replaced it.
                let reply = match held.get(&key) {
                    Some(lock) if lock.generation == request.generation => {
                        held.remove(&key);
                        debug!(%peer, sequence = frame_sequence, action = key.0, identifier = key.1,
                               "released lock");
                        Reply::Ack
                    }
                    Some(lock) => {
                        warn!(%peer, action = key.0, identifier = key.1,
                              held = lock.generation, presented = request.generation,
                              "refusing a release from a superseded hold");
                        Reply::LockRefused(LockReply::Misuse as u8)
                    }
                    None => {
                        warn!(%peer, action = key.0, identifier = key.1,
                              "release names a lock this connection does not hold");
                        Reply::LockRefused(LockReply::Misuse as u8)
                    }
                };
                send_reply(&reply_sender, frame_sequence, reply).await;
            }
        }
    };

    // Order matters. Aborting first stops a queued acquire from being granted a lock nobody would
    // ever release; dropping `held` then frees everything this connection still holds, which is
    // what makes a dead socket an immediate release.
    handlers.abort_all();
    drop(handlers);
    held.clear();
    drop(reply_sender);
    let _ = writer_task.await;
    outcome
}

/// Drops every hold whose stamped deadline has passed, and reports which ones. Absolute, so no
/// amount of arriving traffic can extend one.
///
/// The keys come back rather than being logged and forgotten: the client still believes it owns
/// those locks, and a `LockLost` push is what tells it otherwise. Until the push existed, the only
/// thing on the other side was a timer started a round trip later than this deadline.
fn drop_expired(held: &mut HashMap<LockKey, HeldLock>, peer: &str) -> Vec<LockKey> {
    if held.is_empty() {
        return Vec::new();
    }
    let now = Instant::now();
    let mut expired = Vec::new();
    held.retain(|key, lock| {
        let alive = lock.expires_at > now;
        if !alive {
            warn!(%peer, action = key.0, identifier = key.1, "lock lease expired without a release");
            expired.push(*key);
        }
        alive
    });
    expired
}

/// The daemon never learns what a sub-access *is*: `sub_bytes` are the raw bits the blob held, and
/// "id 1 means all" is expanded on the Go side.
fn granted_reply(verdict: AccessVerdict) -> Reply {
    Reply::ChargeGranted {
        granted_mask: verdict.granted_mask,
        has_subs_mask: verdict.has_subs_mask,
        sub_bytes: verdict.sub_bytes,
    }
}

async fn send_reply(sender: &mpsc::Sender<Vec<u8>>, sequence: u64, reply: Reply) {
    // A closed channel means the connection is already going away, so the reply has nowhere to go.
    let _ = sender.send(reply.encode(sequence)).await;
}

/// A push: no request asked for it, so it carries no correlation and the client routes it on the
/// shape alone.
async fn send_push(sender: &mpsc::Sender<Vec<u8>>, reply: Reply) {
    let _ = sender.send(reply.encode(0)).await;
}
