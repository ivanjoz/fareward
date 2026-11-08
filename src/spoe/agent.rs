//! The SPOE agent (plan phase 4): HAProxy asks, before it reads a request body, whether the request
//! may go on, and the agent answers by setting variables the HAProxy rules act on.
//!
//! One more front-end of the same `RateLimiter`: the decision is the backend's own gate, replayed
//! from the route table (`routes`) and the session token, and the limiter call is the one the
//! backend would have made over TCP.
//!
//! HAProxy sends the message `fareward-check` with `method`, `path`, `auth` (the Authorization
//! header) and `length` (Content-Length, absent when the request has none). The agent sets, in the
//! transaction scope (`txn.<engine-id>.<name>`):
//!
//! | Variable  | Type   | Meaning |
//! |-----------|--------|---------|
//! | `status`  | int32  | 0 to let the request through, otherwise the HTTP status to answer |
//! | `reason`  | string | Why, for the access log: `public`, `session`, `granted`, `token`, `credit`… |
//! | `company` | int32  | The verified company, 0 when there is none |
//! | `user`    | int32  | The verified user, 0 when there is none |
//! | `route`   | int32  | The route number |
//! | `grant`   | binary | Granted slots and sub-accesses, the TCP reply's tail: `[mask][subs][len][bytes]` |

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc, watch},
};
use tracing::{debug, info, warn};

use crate::{
    bridge::auth::authenticate_user,
    limiter::{
        access::{AccessDenial, AccessVerdict},
        credits_blob::Credits,
        quota::{Decision, RateLimiter},
    },
    routes::{Admission, RouteMatch, RouteTableHandle},
    spoe::codec::{
        self, DisconnectStatus, FRAME_HAPROXY_DISCONNECT, FRAME_HAPROXY_HELLO, FRAME_NOTIFY, Frame,
        Message, Reader, TypedData, VarScope,
    },
};

pub const CHECK_MESSAGE: &str = "fareward-check";

/// What the agent was asked to be, from `[spoe]`.
#[derive(Clone, Debug)]
pub struct AgentLimits {
    pub max_connections: usize,
    pub max_inflight_per_connection: usize,
    pub max_frame_size: u32,
    /// Evaluate without charging: the backend still decides and charges over TCP, and HAProxy only
    /// logs what the agent would have done (plan phase 7).
    pub shadow: bool,
}

#[derive(Debug, Default)]
pub struct AgentMetrics {
    pub messages: AtomicU64,
    pub allowed: AtomicU64,
    pub refused: AtomicU64,
    pub unavailable: AtomicU64,
    pub protocol_errors: AtomicU64,
    /// Sum of evaluation time, for an average next to `messages`.
    pub evaluation_micros: AtomicU64,
}

pub struct Agent {
    limiter: Arc<RateLimiter>,
    routes: Arc<RouteTableHandle>,
    secret_phrase: Arc<Vec<u8>>,
    limits: AgentLimits,
    pub metrics: AgentMetrics,
}

/// The agent's answer to one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub status: u16,
    pub reason: &'static str,
    pub company_id: i32,
    pub user_id: i32,
    pub route_id: u16,
    pub grant: Option<AccessVerdict>,
}

impl Verdict {
    fn refuse(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            company_id: 0,
            user_id: 0,
            route_id: 0,
            grant: None,
        }
    }

    fn vars(&self) -> Vec<(VarScope, &'static str, TypedData)> {
        let mut vars = vec![
            (
                VarScope::Transaction,
                "status",
                TypedData::Int32(i32::from(self.status)),
            ),
            (
                VarScope::Transaction,
                "reason",
                TypedData::String(self.reason.into()),
            ),
            (
                VarScope::Transaction,
                "company",
                TypedData::Int32(self.company_id),
            ),
            (
                VarScope::Transaction,
                "user",
                TypedData::Int32(self.user_id),
            ),
            (
                VarScope::Transaction,
                "route",
                TypedData::Int32(i32::from(self.route_id)),
            ),
        ];
        if let Some(grant) = &self.grant {
            let mut tail = vec![
                grant.granted_mask,
                grant.has_subs_mask,
                grant.sub_bytes.len() as u8,
            ];
            tail.extend_from_slice(&grant.sub_bytes);
            vars.push((VarScope::Transaction, "grant", TypedData::Binary(tail)));
        }
        vars
    }
}

impl Agent {
    pub fn new(
        limiter: Arc<RateLimiter>,
        routes: Arc<RouteTableHandle>,
        secret_phrase: Arc<Vec<u8>>,
        limits: AgentLimits,
    ) -> Arc<Self> {
        Arc::new(Self {
            limiter,
            routes,
            secret_phrase,
            limits,
            metrics: AgentMetrics::default(),
        })
    }

    /// The backend's gate, replayed: route, session, route policy, then the limiter.
    pub async fn decide(
        &self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        content_length: Option<u64>,
    ) -> Verdict {
        let table = self.routes.current();
        let entry = match table.lookup(method, path) {
            RouteMatch::Refuse(refusal) => {
                return Verdict::refuse(refusal.status(), "route");
            }
            RouteMatch::Public { route_id } => {
                return Verdict {
                    route_id,
                    ..Verdict::refuse(0, "public")
                };
            }
            RouteMatch::Private(entry) => entry,
        };

        // The backend answers a bad or missing token with its default error status, 400.
        let Ok(user) = authenticate_user(authorization, &self.secret_phrase) else {
            return Verdict {
                route_id: entry.route_id,
                ..Verdict::refuse(400, "token")
            };
        };
        let identified = |status, reason| Verdict {
            status,
            reason,
            company_id: user.company_id,
            user_id: user.id,
            route_id: entry.route_id,
            grant: None,
        };

        let request = match table.admission(entry, user.company_id, user.id, content_length) {
            Admission::Refuse(refusal) => return identified(refusal.status(), "policy"),
            Admission::Public { .. } | Admission::SessionOnly { .. } => {
                return identified(0, "session");
            }
            Admission::Ask(request) => request,
        };

        let mut verdict = match self.ask(request).await {
            Ok(Decision::Allowed(grant)) => Verdict {
                grant: request.requests_authorization().then_some(grant),
                ..identified(0, "granted")
            },
            Ok(Decision::AccessDenied(AccessDenial::NoAccess)) => identified(403, "no-access"),
            // A missing or inactive user is about the session: re-authenticating is the fix.
            Ok(Decision::AccessDenied(_)) => identified(401, "identity"),
            Ok(Decision::CreditViolation(_))
                if table.policy().tolerates_credit_refusal(user.company_id) =>
            {
                // The operator is never locked out by its own budget, but still needs the
                // permission: retry as an authorization-only request, as the backend does.
                let access_only = crate::limiter::protocol::Request {
                    credits: Credits::default(),
                    extra_credits_allowed: false,
                    ..request
                };
                if !access_only.requests_authorization() {
                    identified(0, "operator")
                } else {
                    match self.ask(access_only).await {
                        Ok(Decision::Allowed(grant)) => Verdict {
                            grant: Some(grant),
                            ..identified(0, "operator")
                        },
                        Ok(Decision::AccessDenied(AccessDenial::NoAccess)) => {
                            identified(403, "no-access")
                        }
                        Ok(Decision::AccessDenied(_)) => identified(401, "identity"),
                        Ok(Decision::CreditViolation(_)) => identified(429, "credit"),
                        Err(_) => identified(503, "unavailable"),
                    }
                }
            }
            Ok(Decision::CreditViolation(_)) => identified(429, "credit"),
            Err(limiter_error) => {
                warn!(error = %limiter_error, "spoe: limiter unavailable, failing closed");
                identified(503, "unavailable")
            }
        };
        if verdict.status == 0 && verdict.grant.is_none() && request.requests_authorization() {
            verdict.grant = Some(AccessVerdict::default());
        }
        verdict
    }

    async fn ask(&self, request: crate::limiter::protocol::Request) -> Result<Decision> {
        if self.limits.shadow {
            self.limiter.evaluate(request).await
        } else {
            self.limiter.admit(request).await
        }
    }

    async fn verdict_for(&self, message: &Message) -> Verdict {
        let started = Instant::now();
        let method = message.arg("method").and_then(TypedData::as_str);
        let path = message.arg("path").and_then(TypedData::as_str);
        let verdict = match (method, path) {
            (Some(method), Some(path)) => {
                self.decide(
                    method,
                    path,
                    message.arg("auth").and_then(TypedData::as_str),
                    message.arg("length").and_then(TypedData::as_u64),
                )
                .await
            }
            // A misconfigured HAProxy: fail closed, loudly.
            _ => {
                warn!(message = %message.name, "spoe: message without method or path");
                Verdict::refuse(503, "misconfigured")
            }
        };
        let counter = match verdict.status {
            0 => &self.metrics.allowed,
            503 => &self.metrics.unavailable,
            _ => &self.metrics.refused,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.metrics.messages.fetch_add(1, Ordering::Relaxed);
        self.metrics.evaluation_micros.fetch_add(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        verdict
    }

    /// The ACK for one NOTIFY: one verdict per `fareward-check` message, other messages ignored.
    async fn answer(&self, frame: &Frame<'_>) -> Vec<u8> {
        let messages = match codec::parse_messages(frame.payload) {
            Ok(messages) => messages,
            Err(parse_error) => {
                self.metrics.protocol_errors.fetch_add(1, Ordering::Relaxed);
                warn!(error = %parse_error, "spoe: malformed NOTIFY, answering 503");
                let refusal = Verdict::refuse(503, "malformed");
                return codec::ack(frame.stream_id, frame.frame_id, &refusal.vars());
            }
        };
        let mut vars = Vec::new();
        for message in messages
            .iter()
            .filter(|message| message.name == CHECK_MESSAGE)
        {
            vars.extend(self.verdict_for(message).await.vars());
        }
        codec::ack(frame.stream_id, frame.frame_id, &vars)
    }
}

/// Reads one frame's body, refusing one larger than the negotiated size.
async fn read_frame(
    stream: &mut (impl AsyncReadExt + Unpin),
    max_frame_size: u32,
) -> std::io::Result<Option<Result<Vec<u8>, DisconnectStatus>>> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length);
    if length > max_frame_size {
        return Ok(Some(Err(DisconnectStatus::FrameTooBig)));
    }
    let mut body = vec![0_u8; length as usize];
    stream.read_exact(&mut body).await?;
    Ok(Some(Ok(body)))
}

/// What HAPROXY-HELLO negotiated.
struct Hello {
    max_frame_size: u32,
    pipelining: bool,
    healthcheck: bool,
}

fn negotiate(frame: &Frame<'_>, our_max_frame_size: u32) -> Result<Hello, DisconnectStatus> {
    if frame.frame_type != FRAME_HAPROXY_HELLO {
        return Err(DisconnectStatus::Invalid);
    }
    let list = Reader::new(frame.payload)
        .kv_list()
        .map_err(|_| DisconnectStatus::Invalid)?;
    let find = |key: &str| {
        list.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    };
    let versions = find("supported-versions")
        .and_then(TypedData::as_str)
        .ok_or(DisconnectStatus::NoVersion)?;
    if !versions
        .split(',')
        .any(|version| version.trim() == codec::SPOP_VERSION)
    {
        return Err(DisconnectStatus::BadVersion);
    }
    let their_max = find("max-frame-size")
        .and_then(TypedData::as_u64)
        .ok_or(DisconnectStatus::NoFrameSize)?;
    let max_frame_size = u32::try_from(their_max)
        .unwrap_or(u32::MAX)
        .min(our_max_frame_size);
    let pipelining = find("capabilities")
        .and_then(TypedData::as_str)
        .is_some_and(|capabilities| {
            capabilities
                .split(',')
                .any(|capability| capability.trim() == "pipelining")
        });
    let healthcheck = matches!(find("healthcheck"), Some(TypedData::Bool(true)));
    Ok(Hello {
        max_frame_size,
        pipelining,
        healthcheck,
    })
}

async fn serve_connection(agent: Arc<Agent>, stream: UnixStream) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    let Some(first) = read_frame(&mut reader, agent.limits.max_frame_size).await? else {
        return Ok(());
    };
    let hello = first.and_then(|body| {
        Frame::parse(&body)
            .map_err(|_| DisconnectStatus::Invalid)
            .and_then(|frame| negotiate(&frame, agent.limits.max_frame_size))
    });
    let hello = match hello {
        Ok(hello) => hello,
        Err(status) => {
            agent
                .metrics
                .protocol_errors
                .fetch_add(1, Ordering::Relaxed);
            writer
                .write_all(&codec::agent_disconnect(status, "handshake refused"))
                .await?;
            return Ok(());
        }
    };
    writer
        .write_all(&codec::agent_hello(hello.max_frame_size, hello.pipelining))
        .await?;
    // A health check is a hello and nothing else; HAProxy closes the connection itself.
    if hello.healthcheck {
        return Ok(());
    }

    // Replies leave through one writer, so pipelined answers never interleave mid-frame.
    let (replies, mut outgoing) =
        mpsc::channel::<Vec<u8>>(agent.limits.max_inflight_per_connection);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            if writer.write_all(&frame).await.is_err() {
                return;
            }
        }
        let _ = writer.shutdown().await;
    });
    let inflight = Arc::new(Semaphore::new(agent.limits.max_inflight_per_connection));

    while let Some(body) = read_frame(&mut reader, hello.max_frame_size).await? {
        let body = match body {
            Ok(body) => body,
            Err(status) => {
                let _ = replies
                    .send(codec::agent_disconnect(status, "frame too big"))
                    .await;
                break;
            }
        };
        let Ok(frame) = Frame::parse(&body) else {
            agent
                .metrics
                .protocol_errors
                .fetch_add(1, Ordering::Relaxed);
            let _ = replies
                .send(codec::agent_disconnect(
                    DisconnectStatus::Invalid,
                    "malformed frame",
                ))
                .await;
            break;
        };
        match frame.frame_type {
            FRAME_NOTIFY if hello.pipelining => {
                // Bounded: past the ceiling the reader waits, and HAProxy's processing timeout
                // turns the wait into its own fail-closed answer.
                let Ok(permit) = inflight.clone().acquire_owned().await else {
                    break;
                };
                let agent = agent.clone();
                let replies = replies.clone();
                tokio::spawn(async move {
                    let frame = Frame::parse(&body).expect("parsed once already");
                    let ack = agent.answer(&frame).await;
                    let _ = replies.send(ack).await;
                    drop(permit);
                });
            }
            FRAME_NOTIFY => {
                let ack = agent.answer(&frame).await;
                if replies.send(ack).await.is_err() {
                    break;
                }
            }
            FRAME_HAPROXY_DISCONNECT => {
                let _ = replies
                    .send(codec::agent_disconnect(DisconnectStatus::Normal, "bye"))
                    .await;
                break;
            }
            other => {
                agent
                    .metrics
                    .protocol_errors
                    .fetch_add(1, Ordering::Relaxed);
                debug!(frame_type = other, "spoe: unexpected frame type");
                let _ = replies
                    .send(codec::agent_disconnect(
                        DisconnectStatus::Invalid,
                        "unexpected frame",
                    ))
                    .await;
                break;
            }
        }
    }
    // In-flight answers still hold sender clones; the writer ends once the last one is sent.
    drop(replies);
    let _ = writer_task.await;
    Ok(())
}

/// Accepts HAProxy's connections until `shutdown` turns true.
pub async fn run(agent: Arc<Agent>, listener: UnixListener, mut shutdown: watch::Receiver<bool>) {
    let connections = Arc::new(Semaphore::new(agent.limits.max_connections));
    info!(shadow = agent.limits.shadow, "spoe agent listening");
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    warn!("spoe: connection limit reached, refusing a connection");
                    continue;
                };
                let agent = agent.clone();
                tokio::spawn(async move {
                    if let Err(io_error) = serve_connection(agent, stream).await {
                        debug!(error = %io_error, "spoe connection ended with an error");
                    }
                    drop(permit);
                });
            }
        }
    }
}
