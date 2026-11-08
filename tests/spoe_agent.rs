//! The SPOE agent over a real Unix socket, speaking SPOP the way HAProxy does: handshake, NOTIFY,
//! ACK, health check. The limiter behind it uses an in-memory store.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use async_trait::async_trait;
use fareward::{
    limiter::{
        aggregation::UsageKey,
        block::Rejections,
        credits_blob::Credits,
        quota::{CreditLimits, LimitPolicy, RateLimiter, ScopeLimits, Windows},
        storage::{
            LimiterStore, StoredBudget, StoredBudgetRow, StoredBudgetUsage, StoredUsage,
            StoredUserAccess,
        },
        time_frame,
    },
    routes::RouteTableHandle,
    service::server::bind_unix_socket,
    spoe::{
        Agent, AgentLimits,
        codec::{
            FLAG_FIN, FRAME_ACK, FRAME_AGENT_HELLO, FRAME_HAPROXY_HELLO, FRAME_NOTIFY, Frame,
            Reader, TypedData, encode_varint,
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::watch,
    time::timeout,
};

/// The Go-generated session token for company 7 / user 42 and the secret that signed it, the same
/// pair the bridge tests pin (`go run ./fareward/vectors`).
const TEST_SECRET: &[u8] = b"K1OzWIN0yarCc9ge";
const SESSION_TOKEN: &str = "o-F641c_oVFw39E4xUpKWcJRsd0JxRezdPl8S5KnS5Km";

/// acceso 78 at level 2, packed: what user 42 holds and what `productos` requires.
const GRANT: u16 = 78 << 2 | 1;

const ROUTES: &str = r#"
version = "spoe-test"

[policy]
api_prefixes = ["api"]
saas_company_id = 1
access_exempt_user_id = 1
operator_company_id = 1

[tariff.GET]
base_kib = 8
step_kib = 16

[tariff.POST]
base_kib = 8
step_kib = 8

[[route]]
method = "GET"
path = "productos"
route_id = 103
slots = [313]
base_credits = 2
step_credits = 1

[[route]]
method = "POST"
path = "productos"
route_id = 104
slots = [313]
base_credits = 5
step_credits = 1

[[route]]
method = "GET"
path = "p-public"
route_id = 60
public = true
"#;

struct GrantStore;

#[async_trait]
impl LimiterStore for GrantStore {
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
        Ok(Some(StoredBudgetRow {
            budget: StoredBudget {
                company_id,
                daily: unlimited,
                budget_month_start_day: time_frame::month_start_day(unix_seconds)?,
                monthly_ceiling: unlimited,
                last_set: unlimited,
                updated: 0,
            },
            ..Default::default()
        }))
    }
    async fn upsert_budget(&self, _budget: StoredBudget) -> Result<()> {
        Ok(())
    }
    async fn upsert_budget_usage(&self, _usage: StoredBudgetUsage) -> Result<()> {
        Ok(())
    }
    async fn add_rejections(&self, _c: i32, _t: i32, _r: Rejections) -> Result<()> {
        Ok(())
    }
    async fn load_user_access(
        &self,
        company_id: i32,
        user_id: i32,
    ) -> Result<Option<StoredUserAccess>> {
        Ok(
            (company_id == 7 && user_id == 42).then(|| StoredUserAccess {
                grants_blob: GRANT.to_be_bytes().to_vec(),
                sub_grants_blob: Vec::new(),
                status: 1,
            }),
        )
    }
}

struct TestAgent {
    socket: PathBuf,
    _shutdown: watch::Sender<bool>,
}

async fn start_agent(name: &str, burst: u64) -> TestAgent {
    let dir = std::env::temp_dir().join(format!("fareward-spoe-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    start_agent_in(dir, burst).await
}

async fn start_agent_in(dir: PathBuf, burst: u64) -> TestAgent {
    let routes_path = dir.join("routes.toml");
    std::fs::write(&routes_path, ROUTES).unwrap();
    let socket = dir.join("spoe.sock");

    let limits = ScopeLimits {
        cpu: CreditLimits {
            short: burst,
            long: 100_000,
        },
        inference: CreditLimits {
            short: burst,
            long: 100_000,
        },
    };
    let limiter = Arc::new(RateLimiter::new(
        1,
        LimitPolicy {
            company: limits,
            user: limits,
            company_extra_daily_cpu: 0,
            user_daily_share_pct: 100,
            disable_user_limit: true,
            windows: Windows::default(),
        },
        Arc::new(GrantStore),
        600,
    ));
    let agent = Agent::new(
        limiter,
        RouteTableHandle::open(&routes_path).unwrap(),
        Arc::new(TEST_SECRET.to_vec()),
        AgentLimits {
            max_connections: 8,
            max_inflight_per_connection: 16,
            max_frame_size: 16_384,
            shadow: false,
        },
    );
    let listener = bind_unix_socket(&socket).unwrap();
    let (shutdown_sender, shutdown) = watch::channel(false);
    tokio::spawn(fareward::spoe::agent::run(agent, listener, shutdown));
    TestAgent {
        socket,
        _shutdown: shutdown_sender,
    }
}

fn put_string(out: &mut Vec<u8>, text: &str) {
    encode_varint(out, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn frame(frame_type: u8, stream_id: u64, frame_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![frame_type];
    body.extend_from_slice(&FLAG_FIN.to_be_bytes());
    encode_varint(&mut body, stream_id);
    encode_varint(&mut body, frame_id);
    body.extend_from_slice(payload);
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn hello(healthcheck: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    for (key, value) in [
        ("supported-versions", TypedData::String("2.0".into())),
        ("max-frame-size", TypedData::Uint32(16_380)),
        ("capabilities", TypedData::String("pipelining".into())),
        ("healthcheck", TypedData::Bool(healthcheck)),
    ] {
        put_string(&mut payload, key);
        value.encode(&mut payload);
    }
    frame(FRAME_HAPROXY_HELLO, 0, 0, &payload)
}

fn check(
    stream_id: u64,
    method: &str,
    path: &str,
    auth: Option<&str>,
    length: Option<i64>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    put_string(&mut payload, "fareward-check");
    let args = [
        ("method", TypedData::String(method.into())),
        ("path", TypedData::String(path.into())),
        (
            "auth",
            auth.map_or(TypedData::Null, |auth| TypedData::String(auth.into())),
        ),
        ("length", length.map_or(TypedData::Null, TypedData::Int64)),
    ];
    payload.push(args.len() as u8);
    for (key, value) in args {
        put_string(&mut payload, key);
        value.encode(&mut payload);
    }
    frame(FRAME_NOTIFY, stream_id, 1, &payload)
}

async fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut length = [0_u8; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut length))
        .await
        .expect("agent answered in time")
        .unwrap();
    let mut body = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).await.unwrap();
    body
}

async fn connect(agent: &TestAgent) -> UnixStream {
    let mut stream = UnixStream::connect(&agent.socket).await.unwrap();
    stream.write_all(&hello(false)).await.unwrap();
    let body = read_frame(&mut stream).await;
    let reply = Frame::parse(&body).unwrap();
    assert_eq!(reply.frame_type, FRAME_AGENT_HELLO);
    let list = Reader::new(reply.payload).kv_list().unwrap();
    assert!(list.contains(&("version".into(), TypedData::String("2.0".into()))));
    assert!(list.contains(&("max-frame-size".into(), TypedData::Uint32(16_380))));
    stream
}

/// The variables of one ACK, by name.
async fn ask(
    stream: &mut UnixStream,
    request: Vec<u8>,
    stream_id: u64,
) -> Vec<(String, TypedData)> {
    stream.write_all(&request).await.unwrap();
    let body = read_frame(stream).await;
    let ack = Frame::parse(&body).unwrap();
    assert_eq!((ack.frame_type, ack.stream_id), (FRAME_ACK, stream_id));
    let mut reader = Reader::new(ack.payload);
    let mut vars = Vec::new();
    while !reader.is_empty() {
        assert_eq!(reader.byte().unwrap(), 1, "SET-VAR");
        assert_eq!(reader.byte().unwrap(), 3);
        assert_eq!(reader.byte().unwrap(), 2, "transaction scope");
        let name = reader.string().unwrap().to_owned();
        vars.push((name, reader.typed().unwrap()));
    }
    vars
}

fn var<'v>(vars: &'v [(String, TypedData)], name: &str) -> &'v TypedData {
    &vars
        .iter()
        .find(|(var_name, _)| var_name == name)
        .unwrap()
        .1
}

#[tokio::test]
async fn an_authorized_read_is_let_through_with_its_identity_and_grant() {
    let agent = start_agent("allowed", 1_000).await;
    let mut stream = connect(&agent).await;
    let bearer = format!("Bearer {SESSION_TOKEN}");
    let vars = ask(
        &mut stream,
        check(3, "GET", "/api/productos", Some(&bearer), None),
        3,
    )
    .await;
    assert_eq!(var(&vars, "status"), &TypedData::Int32(0));
    assert_eq!(var(&vars, "company"), &TypedData::Int32(7));
    assert_eq!(var(&vars, "user"), &TypedData::Int32(42));
    assert_eq!(var(&vars, "route"), &TypedData::Int32(103));
    // Slot 0 granted, no sub-accesses: the TCP reply's tail.
    assert_eq!(var(&vars, "grant"), &TypedData::Binary(vec![1, 0, 0]));
}

#[tokio::test]
async fn refusals_carry_the_backends_status() {
    let agent = start_agent("refusals", 1_000).await;
    let mut stream = connect(&agent).await;
    let bearer = format!("Bearer {SESSION_TOKEN}");
    let status = |vars: Vec<(String, TypedData)>| var(&vars, "status").clone();

    let bad_token = check(
        5,
        "GET",
        "/api/productos",
        Some("Bearer AAAAAAAAAAAA"),
        None,
    );
    assert_eq!(
        status(ask(&mut stream, bad_token, 5).await),
        TypedData::Int32(400)
    );
    let no_token = check(7, "GET", "/api/productos", None, None);
    assert_eq!(
        status(ask(&mut stream, no_token, 7).await),
        TypedData::Int32(400)
    );
    let unknown = check(9, "GET", "/api/nope", Some(&bearer), None);
    assert_eq!(
        status(ask(&mut stream, unknown, 9).await),
        TypedData::Int32(400)
    );
    let no_length = check(11, "POST", "/api/productos", Some(&bearer), None);
    assert_eq!(
        status(ask(&mut stream, no_length, 11).await),
        TypedData::Int32(411)
    );
    let public = check(13, "GET", "/api/p-public", None, None);
    assert_eq!(
        status(ask(&mut stream, public, 13).await),
        TypedData::Int32(0)
    );
}

#[tokio::test]
async fn a_company_over_its_burst_is_refused_with_429() {
    // Ten credits of burst and two per read: the sixth read is the first refused.
    let agent = start_agent("burst", 10).await;
    let mut stream = connect(&agent).await;
    let bearer = format!("Bearer {SESSION_TOKEN}");
    for stream_id in 1..=5 {
        let vars = ask(
            &mut stream,
            check(stream_id, "GET", "/api/productos", Some(&bearer), None),
            stream_id,
        )
        .await;
        assert_eq!(
            var(&vars, "status"),
            &TypedData::Int32(0),
            "read {stream_id}"
        );
    }
    let vars = ask(
        &mut stream,
        check(6, "GET", "/api/productos", Some(&bearer), None),
        6,
    )
    .await;
    assert_eq!(var(&vars, "status"), &TypedData::Int32(429));
    assert_eq!(var(&vars, "reason"), &TypedData::String("credit".into()));
}

/// The `usage` variable's fields, split on `;`.
fn usage(vars: &[(String, TypedData)]) -> Vec<String> {
    let TypedData::String(header) = var(vars, "usage") else {
        panic!("usage is not a string");
    };
    header.split(';').map(str::to_owned).collect()
}

/// The burst part of `{short}.{long}`: the bucket refills while the test runs, so only the long-window
/// figure is exact.
fn long_spent(field: &str) -> &str {
    field.split_once('.').unwrap().1
}

#[tokio::test]
async fn the_usage_header_reports_the_figures_and_the_reason() {
    let agent = start_agent("usage", 1_000).await;
    let mut stream = connect(&agent).await;
    let bearer = format!("Bearer {SESSION_TOKEN}");
    let unlimited = i64::MAX as u64;

    // A read charges two credits. Users are not limited apart here, so the user's figure is empty.
    let allowed = usage(
        &ask(
            &mut stream,
            check(3, "GET", "/api/productos", Some(&bearer), None),
            3,
        )
        .await,
    );
    assert_eq!(allowed[0], "42.");
    assert_eq!(allowed[1], format!("7.{}", unlimited - 2));
    assert_eq!(long_spent(&allowed[2]), "2");
    assert_eq!(allowed[3], "0");
    assert_eq!(allowed.len(), 4);

    // No identity, no limiter: only the reason.
    let bad_token = check(
        5,
        "GET",
        "/api/productos",
        Some("Bearer AAAAAAAAAAAA"),
        None,
    );
    assert_eq!(
        var(&ask(&mut stream, bad_token, 5).await, "usage"),
        &TypedData::String("0.;0.;.;1".into())
    );
    let unknown = check(7, "GET", "/api/nope", Some(&bearer), None);
    assert_eq!(
        var(&ask(&mut stream, unknown, 7).await, "usage"),
        &TypedData::String("0.;0.;.;4".into())
    );
}

#[tokio::test]
async fn a_blocked_company_sees_how_many_requests_the_block_refused() {
    // Ten credits of burst and two per read: the sixth read is refused by the limiter, which blocks
    // the company, and the seventh by the block cache.
    let agent = start_agent("usage-blocked", 10).await;
    let mut stream = connect(&agent).await;
    let bearer = format!("Bearer {SESSION_TOKEN}");
    for stream_id in 1..=5 {
        ask(
            &mut stream,
            check(stream_id, "GET", "/api/productos", Some(&bearer), None),
            stream_id,
        )
        .await;
    }
    let refused = usage(
        &ask(
            &mut stream,
            check(6, "GET", "/api/productos", Some(&bearer), None),
            6,
        )
        .await,
    );
    assert_eq!(long_spent(&refused[2]), "10");
    assert_eq!(refused[3], "5", "company over its short-window credits");
    assert_eq!(refused.len(), 4, "the limiter answered, not the block");

    for (stream_id, blocked) in [(7, "2"), (8, "3")] {
        let fields = usage(
            &ask(
                &mut stream,
                check(stream_id, "GET", "/api/productos", Some(&bearer), None),
                stream_id,
            )
            .await,
        );
        assert_eq!(fields[0], "42.", "the block knows only the company");
        assert_eq!(long_spent(&fields[2]), "10");
        assert_eq!(fields[3], "5");
        assert_eq!(fields[4], blocked);
    }
}

#[tokio::test]
async fn a_credit_refusal_carries_what_the_429_page_says() {
    let agent = start_agent("refusal-vars", 10).await;
    let mut stream = connect(&agent).await;
    let bearer = format!("Bearer {SESSION_TOKEN}");
    for stream_id in 1..=5 {
        let vars = ask(
            &mut stream,
            check(stream_id, "GET", "/api/productos", Some(&bearer), None),
            stream_id,
        )
        .await;
        // Admitted: nothing to say about a refusal.
        assert!(vars.iter().all(|(name, _)| name != "retry"));
    }
    for (stream_id, refused) in [(6, 1), (7, 2)] {
        let vars = ask(
            &mut stream,
            check(stream_id, "GET", "/api/productos", Some(&bearer), None),
            stream_id,
        )
        .await;
        assert_eq!(
            var(&vars, "window"),
            &TypedData::String("en los últimos 10 segundos".into())
        );
        assert_eq!(var(&vars, "spent"), &TypedData::Int64(10));
        assert_eq!(var(&vars, "refused"), &TypedData::Int32(refused));
        // Two credits take about two seconds to refill; the margin makes it at least two, and the
        // bucket never needs more than its ten-second period.
        let TypedData::Int32(retry) = var(&vars, "retry") else {
            panic!("retry is not an int32");
        };
        assert!((2..=11).contains(retry), "retry {retry}");
    }
}

/// Serves the agent on `$FAREWARD_SPOE_E2E_DIR/spoe.sock` for `$FAREWARD_SPOE_E2E_SECONDS`, so a
/// real HAProxy can be pointed at it (deploy/haproxy/, phase 0 of the plan). Burst of ten credits.
#[tokio::test]
#[ignore = "serves a real HAProxy; run by hand"]
async fn serve_for_a_real_haproxy() {
    let dir = PathBuf::from(std::env::var("FAREWARD_SPOE_E2E_DIR").expect("FAREWARD_SPOE_E2E_DIR"));
    let seconds: u64 = std::env::var("FAREWARD_SPOE_E2E_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let agent = start_agent_in(dir, 10).await;
    // HAProxy in a container connects as another uid: open the socket to it for the test only.
    std::fs::set_permissions(
        &agent.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

#[tokio::test]
async fn a_health_check_gets_a_hello_and_nothing_else() {
    let agent = start_agent("health", 1_000).await;
    let mut stream = UnixStream::connect(&agent.socket).await.unwrap();
    stream.write_all(&hello(true)).await.unwrap();
    let body = read_frame(&mut stream).await;
    assert_eq!(Frame::parse(&body).unwrap().frame_type, FRAME_AGENT_HELLO);
    let mut rest = Vec::new();
    let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "the agent closes after a health check"
    );
}
