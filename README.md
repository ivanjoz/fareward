# Fareward

One Rust process hosting four server-side services over two transports:

| Service | Transport | Port | Purpose |
|---|---|---|---|
| Access gate + credit limiter | Raw TCP, loopback | `fareward` (default `127.0.0.1:14013`) | Authorizes the caller against its cached grants, then charges CPU/inference quota — both in one round trip. |
| Lock service | Raw TCP, same port | `fareward` | Serializes an action across concurrent Lambdas. |
| Request log | Raw TCP, same port | `fareward` | One row per finished request, plus the code lines that failed. |
| SSE bridge | HTTP (TLS via Nginx) | `sse_bridge.port` (default `14012`) | Relays agent events between a backend and browser tabs, authenticating both ends. |

The limiter, the lock and the request log share the port, the connection, and the handshake —
nothing else. Each opcode has its own frame width, its own codec, and its own module. That shared port is why its
address is the root-level `fareward` key rather than something under `[rate_limit]`: it
belongs to the process, not to any one service inside it.

The bridge shares nothing with either but the process: the config load, the shutdown signal, and
the tokio runtime. No service calls into another.

**Nothing here is anonymous, and one of these services decides who may do what.** Three separate
relationships are authenticated with two secrets — the backend to the raw-TCP port, the backend to
the bridge, the browser to the bridge — and `CHARGE_CREDITS` answers a permission question before it
answers a cost one, out of a grant cache this process keeps because it is the only one always
resident. Identity and access are therefore not a layer above this daemon: they are the first thing
every opcode and every HTTP route resolves. See [Authentication](#authentication) and [Access
management and authorization](#access-management-and-authorization).

Start with [LOCK_SERVICE_WALKTHROUGH.md](LOCK_SERVICE_WALKTHROUGH.md) — one sign-up request end
to end, with the exact bytes. Designs: [PLAN.md](PLAN.md) (rate limiter, including all binary
formats), [PLAN_LOCK_SERVICE.md](PLAN_LOCK_SERVICE.md) and
[PLAN_MULTIPLEXING.md](PLAN_MULTIPLEXING.md) (lock service),
[PLAN_SSE_BRIDGE.md](PLAN_SSE_BRIDGE.md) (bridge). Deployment:
[`../scripts/configure/CONFIGURE_FAREWARD.md`](../scripts/configure/CONFIGURE_FAREWARD.md).

> **One process, shared fate.** The rate limiter loads existing usage from ScyllaDB before
> admitting anything and exits when it cannot — which also stops the bridge. Deploy the tables
> [it expects](#the-tables-it-expects-to-already-exist) before starting the daemon. The request log
> and the metrics collector are the two halves that do *not* share that fate: they drop rows rather
> than propagate a failure, because taking the process down would stop everything else.

## The backend contract

This repository is standalone: it builds, tests and runs with no Go in the picture, and its only
non-crates.io build dependency is `colbin`, a Rust crate. What it is *not* is self-contained. The
daemon answers questions something asks it and writes rows something reads, so a backend has to play
the client. The Go backend in `github.com/ivanjoz/genix` is that client today, and the only one —
but the coupling is **four contracts, not a language**.

| # | Contract | Defined by | What a different backend has to do |
|---|---|---|---|
| 1 | Raw-TCP frame protocol | `src/service/`, with a working client in [`go/`](go/) | Go: import it. Anything else: port `go/connection.go` and `go/siphash/` — eight-byte nonce at accept, then every frame tagged `SipHash-2-4(SHA-256(internal_apikey)[..16], fareward:v8 ‖ nonce ‖ sequence ‖ opcode ‖ payload)`, big-endian, over fixed-width big-endian fields. |
| 2 | The ScyllaDB schema | nobody here — the daemon issues no `CREATE TABLE` | Create the tables and columns below before first start. |
| 3 | The `accesos_computed` packing | `src/limiter/access.rs` | Write `users.accesos_computed` as little-endian `u16` grants. |
| 4 | The browser session token | `src/bridge/token.rs`, `src/bridge/auth.rs` | Issue a colbin-encoded `core.UsuarioToken`, its 16-byte `Hash` a keyed BLAKE2s-128 tag over `usrToken:v3`. **The only Go-shaped contract** — see below. |

Contracts 1–3 belong to the raw-TCP half. Contract 4 belongs to the SSE bridge alone, and the bridge
shares nothing with the rest but the config load and the tokio runtime — so a deployment that does
not run the bridge never meets contract 4 at all.

### The tables it expects to already exist

The daemon prepares its statements at startup and **never creates schema**. Ownership of these
tables sits with whoever runs the migrations; in the Genix deployment that is the Go ORM.

| Table | Access | Used for |
|---|---|---|
| `users` | read | `accesos_computed`, `status` — the grant cache behind `CHARGE_CREDITS` |
| `credit_usage_company`, `credit_usage_user` | read + write | the quota windows, loaded at cold start |
| `company_credit_budget` | read + write | the extra-credit pool, its ceiling and the activated month |
| `user_logs`, `request_errors` | write | the request log |
| `server_metrics` | write | the metrics collector |

The split matters at startup. The limiter loads usage before admitting anything and **exits** if it
cannot, so its four tables are a hard precondition. The last three are written by the two services
that fail open: a missing column leaves `ensure_prepared` retrying once a minute and dropping rows,
and the process stays up.

### Could a Rust or Node backend drive this?

**Go: nothing to do.** [`go/`](go/) is a module in this repository — `github.com/ivanjoz/fareward/go`
— that implements contracts 1 and 3 and depends on the standard library and nothing else. Configure
it and call it; see [The Go client](#the-go-client).

**Rust: yes, with nothing missing.** All four contracts are available to it. The frame protocol is
already in this crate, and `colbin` is the same crate the bridge decodes with, so a Rust backend can
issue session tokens directly.

**Node: yes for the raw-TCP services, with one gap at the bridge.** Contracts 1–3 are byte layouts
and CQL — nothing about them is Go. Contract 4 is the exception: colbin has Go and Rust
implementations and **no JavaScript one**, so a Node backend would have to write a colbin encoder
for the five fields of `UsuarioToken`, or run without the bridge, or swap `decode_session_token` for
a format it can already produce. The *channel* token is not a barrier — it is a small varint format
already mirrored in TypeScript in `frontend/core/agent/channel.ts`.

**Any other language: the same shape.** Contract 4 is the only place one specific Go type's wire
encoding is assumed, and it is confined to one function behind one trait-free entry point. For
contract 1, read `go/connection.go` rather than `src/service/` — it is the same protocol seen from
the caller's side, which is the side a port has to reproduce.

### The Go client

`go/` holds the client the Genix backend uses, and it is the reference implementation of contract 1.
It lives here rather than in the backend so a wire change and the client that speaks it move in one
commit, and so a backend that is not Genix can depend on it without depending on Genix.

Configure once, then call package-level functions — there is no client object to thread through
call sites, because the daemon keys its frame sequence per connection and one process wants one
sequence:

```go
import fareward "github.com/ivanjoz/fareward/go"

fareward.SetLogger(myLogger)                      // optional; a no-op until set
if err := fareward.ConfigureFareward(addr, secret); err != nil { return err }

err := fareward.ChargeAPIUsage(ctx, companyID, userID, routeID, method, payloadBytes, required)
lock, err := fareward.AcquireLock(ctx, action, identifier, maxWaiters)
err := fareward.SendRequestLog(ctx, record)
err := fareward.InvalidateUserAccess(ctx, companyID, userID)
err := fareward.MutateCompanyCreditBudget(ctx, companyID, op, amount)
```

It owns the wire *and the tariff* — `APICPUCredits`, `APICPUBaseCredits`, `InferenceCredits` —
because the daemon charges the counts a frame names and does not compute them. It owns none of the
policy above that: route-to-access mapping, charging exemptions and HTTP status mapping stay in the
caller, which is why the Genix backend keeps a 156-line adapter (`core/fareward_api.go`) on its side
of the seam and nothing more.

The module has **no dependencies beyond the standard library**, and that is worth keeping: this is
the one piece of the system a backend links into its own binary, so its dependency list becomes
somebody else's transitive dependency list.

Its cross-language tag vectors sit next to the Rust ones they pin, in `go/credits_test.go` and
`go/locks_test.go`, so a change to `DOMAIN` fails both suites in the same repository.

### What is *not* a contract

Most of what reads like backend coupling is caller-side policy this daemon has no opinion about:

- **Tariffs.** The daemon charges the credits the frame names; it does not compute them. Which
  method costs what, the KiB boundaries and the GET base-plus-top-up split are the client's.
- **Which route needs which access.** `src/limiter/access.rs` answers "does this user hold any of
  these grants" and deliberately does not know access *names*, that `access_list.yml` exists, or
  which route maps to which grant.
- **Route ids.** The request log stores whatever number the client puts in bits 39..24.
- **Who is exempt.** The user-1 bypass, unmapped GETs being free, `POST.user-self` needing no
  access — all resolved before a frame is ever built.

[Charging rules in the Go client](#charging-rules-in-the-go-client) documents what one client chose
for the first four; a different backend picks its own without touching this repository.

## Layout

`service/` owns everything the raw-TCP operations share — the listener, the handshake, the frame
tag and the opcode table. Each operation's own codec and logic live in its own tree, so adding
one touches the opcode table and nothing else:

```text
src/
├── main.rs      # spawns both transports, one shared shutdown signal
├── config.rs    # the only thing they share
├── siphash.rs   # SipHash-2-4: the keyed tag on both internal schemes (not the token)
├── service/     # the raw-TCP port: server (listener, handshake, opcode dispatch),
│                # protocol (opcode table), auth (frame tag)
├── limiter/     # opcodes 0x01/0x05/0x06: charging, authorization, company-budget
│                # mutation and grant-cache invalidation,
│                # quota, protocol, aggregation, credits_blob, time_frame, storage
├── lock/        # opcodes 0x02/0x03: registry.rs (sharded key mutexes), protocol
├── reqlog/      # opcode 0x04: protocol (the one variable-length payload), errors
│                # (ten-minute write suppression), writer (batching, fails open)
├── sysmetrics/  # no opcode: samples the machine once a second and writes the peak
│                # of each five-second window to server_metrics. collector (/proc +
│                # cgroup v2), writer (the tick loop and the insert)
└── bridge/      # token.rs (colbin + channel token), auth (the browser's session
                 # token and the backend's service header), channel, http (axum)

go/              # the Go client: its own module, stdlib only. The reference
                 # implementation of the raw-TCP protocol above, and what the Genix
                 # backend imports.
vectors/         # its own module too: prints the session-token vectors token.rs asserts
```

## Authentication

Three relationships are authenticated here, each under its own domain string, and none of them costs
a database round trip:

| Who proves what | How | Secret |
|---|---|---|
| Backend → raw-TCP port | An eight-byte random nonce written at accept, then every frame tagged with `SipHash-2-4(fareward:v8 ‖ nonce ‖ sequence ‖ opcode ‖ payload)`, big-endian. | `internal_apikey` |
| Backend → SSE bridge | `X-Bridge-Auth: <unix seconds>.<16 hex characters>`, signed over `sse-bridge:v2\|<unix seconds>` and accepted within ±300 s of this host's clock. | `internal_apikey` |
| Browser → SSE bridge | `Authorization: Bearer <session token>` — the colbin token the backend client issued, its own 128-bit keyed-BLAKE2s tag recomputed over `usrToken:v3 ‖ company ‖ user ‖ created ‖ username`. | `secret_phrase` |

Both keys are root-level in `config.toml` and must match the backend client's byte for byte. Each use is
domain-separated, so one key serving two protocols cannot produce interchangeable tags, and
splitting the two means the inter-service key can be rotated without invalidating every live session
token. Every tag is compared in constant time, including the bridge's, where the value is a string
and the temptation to use `==` is strongest.

**The TCP tag is bound to a connection and to frame order; the bridge's header is not.** The nonce
makes a captured frame useless on the next connection, the sequence makes it useless on this one,
and the opcode inside the signed bytes keeps a charge from being replayed as a lock release. The
service header has none of that, because the caller is a Lambda with no connection to bind to, so it
carries a five-minute skew window instead — the price of holding no per-caller state.

**The browser is verified from the token alone.** The session token is self-contained, so `GET /sse`
is answered without ScyllaDB. What the bridge does *not* do is decide permissions: it establishes
identity and stops there, because the backend already evaluated what this user may do when it
accepted the turn. A `created` timestamp is signed into the token, but this crate enforces no expiry
on it — ending a session is the backend's to do.

The channel in the URL is an **identifier, not a credential**, and both client routes cross-check
that the company and user encoded inside it are the authenticated ones. See
[Channel token](#channel-token).

## Rate limiter behavior

**For the whole flow — what Go decides, what the daemon decides, and where the numbers end up —
read [CREDIT_LIMITER_WALKTHROUGH.md](CREDIT_LIMITER_WALKTHROUGH.md) first.** The sections below are
the reference material it ties together.

- Authenticates persistent TCP connections with an eight-byte server nonce and sequence-bound
  SipHash-tagged frames.
- Answers **two** questions per frame: whether the caller holds the access the route requires, and
  whether the tenant can afford the request. Authorization is resolved first and a refusal charges
  nothing.
- Atomically checks company/user burst and hourly limits plus company-configured daily/monthly budgets.
- Derives each user's daily allowance as `rate_limit.user_daily_share_pct` of its company's CPU and
  inference allowances. Below 100 a single-user company cannot reach the rest of what it bought,
  which is the trade the key exists to let you make.
- Requires an explicitly activated current month; a new one stays blocked until `SET_CURRENT`. The
  month is the **local business month** (UTC-5), the same boundary the daily frames use — not the UTC
  month.
- Optionally serves reads from a company's extra daily pool once its entitlement has refused, without
  ever relaxing a burst gate.
- Aggregates every accepted charge into user/company and five-minute/daily in-memory records.
- Flushes only changed absolute records to `credit_usage` every 15 seconds.
- Leaves the fail-closed decision to the caller. The Go client fails closed on quota
  exhaustion and on daemon/storage unavailability; the daemon only reports which it was.

Version one must run as a single active process. Two instances would have independent in-memory
quota state and must not write the same absolute rows.

## Configuration

Add `[fareward]` and `[rate_limit]` to the project `config.toml`; the complete commented
example is in [`../config.example.toml`](../config.example.toml).

```toml
# The raw-TCP endpoint of the whole process, its own section: the opcode decides which service
# answers, so the address is not the rate limiter's to own.
#
# `host` is what the CLIENT dials; `public` is what the DAEMON binds — true is 0.0.0.0, false is
# 127.0.0.1. They are separate because behind NAT they cannot be one value: a cloud VM's public
# IP is never on its own interface, so binding it fails with EADDRNOTAVAIL. With public = false
# the client ignores `host` and dials loopback.
#
# public = true puts the port on the open internet. Frames are tag-authenticated but NOT
# encrypted, so it is only worth it when the backend runs off-box (Lambda, for instance).
[fareward]
host   = "127.0.0.1"
port   = 14013
public = false

# Purpose: Configure process limits and the two global quota profiles.
[rate_limit]
flush_seconds         = 15
frame_timeout_seconds = 30
max_connections       = 1024
shards                = 0 # 0 uses the logical CPU count
# Requests one connection may have in flight at once. Multiplexing removed the backpressure that
# one-request-per-socket used to give for free, so it has to be stated.
max_inflight_per_connection = 64
access_cache_seconds  = 600 # TTL of the cached user grants; INVALIDATE_USER_ACCESS is the fast path

company_cpu_10s       = 2000
company_inference_10s = 1000
company_cpu_1h        = 40000
company_inference_1h  = 10000

user_cpu_10s          = 1000
user_inference_10s    = 500
user_cpu_1h           = 20000
user_inference_1h     = 5000
```

The eight burst/hour ceilings are the only settings here with no built-in default: a guessed quota
is worse than none, so the process refuses to start without them. Since that refusal is a
three-second crash loop under `Restart=always`, the nested Fareward installer writes these
defaults into `config.toml` when they are absent, rather than leaving the daemon to discover it.

The lock service adds process-wide ceilings only — per-action policy stays in the Go call sites:

```toml
# Purpose: Bound the daemon's memory; who locks what is decided by the backend.
[lock]
max_keys          = 100000
max_total_waiters = 4096
max_lease_ms      = 60000
```

The request log adds a section where every key has a default, so omitting it entirely means "on,
with these" rather than a refusal to start:

```toml
# Purpose: One row per finished request; a month of history, then the partition expires.
[request_log]
enabled             = true
ttl_days            = 30
flush_ms            = 1000
max_batch           = 128
error_cache_seconds = 600
error_cache_entries = 20000
queue_capacity      = 8192
```

The SSE bridge adds one small section:

```toml
# Purpose: Expose the bridge's HTTP port; the public URL is only read by the backend/frontend.
[sse_bridge]
url     = "https://genix-sse.example.com/"
port    = 14012
verbose = false
```

The process also reads root `secret_phrase`, root `internal_apikey`, and `[db].host`, `port`,
`name`, `user`, and `password`. Set `GENIX_CONFIG_FILE` to select a non-default TOML file. Every
setting can be overridden by its uppercase environment equivalent, such as
`RATE_LIMIT_USER_CPU_10S`, `SSE_BRIDGE_PORT`, or `DB_HOST`.

All quota values must be positive and nondecreasing from ten seconds to one hour. Daily and monthly
entitlements are stored per company in `company_credit_budget`, not in this file. Every usage flush
writes the counters those entitlements are compared against back into the same row
(`usage_day_period`, `day_*_used`, `usage_month_start_day`, `month_*_used`, `usage_updated`), so the
SaaS panel can show remaining credits without re-summing the usage rows. Both windows are counted on
the Lima business day, the same day `time_frame::daily` buckets by.

`sse_bridge.url` is *not* parsed by this process — the backend reads it for service-to-service
publishing and the deployment script uses it for the Nginx `server_name`. The frontend gets the
matching public URL from the selected `[[endpoints]].bridge`; omitting that field means the
selected backend serves its own `/agent/stream`.

## Build and test

```bash
# Purpose: Compile and verify all protocol, codec, limiter, lock, and flush tests.
cd fareward
cargo test
cargo build --release
```

`cargo test` also runs `tests/lock_tcp.rs`, which drives a real socket: that is where the claims
this design rests on are checked — that a queued acquire does not delay a charge sent after it,
that a lease expires while the connection stays busy, and that a dropped connection frees
everything it held.

Building needs a C compiler even though no crate here contains C: rustc shells out to `cc` to
link, and a `build.rs` is itself an executable that has to be linked before cargo can run it.
`../scripts/configure/configure_fareward.py` installs one when the host has none.

For a host that should compile nothing, build a static binary and ship it instead. `.cargo/
config.toml` pins `rust-lld` for the musl targets, which is also what makes cross-building arm64
work — the host `cc` can only link for the host:

```bash
# Purpose: Produce a dependency-free binary; runs on any Linux of that architecture.
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Every versioned [GitHub Release of this repository](https://github.com/ivanjoz/fareward/releases)
publishes these static outputs as `fareward_linux_amd64` and `fareward_linux_arm64`, built
by `.github/workflows/release-binaries.yml` on a native runner per architecture. Downloading
`latest` is convenient for a manual install; replace `latest/download` with `download/vX.Y.Z` to
pin production automation to an immutable release.

```bash
# Map the Linux machine name to the release asset suffix.
case "$(uname -m)" in
  x86_64) release_architecture=amd64 ;;
  aarch64|arm64) release_architecture=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# Download the public binary and the manifest without requiring a GitHub token.
release_base_url=https://github.com/ivanjoz/fareward/releases/latest/download
release_asset="fareward_linux_${release_architecture}"
curl --fail --location --output "$release_asset" "${release_base_url}/${release_asset}"
curl --fail --location --output SHA256SUMS "${release_base_url}/SHA256SUMS"

# Verify exact release bytes before making the daemon executable.
grep " ${release_asset}$" SHA256SUMS | sha256sum --check --strict
chmod 0755 "$release_asset"
```

Before starting the daemon, deploy the backend tables so the generated Genix controller creates
`credit_usage`:

```bash
# Purpose: Regenerate/validate controllers and deploy tables through the normal Genix workflow.
cd scripts
go run . generate_controllers
go run . check_tables
```

Run locally from `fareward/` (it finds `../config.toml`):

```bash
# Purpose: Enable detailed request and flush diagnostics during local development.
RUST_LOG=fareward=debug cargo run
```

## SSE bridge HTTP contract

```
navegador                     bridge                        backend (Lambda)
   |--- GET /sse?ch= ---------->| registra el canal
   |<-- data:{bridgeReady} -----| handshake
   |                            |<--- POST /publish ---------| evento (no bloquea)
   |<-- data:{agentStatus} -----|
   |                            |<--- POST /rpc -------------| comando (BLOQUEA)
   |<-- data:{ID:7,navigate} ---|
   |--- POST /in {ID:7,...} --->|
   |                            |---- 200 {Kind,Payload} --->| request() retorna
```

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/sse?ch=<token>` | session token | Opens the stream. First frame `{"Type":"bridgeReady"}`, keepalive comment every 20s. |
| `POST` | `/in?ch=<token>` | session token | Browser reply `{ID,Type,Payload}`. Wakes the `/rpc` waiting on that `ID`. |
| `POST` | `/publish` | service tag | `{Channel,Message,WaitMs}` → `{Delivered}`. Does not block. |
| `POST` | `/rpc` | service tag | `{Channel,ID,Message,TimeoutMs,WaitMs}` → `{Kind,Payload}`. Blocks until the reply. |
| `GET` | `/health` | — | `{Ok,Channels,UptimeSeconds}`. |

Messages are opaque JSON and **nothing is buffered**: a message for a disconnected tab is
dropped (`Delivered:false`). The bridge holds no business logic and never touches ScyllaDB.

### Channel token

A channel is one browser tab, named by a single string:

```
bytes = uvarint(companyID) ‖ uvarint(userID) ‖ 6 random bytes (tab)
token = base64url(bytes), unpadded
```

For ordinary ids that is **11 characters** (`7/42` → `Byo3bFBobzE`). The decoder rejects
non-canonical encodings, which makes the token bijective with the triple — that is what lets it
be the registry key directly: two distinct strings can never name the same channel.

**It is an identifier, not a credential.** The browser still proves who it is with its session
token, and the bridge checks that the identity *inside* the channel token matches the
authenticated one. Without that cross-check, editing the company id would attach a client to
another tenant's stream.

The format is mirrored in `src/bridge/token.rs`, `backend/agent/channel.go`, and
`frontend/core/agent/channel.ts`; the vectors in `token.rs` pin all three byte for byte.

## TCP contract

After accepting a connection, the server writes an eight-byte random nonce. Every subsequent
request is `[opcode:1][payload][tag:8]`, big-endian. The opcode routes the payload; it is not a
shared frame shape, and the three operations have no field in common.

| Op | Name | Payload | Frame |
|---|---|---|---|
| `0x01` | `CHARGE_CREDITS` | company `u24` · user `u24` · extra_flag+route `u16` · CPU `u16` · inference `u16` · required_access `4×u16` | 29 |
| `0x02` | `LOCK_ACQUIRE` | action `u16` · identifier `i64` · max_waiters `u8` · wait_ms `u16` · lease_ms `u16` | 24 |
| `0x03` | `LOCK_RELEASE` | action `u16` · identifier `i64` · generation `u16` | 21 |
| `0x04` | `LOG_REQUEST` | `[length:u16]` then date `i16` · request `i64` · route `i16` · frame `u8` · company `u24` · user `i32` · elapsed `u16` · errors `u8`, then per error: id `i32` · line `u8`+bytes · text `u16`+bytes | ≤ 1 110 |
| `0x05` | `MUTATE_COMPANY_BUDGET` | company `u24` · operation `u8` · CPU `u64` · inference `u64` | 29 |
| `0x06` | `INVALIDATE_USER_ACCESS` | company `u24` · user `u24` (`0` = every user of the company) | 15 |

`0x00` stays unassigned so an all-zero frame cannot route. 249 opcodes remain free; new *use
cases* for the lock cost none of them, since they are namespaced by the `u16` action instead.

Three properties vary by opcode, and every variation is deliberate:

| Op | Answered | Framing | Malformed payload |
|---|---|---|---|
| `0x01` `0x02` `0x03` `0x05` | yes | fixed width | closes the connection |
| `0x04` `LOG_REQUEST` | **never** | `u16` length prefix | warning, connection survives |
| `0x06` `INVALIDATE_USER_ACCESS` | **never** | fixed width | closes the connection |

`0x04` carries strings, hence the prefix; its length is inside the signed bytes, and one declaring
more than the ceiling still closes the connection. Neither it nor `0x06` is answered — waiting on
"the log row was stored" would put this daemon on the critical path of every request in the system,
and the grant cache's TTL already bounds a lost invalidation — but both still advance the sequence,
which is what the tag is bound to. Only `0x04` survives a decode failure: the others decide whether
a request is admitted, and a log row is not worth taking down the charges and locks sharing that
socket.

### The charge frame asks two independent questions

| CPU / inference | `required_access` | What the frame is |
|---|---|---|
| non-zero | all zero | Charge only — no access is mapped to this route. |
| zero | filled | Authorize only — a route the Go router exempts from charging. |
| non-zero | filled | Both, in one round trip. |
| zero | all zero | Refused: a frame that asks nothing. |

Slots fill from index 0 and zero terminates; holding **any one** of them is enough. Each holds a
packed `acceso_id << 2 | (nivel - 1)` — see [Access management and
authorization](#access-management-and-authorization).

The route field is not only a route:

```
bit  15     EXTRA_CREDIT_FLAG  the router classified this charge as a read, making it eligible
                               for the extra daily pool — see "Extra credits"
bit  14     unassigned         a frame carrying it is refused
bits 13..0  route id           MAX_ROUTE_ID is fourteen bits
```

Those top two bits were always dead space both sides validated as zero, and the flag is stripped
before the range check both sides already ran — so anything left above fourteen bits is an error.

The tag covers the opcode and payload plus the connection nonce and the frame sequence, so a frame
can be replayed neither as itself nor as a different operation. Authentication, malformed-frame,
unknown-opcode, initialization and transport failures close the connection. The domain string is
bumped on every wire change — `fareward:v8` today — because replies are not authenticated:
without the bump an old client would authenticate fine and then misread a reply that grew under it.

### Replies are multiplexed

Requests travel in order; replies do not. An acquire can sit in a lock queue for seconds while
charges sent after it are answered immediately. Every reply is therefore five bytes:

```
[correlation:u16][status:u8][detail:u16]
```

| Field | Carries |
|---|---|
| `correlation` | The low 16 bits of the request's frame sequence, echoed back. The sequence already exists for the tag, so nothing extra travels on the wire — and it is what lets one connection serve many callers at once. |
| `status` | `0` is success for every opcode. |
| `detail` | The lock generation on a granted acquire, the authorization verdict on a charge, `0` everywhere else. |

`status` on a refusal:

| Opcode | Value | Meaning |
|---|---|---|
| `CHARGE_CREDITS` | low 5 bits | The scope, time window and exhausted credit types of the violation. |
| `LOCK_*` | `1` | Queue full. |
| `LOCK_*` | `2` | Wait timed out. |
| `LOCK_*` | `3` | Daemon at capacity. |
| `LOCK_*` | `4` | Protocol misuse — releasing a lock this connection does not hold, or a superseded generation. |
| any | `0xFF` | The daemon could not answer at all. Deliberately not a valid verdict for any opcode. |

`detail` on a charge is the authorization verdict, and the HTTP answer Go turns it into:

| Value | Verdict | Go |
|---|---|---|
| `0` | Nothing was asked | — |
| `1` | Granted | — |
| `2` | Holds none of the required accesses | 403 |
| `3` | No such user in this company | 401 |
| `4` | The user is not active | 401 |

A 429 and a 403 can never both be set — authorization resolves first and returns without charging —
so a client reads `status` for the credit answer and `detail` for the access one. Credit charges and
budget mutations fail closed; lock call sites keep their operation-specific policy. The client must
assign a sequence and write its frame atomically: two callers taking 5 and 6 but writing 6, 5 would
desynchronize the tag and every later frame would fail.

## Access management and authorization

The charge frame's other question. Grants are cached here because this is the only always-resident
process: on Lambda every execution environment starts empty and a large share of requests are
somebody's first, so caching there would pay a ScyllaDB round trip on the authorization path before
the handler runs. The frame was going out regardless.

**A grant is one `u16`**, and the level lives in the low two bits:

```
bits 15..2  acceso_id
bits  1..0  nivel - 1    nivel is 1..4; a read needs 1, a write 2
```

A required grant is satisfied by any level **at or above** it inside the same id: binary search for
the exact value, then one look at the next element to see whether it is still under that id's ceiling
(`required | 0b11`). This is `hasPackedAccesoInRange` from `backend/core/responses.go`, ported
unchanged, so the two processes cannot drift into disagreeing about what a grant means.

- **What is cached.** Per `(company, user)`: the sorted grants, `users.status`, and whether the row
  exists at all. Two bytes per grant, so a user holding every access in today's catalogue costs 68
  bytes. It sits in the same shard, mutex and key as the quota state, so a request that both
  authorizes and charges takes one lock.
- **Identity before permission.** The verdict resolves in that order — no such user, then
  `status != 1`, then grants — because the three become different HTTP answers, and collapsing them
  would tell a user this company no longer has that it merely lacks permission. `1` is the only
  value that means active: a `0` from a soft delete and anything a future migration invents are both
  refused.
- **Refusal precedes charging.** A refusal touches no usage, allocates no quota state and loads no
  budget. A 403 is free; the work given away is one binary search.
- **The blob is little-endian.** `accesos_computed` is written by
  `backend/genix-orm/scylla/converter.go` with `binary.LittleEndian.PutUint16`, while every integer
  in this protocol is big-endian. Reading it the wrong way round would not fail — it would authorize
  the wrong things.
- **Freshness.** `rate_limit.access_cache_seconds` (default 600) is a backstop, not the mechanism.
  `INVALIDATE_USER_ACCESS` is sent right after the column is rewritten — per user from `POST.users`,
  once per affected user from `POST.perfiles` — so a revoked access stops working immediately; the
  TTL only covers a lost frame or a restarted backend. User `0` is the wildcard, for a write that
  cannot name them.

**What stays in Go.** This daemon holds no copy of `access_list.yml` and never sees an access *name*,
which route maps to which access, or what level a method implies. That is all `resolveRouteAccess` in
`backend/main-handlers.go`, where every rule meaning "do not ask" produces an empty slot list rather
than a special case here:

| Case | What the router does |
|---|---|
| Unmapped `GET` | Frame with no slots — free to any session. |
| `POST.user-self` | Frame with no slots — needs a session, no access. |
| User 1 | Frame with no slots. `login.go` synthesizes its grant list in the login response and never persists it, so its stored blob is empty and this daemon would deny it. It cannot be asked. |
| Mapped route with no accesses | Refused in Go, no frame — the catalogue denies by default, and an empty slot list would have meant the opposite. |
| Route mapped to more than four accesses | Refused in Go with a 500 — truncating would authorize against fewer accesses than the route declares. |

## Extra credits

`rate_limit.company_extra_credits_24h` is CPU a company may spend per local business day **after**
its normal quota has already refused, and only on a frame marked as a read. It is the difference
between a tenant out of credit seeing a 429 everywhere and one that can still look at its data.
Zero — the default — removes the feature entirely.

```
charge
  ├─ burst gates: 10s buckets, hourly ceilings ──refuse──→ 429
  │      pass       never bypassed: a pooled charge still spends burst tokens and hour_used
  ├─ entitlement: company daily, user daily, monthly ──pass──→ charged to day_used
  │      refuse     this, and only this, is what the pool bypasses
  ├─ read-marked frame, and the pool covers the charge? ──no──→ that same 429, unchanged
  │      yes
  └─ charged to day_extra_cpu_used, never to day_used or month_used
```

- **Reads only, and the daemon does not decide which.** Eligibility rides in the frame, derived on
  the Go side inside `ChargeAPIUsage` from the same string that chose the tariff, so a write cannot
  be marked by a caller disagreeing with itself. A marked frame that also asks for inference is
  not relaxed in any dimension: the pool is a single CPU figure.
- **The burst gates are never relaxed.** A flood of reads is what they protect the machine from, so
  skipping them would hand a company in read-only mode unlimited burst.
- **No per-user share.** One user can drain it. Halving it the way the daily user gate is halved
  would leave a single-user company — most of them — unable to reach it at all, and the burst gates
  already bound the rate.
- **Counted apart.** It lands in `company_credit_budget.day_extra_cpu_used`, keyed by the same
  `usage_day_period` as the other counters, so `daily - day_used` keeps meaning what a write is
  judged against and the monthly ceiling never moves.
- **`month_extra_cpu_used` is not a second ceiling** — there is no monthly extra limit. It is the
  correction `ensure_budget` subtracts when it rebuilds `month_used` from the month's usage rows,
  because a pooled request still landed in them. Without it every restart would quietly shrink the
  entitlement by whatever the pool had paid for.
- **Invisible on the wire.** A pooled request is answered exactly like a quota one; the client cannot
  tell. The daemon logs it at `info` — the only outward sign a tenant is in read-only mode.

## Lock behavior

One holder per `(action, identifier)` — every lock is mutual exclusion. The daemon interprets
neither field: the Go call sites decide what is being serialized (a client IP, a company, a packed
pair), which is what makes one service cover every case in the project.

- **Ownership is bound to the connection.** The permit lives in the connection task, so a
  disconnect, a crash and a killed Lambda all free the lock at once — no sweeper, no waiting out a
  lease. One connection may hold several keys, and losing it frees all of them.
- **The lease is an absolute deadline**, stamped at grant and checked by the reader: the backstop
  for a holder that stays connected but wedged. Deliberately not the socket's read timeout — with
  charges and locks sharing one connection, arriving traffic would push that forward forever.
  Expiry drops that one lock and leaves the connection running, since killing it would take every
  other lock with it. While a connection holds anything the idle timeout does not apply: a caller
  holding a 30 s lease is quiet, not dead.
- **Each grant carries a generation**, returned in the reply's `detail` and required by the release.
  Without it, a release from a caller that already gave up would end whichever hold replaced it on
  that key — a real risk now that several callers share one connection. The counter is registry-wide
  because an idle key's entry is pruned, and a per-key counter would restart at zero and match the
  stale release exactly.
- **Two ceilings, one at each end.** `max_waiters` is checked before queueing, because with an
  unbounded queue the wait itself becomes the denial of service;
  `rate_limit.max_inflight_per_connection` bounds the other direction, since multiplexing removed
  the backpressure one-request-per-socket used to provide for free.

Locks are in-memory: a restart drops all of them, and two daemon instances would hand the same key
to two holders. Single active process, same as the limiter. And a lock orders callers; it does not
make them safe — a partition can free a key while its holder still works, so work inside one must
remain safe to run twice.

## Request log behavior

| Table | One row per | Retention |
|---|---|---|
| `user_logs` | Finished request, in unlogged batches every `flush_ms` or at `max_batch`, whichever comes first. | `USING TTL ttl_days`. The partition is the date, so a whole day expires together and Scylla drops it wholesale. |
| `request_errors` | Distinct failing **code line**, at most once per `error_cache_seconds`. | None — a code line that failed once is worth keeping until it is rewritten. |

The code line is the identity, not the message: two failures at `responses.go:539` are the same
error however differently they phrase themselves, which keeps that table bounded by the codebase
instead of by traffic. The staleness costs nothing — the current message is already in CloudWatch
under the request id that referenced it.

**Fails open, everywhere.** A full queue drops the record and counts it; a failed write warns and
drops the batch; statements that cannot be prepared at startup disable the writer and leave the
process running. A log row is never worth stopping the limiter and the bridge for.

The dashboard reads through one index, `frame_route_company_agg`, packed frame-major so a
fifteen-minute slice of a day is one contiguous clustering range and a poll reads forward instead of
rereading the day:

```
bits 47..40  frame      0..95, four per hour
bits 39..24  route_id   the generated number, backend/core/api_routes.generated.go
bits 23..0   company_id
```

It is written twice — `src/reqlog/protocol.rs` writes the column, `backend/core/types/user_logs.go`
ranges over it — and the vectors in both test files pin them together. A drift there produces rows
that look right and a chart that is quietly wrong.

## Server metrics behavior

The one part of this daemon nothing calls into: it just ticks. Design in
[PLAN_SERVER_METRICS.md](PLAN_SERVER_METRICS.md), schema in
`backend/core/types/server_metrics.go`. One row every `row_seconds` in `server_metrics`, partitioned
by unix day and clustered by the slot within it (`secondsIntoDay / 5`, so 0..17279 and comfortably
inside the int16 key).

| Columns | Unit | Range it has to cover |
|---|---|---|
| CPU | Hundredths of a percent **of the whole machine** | Scylla pinning eight of eight cores reads 100.00%, not the top-style 800% that would not fit the column. |
| Memory | Megabytes | Saturates at 32 GB. |
| Network | 5 KB/s units | Reaches 163 MB/s while still resolving the single-digit KB/s an idle box shows. |
| any | `-1` | **Not measured**, and the whole answer to the Lambda case: with no `genix.service` on the machine the backend's columns carry the sentinel rather than a `0` that would read as an idle backend. |

- **Every value is a peak, not an average.** Sampling runs at `sample_seconds` and the row carries
  the highest of the five sub-samples, so a one-second spike survives into a five-second row. The
  price is that these rows cannot be summed: each value is a peak standing in for five seconds, so
  adding `net_rx_rate` across a day overstates the bytes transferred. `-1` likewise reaches the row
  only when no sub-sample of the window produced a value.
- **Per-service memory and CPU come from the unit's cgroup** — `memory.stat`'s `anon + file_mapped`
  (which reconstructs `VmRSS`: anonymous plus mapped file pages, cold page cache left out) and
  `cpu.stat`'s `usage_usec`. One read covers a multi-process service, and a missing directory is
  exactly the "not on this box" signal. The directory is **searched for** under `/sys/fs/cgroup`,
  never assumed to be under `system.slice` — Scylla's packaging puts it at
  `scylla.slice/scylla-server.slice/scylla-server.service`. Resolved once and cached, retrying every
  30 s while it fails, so one that starts later is picked up.
- **Rows land on a wall-clock grid**, not on a tick counter, so a restart resumes the same slots and
  a skipped tick leaves an honest hole instead of shifting every later row.
- **Fails open**, like the request log. The insert is prepared lazily and retried every 60 s, so a
  daemon that starts before `fn-homologate` created the table heals itself.

## Deploying

`sudo python3 scripts/configure.py 37` compiles the binary, installs the systemd units, and writes
the bridge's Nginx vhost (HTTP/3 when a certificate exists and Nginx was built with it). It asks
nothing — everything comes from `config.toml` — and installs a C compiler if the host has none.
After starting the service it probes `/health` rather than trusting `systemctl restart`: this daemon
exits when ScyllaDB is unreachable, which with `Restart=always` looks identical to a healthy start.
The generated unit and the three non-negotiable Nginx streaming settings are in
[`../scripts/configure/CONFIGURE_FAREWARD.md`](../scripts/configure/CONFIGURE_FAREWARD.md).

For a self-hosted backend, select both components (`237` or `238`) and choose Backend mode `1` or
`2`: the dispatcher then installs this daemon without its public SSE Nginx vhost and does not
require `sse_bridge.url`, since the backend already serves `/agent/stream`.

Keep the raw TCP listener on loopback or a private network. The frame tag authenticates messages but does not
encrypt them, and the bridge's HTTP port speaks plain HTTP with Nginx terminating TLS in front.

## Charging rules in the Go client

**None of this is daemon behaviour.** The tariff is computed caller-side and arrives as the credit
counts already inside the frame, so what follows describes the choices the Go backend made, not a
rule this repository enforces. It is here because it is the only worked example of the policy layer
contract 1 leaves open, and because reading the usage tables requires knowing it.

Sizes are uncompressed bytes in binary KiB (`1 KiB = 1024 bytes`), and the group boundaries are the
same for both methods:

| Method | Groups | Sized by | CPU for the first 8 KiB | CPU beyond it |
|---|---|---|---|---|
| `GET` | `0/1/2` | response bytes: `<32`, `32..256`, `>256` KiB | 2 credits | 1 per started 16 KiB |
| `POST` / `PUT` | `3/4/5` | request-body bytes, same boundaries | 5 credits | 1 per started 8 KiB |

Inference has no base and is charged only on success: one credit per started 8 KiB of provider
input, two per started 8 KiB of provider output. `PUT` is a write like `POST` — same tariff, same
required access level, declared once (`isWriteMethod` in the router, one `case "POST", "PUT"` in
the tariff).

How many frames a request sends:

| Request | Frames |
|---|---|
| `POST` / `PUT` | One, before the handler runs: it authorizes and charges together. |
| `GET` | A pre-handler frame with the access check and the **base** two credits, then a **top-up** only if the response exceeded the first 8 KiB. Most GETs send one frame and no top-up. |
| A method with no tariff | Authorize-only. Not a 503: the tariff errors on a method it does not know, and the router fails closed on an error. |
| A route exempt from charging | Authorize-only, zero credits. The credit panel's own reads, so a tenant out of credit can still see why — and three of them are access-mapped, two SaaS-only, so skipping the *frame* would leave them open to any session. |

The GET is split because its byte count only exists after the handler while its verdict is needed
before it. Two consequences when reading the usage tables: a GET that ends in an error still costs
its two base credits, and a streamed response is charged its base and never topped up.
