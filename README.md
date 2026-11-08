# Fareward

One Rust process hosting server-side services over two transports:

| Service | Transport | Port | Purpose |
|---|---|---|---|
| Access gate + credit limiter | Raw TCP, loopback | `fareward` (default `127.0.0.1:14013`) | Authorizes the caller against its cached grants, then charges CPU/inference quota — both in one round trip. |
| Lock service | Raw TCP, same port | `fareward` | Serializes an action across concurrent Lambdas. |
| Reports and grants | Raw TCP, same port | `fareward` | Usage, budgets and server metrics read out of its store; the grants the backend pushes. |
| SSE bridge | HTTP (TLS via Nginx) | `sse_bridge.port` (default `14012`) | Relays agent events between a backend and browser tabs, authenticating both ends. |
| HAProxy edge agent (optional) | SPOP 2.0, Unix socket | `spoe.socket` | The access gate and credit limiter above, asked by HAProxy on the request headers before the body is read. See [HAProxy edge agent](#haproxy-edge-agent-spoe). |

The limiter, the lock, the reports and the grants push share the port, the connection, and the handshake —
nothing else. Each opcode owns its own payload and its own module. That shared port is why its
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

> **One process, shared fate.** The rate limiter loads existing usage from its own store before
> admitting anything and exits when it cannot open it — which also stops the bridge. The grants live
> in that store too, pushed by the backend, so Fareward depends on **no database** but its own. The
> metrics collector is the half that does *not* share that fate: it drops rows rather than propagate
> a failure, because taking the process down would stop everything else.
>
> The request log is not here any more: the backend writes `user_logs` and `request_errors` itself
> (Genix keeps `user_logs` in a compressed MyRocks table, written without the WAL and expired by a
> TTL). Opcode `0x04` is retired.

## The backend contract

This repository is standalone: it builds, tests and runs with no Go in the picture, and its only
non-crates.io build dependency is `colbin`, a Rust crate. What it is *not* is self-contained. The
daemon answers questions something asks it and writes rows something reads, so a backend has to play
the client. The Go backend in `github.com/ivanjoz/genix` is that client today, and the only one —
but the coupling is **three contracts, not a language**.

| # | Contract | Defined by | What a different backend has to do |
|---|---|---|---|
| 1 | Raw-TCP frame protocol | `src/service/`, with a working client in [`go/`](go/) | Go: import it. Anything else: port `go/connection.go` and `go/siphash/` — eight-byte nonce at accept, then every frame tagged `SipHash-2-4(SHA-256(internal_apikey)[..16], fareward:v12 ‖ nonce ‖ sequence ‖ opcode ‖ length ‖ payload)`, big-endian. Every payload is a colbin message, which has a Rust crate and a browser module as well as the Go one. |
| 2 | The grants push | `src/store/grants.rs`, `src/limiter/access.rs` | Push every user's status and grant blobs (little-endian `u16` grants) with opcode `0x0A`: at start, and on every change. |
| 3 | The browser session token | `src/bridge/token.rs`, `src/bridge/auth.rs` | Issue a colbin-encoded `core.UsuarioToken`, its 16-byte `Hash` a keyed BLAKE2s-128 tag over `usrToken:v3`. **The only Go-shaped contract** — see below. |

Contracts 1–2 belong to the raw-TCP half. Contract 3 belongs to the SSE bridge alone, and the bridge
shares nothing with the rest but the config load and the tokio runtime — so a deployment that does
not run the bridge never meets contract 3 at all.

### Its own store

Usage, budgets and server metrics live in **Fareward's own store**, an embedded
[fjall](https://github.com/fjall-rs/fjall) database in `[store].path` (default
`/var/lib/fareward/store`). Fareward is their source of truth: the backend reads them through the
report opcode (below) and no longer has tables for them. Pure binary, company-first keys:

| Keyspace | Key | Value |
|---|---|---|
| `usage_company` | company, time_frame | version, `rejected_short`, `rejected_long`, `rejected_no_funds` (u32 each), the credits blob |
| `usage_user` | company, user, time_frame | version, the credits blob |
| `budget` | company | version, the entitlement and the usage counters, fixed 111 bytes |
| `server_metrics` | date, slot | version, eleven i16 columns |
| `grants` | company, user | version, status, the grants blob, the sub-grants blob — as last pushed |
| `meta` | one byte | the store's layout version; a store of another layout refuses to open |

Keys are big-endian with the sign bit flipped, so byte order is numeric order and one company is one
contiguous range. The layouts are in `src/store/codec.rs`. Each flush ends with one fsync, so a crash
loses at most one flush interval of usage, as before. **Backups are Fareward's job now**: the
directory is the whole state of the credit system.

### Reports

Opcode `0x09` reads the store; the Go client is [`go/reports.go`](go/reports.go)
(`QueryCompanyUsage`, `QueryEveryCompanyUsage`, `QueryUserUsage`, `QueryCompanyBudgets`,
`QueryServerMetrics`). The reply is shape `0x0B`, `[length:u32][body]`, the only reply that may be
large (at most 32 MiB). Reports read what was flushed, so they lag the limiter by at most one flush
interval. Over TCP, so a Lambda backend reads them as a VPS one does.

### Grants

Fareward does not read the backend's `users` table: the backend pushes what the gate needs — per
user, the status and the two grant blobs (`accesos_computed`, `accesos_sub_computed`) — with opcode
`0x0A` ([`go/grants.go`](go/grants.go), `PutUserGrants`). Each frame (at most 8 KiB; the client
splits a larger push) is validated whole, stored atomically, drops those users' cached grants, and
only then is acknowledged. A user sent as deleted is removed, so it is denied like an unknown one.

A user Fareward was never sent is denied, so the backend pushes **everyone at start** (Genix:
`security.SyncAllFarewardGrants` in the background on a VPS start, `fn-sync-fareward-grants` on
demand) and **each user on every save**. Re-sending is harmless; a lost push is repaired by the next
save or the next full sync.

Sequences are not here: MariaDB owns them (the ORM's `_sequences` table), so the
`RESERVE_SEQUENCE`/`SET_SEQUENCE` opcodes `0x07`/`0x08` and reply shapes `0x09`/`0x0A` are retired.

### Could a Rust or Node backend drive this?

**Go: nothing to do.** [`go/`](go/) is a module in this repository — `github.com/ivanjoz/fareward/go`
— that implements contracts 1 and 2 and depends on the standard library and `colbin`, which has no
dependencies of its own. Configure it and call it; see [The Go client](#the-go-client).

**Rust: yes, with nothing missing.** All three contracts are available to it. The frame protocol is
already in this crate, and `colbin` is the same crate the bridge decodes with, so a Rust backend can
issue session tokens directly.

**Node: yes.** Contracts 1–2 are byte layouts — nothing about them is Go — and they are now
colbin messages, for which the format's repository carries a browser module alongside the Go and
Rust ones. Contract 3 is the same story: a Node backend encodes `UsuarioToken` with that module
rather than transcribing the format. The *channel* token is not a barrier either — a small varint
format already mirrored in TypeScript in `frontend/core/agent/channel.ts`.

**Any other language: the same shape, and one dependency.** A port needs colbin, which is a format
with a written specification and three implementations rather than a library with an API. Contract 3
is the only place one specific Go type's wire encoding is assumed, and it is confined to one function
behind one trait-free entry point. For contract 1, read `go/connection.go` rather than `src/service/`
— it is the same protocol seen from the caller's side, which is the side a port has to reproduce.

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
err := fareward.PutUserGrants(ctx, users)
err := fareward.MutateCompanyCreditBudget(ctx, companyID, op, amount)
```

It owns the wire *and the tariff* — `APICPUCredits`, `APICPUBaseCredits`, `InferenceCredits` —
because the daemon charges the counts a frame names and does not compute them. It owns none of the
policy above that: route-to-access mapping, charging exemptions and HTTP status mapping stay in the
caller, which is why the Genix backend keeps a 156-line adapter (`core/fareward_api.go`) on its side
of the seam and nothing more.

The module has **exactly one dependency**, `github.com/ivanjoz/colbin`, which carries the request
frames that are records rather than fixed layouts (`PROTOCOL_SHAPES.md` §4) and which the daemon
decodes with the same format's Rust crate. colbin has no dependencies of its own, so the module still
pulls nothing else in — and that restraint is worth keeping, because this is the one piece of the
system a backend links into its own binary and its dependency list becomes somebody else's
transitive dependency list.

Its cross-language tag vectors sit next to the Rust ones they pin, in `go/credits_test.go` and
`go/locks_test.go`, so a change to `DOMAIN` fails both suites in the same repository.

### What is *not* a contract

Most of what reads like backend coupling is caller-side policy this daemon has no opinion about:

- **Tariffs.** The daemon charges the credits the frame names; it does not compute them. Which
  method costs what, the KiB boundaries and the GET base-plus-top-up split are the client's.
- **Which route needs which access.** `src/limiter/access.rs` answers "does this user hold any of
  these grants" and deliberately does not know access *names*, that `access_list.yml` exists, or
  which route maps to which grant.
- **Route ids.** The daemon meters whatever route number the client puts in a frame.
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
├── limiter/     # opcodes 0x01/0x05: charging, authorization and company-budget
│                # mutation,
│                # quota, protocol, aggregation, credits_blob, time_frame, storage
├── lock/        # opcodes 0x02/0x03: registry.rs (sharded key mutexes), protocol
├── routes/      # the route table the backend generates: table (parse, lookup, tariff,
│                # admission), watch (hot reload on change, keeps the old table on error)
├── spoe/        # the HAProxy agent: codec (SPOP 2.0 frames), agent (the gate, replayed)
├── store/       # opcodes 0x09/0x0A: the fjall store, reports and grants. codec (keys and values), limiter (the
│                # LimiterStore over it), metrics (the MetricsSink), query (reports)
├── sysmetrics/  # no opcode: samples the machine once a second and writes the peak
│                # of each five-second window to the store. collector (/proc +
│                # cgroup v2), writer (the tick loop and the write)
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
| Backend → raw-TCP port | An eight-byte random nonce written at accept, then every frame tagged with `SipHash-2-4(fareward:v12 ‖ nonce ‖ sequence ‖ opcode ‖ length ‖ payload)`, big-endian. | `internal_apikey` |
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
is answered without the database. What the bridge does *not* do is decide permissions: it establishes
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
- Atomically checks company/user short- and long-window limits plus company-configured daily/monthly budgets.
- Derives each user's daily allowance as `rate_limit.user_daily_share_pct` of its company's CPU and
  inference allowances. Below 100 a single-user company cannot reach the rest of what it bought,
  which is the trade the key exists to let you make.
- With `rate_limit.disable_user_limit = true`, limits by company only: no per-user gate, state or
  cold load. Each company is one customer who creates its own users, so the per-user rows stay as
  accounting only, and since nothing loads them before a charge, the flush reads the stored row and
  adds to it instead of replacing it.
- Once a company gate refuses, **blocks the whole company** until that gate can reopen (the burst
  bucket refills, the clock hour turns, the business day turns, or the budget changes) and answers
  its requests without taking the limiter's lock, so an abuser cannot slow the other companies. A
  request that charges nothing is never blocked, and a marked read still reaches the extra pool while
  the pool has credit. Never by IP: an IP can be shared by many customers.
- Counts every company refusal by cause, in the five-minute frame and in the day: `rejected_short` and
  `rejected_long` (abuse) and `rejected_no_funds` (day, month or an extra pool that could not pay).
  Counts only, not a request log.
- Requires an explicitly activated current month; a new one stays blocked until `SET_CURRENT`. The
  month is the **local business month** (UTC-5), the same boundary the daily frames use — not the UTC
  month.
- Optionally serves reads from a company's extra daily pool once its entitlement has refused, without
  ever relaxing a burst gate.
- Aggregates every accepted charge into user/company and five-minute/daily in-memory records.
- Flushes only changed absolute records to its store every 15 seconds, then fsyncs once.
- Leaves the fail-closed decision to the caller. The Go client fails closed on quota
  exhaustion and on daemon/storage unavailability; the daemon only reports which it was.

Version one must run as a single active process. Two instances would have independent in-memory
quota state and must not write the same absolute rows.

## HAProxy edge agent (SPOE)

Optional, and off unless `spoe.socket` is set. HAProxy (3.1 or later: SPOP 2.0) asks the agent once
per request, on the headers, before the body is read. The agent replays the backend's gate with the
same limiter the TCP port charges through: route, session token, route policy, then access and
credits. A refused request never reaches the backend, and its body is never read. The design and its
decisions are in [plans/plan.md](plans/plan.md); the HAProxy side is in
[`deploy/haproxy/`](deploy/haproxy/).

**The route table.** The backend writes it at startup to `[fareward].routes_file`, a TOML file with
one row per served route: method, exact path, `route_id`, the packed access slots, `base_credits` and
`step_credits` (0 = not charged), and `public`, `saas_only` or `deny` where they apply. A `[policy]`
section carries the API prefixes, the SaaS company, the access-exempt user and the operator company;
`[tariff.<METHOD>]` carries the size steps. **A route not in the table is refused.** The file is
polled every `spoe.routes_poll_ms`; a changed file is validated whole and swapped in, and an invalid
one keeps the previous table. A missing or invalid table at startup fails the start.

**The verdict** is left in transaction variables, `txn.fw.*`:

| Variable | Meaning |
|---|---|
| `status` | `0` go on; otherwise the HTTP status to answer (the backend's own: 400, 401, 403, 429, 500, 503; plus 411 for a charged write without Content-Length and 413 for a write whose charge overflows) |
| `reason` | for the access log: `public`, `session`, `granted`, `operator`, `token`, `route`, `policy`, `no-access`, `identity`, `credit`, `unavailable` |
| `company`, `user`, `route` | who was admitted, for which route |
| `grant` | the granted slots and sub-accesses, the TCP reply's tail: `[mask][has_subs][len][bytes]` |

On an admitted request HAProxy forwards these as `x-fareward-admitted`, `-company`, `-user`, `-route`
and `-grant` (hex), after deleting any the client sent. A backend with
`[fareward].trust_edge_headers = true` takes them from a loopback peer instead of charging again; it
still charges a GET's response top-up itself, streams included.

**Modes.** `spoe.mode = "shadow"` (the default) evaluates without charging and without blocking, so
the access log can be compared with the backend's decisions before anything depends on it.
`"enforce"` charges, and HAProxy refuses on the verdict. HAProxy's own mode (`FAREWARD_ENFORCE` in
the reference config) must match. Any agent failure fails closed: a 503.

```toml
[fareward]
routes_file = "/var/lib/genix/fareward-routes.toml"   # written by the backend, read here

[spoe]
socket                      = "/run/fareward/spoe.sock"
mode                        = "shadow"   # or "enforce"
routes_poll_ms              = 2000       # minimum 100
max_connections             = 64
max_inflight_per_connection = 256
max_frame_size              = 16384      # 256 to 1048576
```

Under SELinux, a confined or containerized HAProxy cannot connect to a socket an unconfined daemon
created: every request then fails closed with `txn.fw.error` set while the agent sees no connection.

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
access_cache_seconds  = 600 # TTL of the cached user grants; a PUT_GRANTS push drops them at once

# Two rate-limit windows, always two. Optional; absent means 10 seconds and 60 minutes.
# The short window is a token bucket: its credits refill continuously over this many seconds.
short_window_seconds  = 10
# The long window is a fixed clock window (with 10: :00, :10, :20…). In steps of 5 minutes, because
# a restart rebuilds it from the five-minute usage rows; at most 1440 and longer than the short one.
long_window_minutes   = 10

# Credits per window. Required.
company_cpu_short       = 2000
company_inference_short = 1000
company_cpu_long        = 40000
company_inference_long  = 10000

user_cpu_short          = 1000
user_inference_short    = 500
user_cpu_long           = 20000
user_inference_long     = 5000

# Optional. true limits by company only: the user_* ceilings and user_daily_share_pct stop
# applying (they are still required and validated). Default false.
disable_user_limit    = false
```

The eight short/long ceilings are the only settings here with no built-in default: a guessed quota
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

The store is local and Fareward's own:

```toml
# Purpose: Where usage, budgets and server metrics live. Back this directory up.
[store]
path = "/var/lib/fareward/store"
```

Fareward reads no database settings: `[mariadb]`, `db.name` and `[request_log]` in a shared config
file are ignored.

The SSE bridge adds one small section:

```toml
# Purpose: Expose the bridge's HTTP port; the public URL is only read by the backend/frontend.
[sse_bridge]
url     = "https://genix-sse.example.com/"
port    = 14012
verbose = false
```

The process also reads root `secret_phrase` and root `internal_apikey`. Set `GENIX_CONFIG_FILE` to select a non-default TOML file. Every
setting can be overridden by its uppercase environment equivalent, such as
`RATE_LIMIT_USER_CPU_SHORT`, `RATE_LIMIT_LONG_WINDOW_MINUTES`, `SSE_BRIDGE_PORT`, or `DB_HOST`.

All quota values must be positive and nondecreasing from the short to the long window. Daily and monthly
entitlements are stored per company in the store's `budget` keyspace, not in this file. Every usage
flush writes the counters those entitlements are compared against back into the same value
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
dropped (`Delivered:false`). The bridge holds no business logic and never touches the database.

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
request is `[opcode:1][length:u16][payload][tag:8]`, big-endian. The opcode routes the payload; it
is not a shared frame shape, and the operations have no field in common.

Every payload is a [colbin](https://github.com/ivanjoz/colbin) message — one numbered struct per
shape, with ids 1..16 so both sides use four-bit keys. `PROTOCOL_SHAPES.md` is the full map and the reasoning; the `cb` ids are §1.2.

| Op | Name | Codec | Fields | Payload ceiling |
|---|---|---|---|---|
| `0x01` | `CHARGE_CREDITS` | colbin | company `i32` · user `i32` · route `u16` · CPU `u16` · inference `u16` · extra_allowed `bool` · access `4×u16` | 48 |
| `0x02` | `LOCK_ACQUIRE` | colbin | action `u16` · identifier `i64` · max_waiters `u8` · wait_ms `u32` · lease_ms `u32` | 40 |
| `0x03` | `LOCK_RELEASE` | colbin | action `u16` · identifier `i64` · generation `u16` | 24 |
| `0x05` | `MUTATE_COMPANY_BUDGET` | colbin | company `i32` · operation `u8` · CPU `u64` · inference `u64` | 32 |
| `0x09` | `REPORT` | colbin | kind `u8` · company `i32` · user `i32` · first `i64` · last `i64` | 48 |
| `0x0A` | `PUT_GRANTS` | hand-rolled | count `u16`, then per user: company `i32` · user `i32` · flags `u8` · status `i8` · grants `u16`-prefixed · sub-grants `u16`-prefixed | 8 192 |

A colbin field holding its zero value is not written at all, so a payload is as small as the record
is sparse: an ungated charge is 10 bytes against the 20 the old fixed layout always spent.

`0x00` stays unassigned so an all-zero frame cannot route. `0x04` (the retired request log), `0x06`
(the retired grant-cache invalidation, replaced by `PUT_GRANTS`) and `0x07`/`0x08` (the retired
sequence opcodes) stay unassigned too, so a stale client's frame closes the connection. New *use cases* for the lock cost none of them, since they are namespaced by the `u16` action instead.

A malformed payload closes the connection, whatever the opcode. Every opcode is answered.

Every opcode is length-prefixed. There used to be a second, fixed-width framing for the payloads
whose width the opcode alone implied; nothing is left that a fixed width could describe, so one
reader path replaced two. The length is inside the signed bytes, and one declaring more than its
opcode's ceiling closes the connection before a byte of payload is buffered.

