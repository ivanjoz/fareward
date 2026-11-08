# Plan: Fareward as an SPOE agent behind HAProxy

> **Status:** proposal. This document states the **technical intent**, not the implementation.
> Whoever picks it up has the repository in front of them and should settle the details against the
> real code. Wherever this plan assumes something it did not verify, it is marked **[verify]**.

---

## 1. Goal

Make Fareward's decision (may this identity call this route? can the company afford it?) **in
HAProxy, from the request headers, before the body is read and before the request reaches Go**.

Today the flow is: proxy → Go → `0x01` frame to Fareward → handler. A refused request has already
crossed the proxy and, if the proxy buffers, has already uploaded its whole body. The goal is that a
refused request **costs no upload bandwidth, no Go CPU and no buffer memory**.

The chosen mechanism is **SPOE** (Stream Processing Offload Engine): HAProxy sends request arguments
to an external agent over the **SPOP** protocol, the agent replies by setting variables, and
HAProxy's `http-request` rules act on them. Fareward also becomes that agent.

## 2. Why it matters (context for the decision)

- With HTTP/3 (QUIC) and HTTP/2, the body travels in frames separate from the headers and under
  per-stream flow control. If the request is refused on its headers, the client can only send what
  fits in the initial window; the rest is never transmitted.
- HAProxy terminates TLS/QUIC and evaluates rules as soon as it has the headers. That is the
  earliest point where the user's identity exists: the kernel cannot read the token because it
  travels encrypted.
- The cost of an accepted check does not change (one local round trip, the same as today from Go).
  What changes is the cost of a **refused** one, which drops to almost zero.

## 3. What does NOT change

This bounds the work and protects the other consumers:

- **The current TCP protocol and the Go client (`go/`)** stay, with no wire changes. Lambda
  backends do not go through HAProxy and keep using it.
- **The services that are not about admission:** locks (`0x02`/`0x03`), request log (`0x04`; D7
  later moves it to Genix),
  sysmetrics and the SSE bridge. They stay as they are and Go keeps calling them.
- **The MariaDB schema** and the four contracts in the README, *for the SPOE work*. D7 changes
  them later, as a separate stage.
- **The limiter's semantics:** windows, budgets, extra pool, activated month, 15-second flush.
  The SPOE agent is one more *front-end* of the same `RateLimiter`, not a second implementation.
- **A single active process** (a constraint of the limiter's version one). The SPOE agent lives
  inside the same process and shares the in-memory state.

## 4. Target architecture

```
client ──HTTP/3──▶ [Cloudflare, optional] ──▶ HAProxy
                                                │  headers ready
                                                │  SPOP over a Unix socket
                                                ▼
                                          Fareward (same process)
                                          ├─ SPOE front-end        ← new
                                          ├─ TCP 0x01 front-end    ← unchanged (Lambda)
                                          └─ RateLimiter::admit    ← shared core
                                                │  verdict in variables
                                                ▼
                                  HAProxy: deny 401/403/429/503  or  forward
                                                │  + identity headers
                                                ▼
                                               Go  (does not repeat the pre-handler frame)
```

Guiding principle: **one core, several adapters**. `RateLimiter::admit(Request) -> Decision`
is already the natural boundary (`src/limiter/quota.rs`). The SPOE adapter builds a `Request` the
same way the `0x01` frame decoder does today, and translates the `Decision` into variables.
No adapter may reach into the limiter's internals.

## 5. Decisions to make

Each comes with a recommendation; whoever implements it may change it, recording the reason.

### D1. Where route policy lives

Today Go decides, before the frame, everything the daemon does *not* know (see
`CREDIT_LIMITER_WALKTHROUGH.md` §3): which grants each route requires (`access_list.yml`), the
route number (`api_routes.generated.go`), the tariff (`APICPUCredits`), whether the extra pool is
allowed, and the special cases (user 1, `selfServiceRoutes`, `creditControlRoutes`, unmapped write
→ 403, more than four accesses → 500). With SPOE, that decision has to be available **before Go**.

**Decision:** the Go backend (Genix) **generates a TOML routes file** from the same sources it uses
today. The SPOE adapter loads it (not the core). HAProxy only sends method, path and size. The core
still knows no access names or routes; the policy lives in the adapter, just as it lives today in the
Go adapter (`core/fareward_api.go`).

Shape of the file:

```toml
version = "<hash of the sources>"   # exported as a metric; the parity test checks it

# The size steps are global per method, not per route.
[tariff.GET]
base_kib = 8
step_kib = 16

[tariff.POST]          # PUT is the same behaviour (TestPostAndPutAreIndistinguishable)
base_kib = 8
step_kib = 8

[[route]]
method       = "GET"
path         = "api/productos"   # exact match, no prefixes or parameters
route_id     = 103
slots        = [0x0139, 0x008B]  # packed grants: acceso_id << 2 | (nivel - 1); at most 4
base_credits = 2                 # 0 = not charged (creditControlRoutes)
step_credits = 1
```

Rules:

- **Exact match** on method + path. No prefixes, no parameters.
- **A request whose route is not in the file is refused.** There are no defaults: an unmapped GET,
  which Go lets through for free today, is refused as well. Shadow mode (phase 7) must confirm no
  legitimate GET lives outside the catalogue before enforcement.
- `base_credits = 0` means not charged. Rate limiting and authorization still apply.
- The generator **fails** (the file is never written) on: more than 4 slots; an entry with empty
  `slots` and `base_credits = 0` (an open route); sparse or zero slots.
- `selfServiceRoutes` are entries with empty `slots` and credits: a session is required, no access.
- **User 1** depends on the identity, not on the route: it stays as code in the adapter, not in the
  file.

**Hot reload.** Fareward watches the file's **directory** (inotify via the `notify` crate, or an
`mtime` poll every few seconds as a fallback). Genix writes a temp file and `rename`s it over the old
one, so a reader never sees half a file. On change, Fareward parses and validates the whole file and
swaps the table atomically (`ArcSwap`): in-flight requests finish on the old table, new ones use the
new one. **An invalid file keeps the previous table** and logs an error plus a metric. A missing file
at startup keeps the SPOE agent from starting; Fareward never runs the agent with no table.

**Non-negotiable requirement:** a single source of truth. The file is generated by the same tool
and in the same step as `api_routes.generated.go`, and there is a parity test (section 6, phase 3).

### D2. What happens to the GET top-up

A GET's charge is split in two: a base before the handler and a top-up based on the response size.
The top-up is only known after the handler runs.

**Decision:** the top-up **stays in Go**, over the current TCP protocol, also for requests that
arrived pre-admitted. SPOE covers only the pre-handler frame.

Considered and discarded: Genix puts the response size in a mandatory header and HAProxy charges it
from the SPOE `on-http-response` event. It is possible (Genix holds the whole body in memory before
writing headers), but:

- It adds a **synchronous** agent round trip on the response path of every GET. Today, on a VPS,
  Go charges the top-up in a goroutine and the response does not wait for it.
- It cannot measure a stream: its headers go out before its size exists.
- Lambda still needs the top-up from Go, so the charge would be implemented twice.

Consequences:

- The D5 headers carry `route_id` besides company and user: `settleGetResponseTopUp` needs it.
- **Streamed responses get charged** (today `!handlerResponse.StreamHandled` excludes them). Genix
  wraps the stream writer in a byte counter and settles the top-up when the stream closes.

### D3. What happens if the agent does not answer

The current Go client fails closed when the daemon is unavailable. **Recommendation: keep that.**
Agent error or timeout → HAProxy answers 503. Set a short `timeout processing`, on the order of
milliseconds, and measure it.

### D4. Transport

A **Unix socket** between HAProxy and Fareward, with file permissions restricted to HAProxy's user.
The daemon already knows how to listen on a Unix socket for its own protocol
(`fareward.unix_socket`); the SPOE agent uses a separate socket.

With access controlled by the filesystem, the SPOE channel does not need the nonce or the SipHash
tag of the TCP protocol. That authentication remains mandatory on the TCP port.

### D5. How Go learns that the request was already admitted

After a positive verdict, HAProxy adds headers carrying the identity (company, user), the
`route_id` (the GET top-up needs it, D2) and a "pre-admitted" marker. Before that it **deletes any header with those names sent by the client**.
Go only trusts them if the connection comes from HAProxy, over loopback or a Unix socket.

Consider having the agent sign those headers with `internal_apikey` under its own domain string, as
a defense against configuration mistakes (for example, Go exposed without HAProxy in front). It is
not strictly necessary if Go only listens locally.

### D6. Platform risk: the state of SPOE

The original SPOE implementation was marked deprecated in HAProxy 3.0 in order to rework it, and it
was rewritten in 3.1. However, `doc/SPOE.txt` on HAProxy's main branch still shows a deprecation
notice. **[verify]** the status in the HAProxy version that will be deployed, and ask on the
HAProxy mailing list, before moving past phase 0.

Mitigation by design: the SPOE adapter is thin and replaceable. If SPOE went away, the worst case
is falling back to the check from Go, which never stops working because the TCP protocol stays.

### D7. Database independence (later stage, separate from SPOE)

Today the daemon persists to MariaDB (`src/database.rs`, `mysql_async`): usage
(`credit_usage_company`, `credit_usage_user`), budgets (`company_credit_budget`), the request log
(`user_logs`, `request_errors`) and metrics (`server_metrics`). It also **reads** two inputs owned by
Genix: the grants (`users.accesos_computed`, `accesos_sub_computed`, `status`) and the budget
entitlement columns written by the panel.

**Scope decision:** Fareward stores the **credit system** (accumulated usage, budgets and the grants
the admission check needs) and the **server metrics**. It is not a request log. `user_logs`, `request_errors` and the error ids
belong to Genix's backend, which writes and reads them itself; the request log opcode (`0x04`) and
`src/reqlog/` leave the daemon.

**Decision:** Fareward becomes the **source of truth** for usage and budgets. Genix no longer reads
or writes those tables; it asks Fareward over an API. This changes the contract with Genix, which is
accepted.

**Store:** **fjall** (embedded LSM, pure Rust). Each table is a fjall partition ("keyspace" in fjall
3 **[verify]** against the version used).

**Step 1: ports, no migration.** Three traits, with MariaDB as one implementation:

| Port | Today | Notes |
|---|---|---|
| `LimiterStore` | Already a trait (`src/limiter/storage.rs`) | Usage + budgets. Split out the access read. |
| `AccessSource` | Inside `LimiterStore::load_user_access` | Grants and user status. |
| `MetricsSink` | `sysmetrics/writer.rs` uses the `Pool` directly | Extract the trait. |

A bounded refactor with no behavior change; the existing `MemoryStore` pattern covers all three.

**Step 2: the fjall backend**, with the layout below.

#### Encoding rules

- Pure binary, no text. Keys are **fixed-width big-endian**, so byte order is numeric order, and
  they start with `company_id`: everything of one company is one contiguous range.
- Signed integers in a key (`time_frame`) are stored with the sign bit flipped, so a negative never
  sorts after a positive.
- Every value starts with a `version: u8`, so a format change is detected instead of misread.

#### `usage_company`: usage per company

| Part | Field | Type | Bytes |
|---|---|---|---|
| Key | `company_id` | u32 BE | 4 |
| Key | `time_frame` | i32 BE, sign flipped | 4 |
| Value | `version` | u8 | 1 |
| Value | `rejected_10s` | u32: requests refused by the company's 10-second gate (D9) | 4 |
| Value | `rejected_1h` | u32: requests refused by the company's one-hour gate (D9) | 4 |
| Value | `rejected_no_funds` | u32: requests refused for lack of credits, day or month (D9) | 4 |
| Value | `used_credits` | the existing `credits_blob.rs` encoding, unchanged, to the end | variable |

#### `usage_user`: usage per user

| Part | Field | Type | Bytes |
|---|---|---|---|
| Key | `company_id` | u32 BE | 4 |
| Key | `user_id` | u32 BE | 4 |
| Key | `time_frame` | i32 BE, sign flipped | 4 |
| Value | `used_credits` | `credits_blob.rs` | variable |

Kept apart from `usage_company`, as today: a company read never walks every user's rows.

**What these two tables are:** the accumulated credits, not a per-request log. The limiter adds
each charge in memory and the flush (every `flush_interval`, 15 s by default) writes the absolute
totals of the dirty buckets. `time_frame` already encodes two granularities (`time_frame.rs`):
five-minute buckets (`100_000_000 + unix / 300`) and Lima business days (`200_000_000 + UnixDay`).
Both are positive and the prefix keeps them apart, so within one company (or one user) all
five-minute buckets form one contiguous range and all daily buckets another.

**[decide]** retention of the five-minute buckets: 288 per user per day, kept forever today. The
daily buckets are enough for history; the five-minute ones could expire after N days.

#### `budget`: one fixed 63-byte value per company

The two halves are written separately today so they do not overwrite each other; with Fareward as
the only writer they become one value.

| Part | Field | Type | Bytes |
|---|---|---|---|
| Key | `company_id` | u32 BE | 4 |
| Value | `version` | u8 | 1 |
| Value | `daily_cpu`, `daily_inference` | u32 each | 8 |
| Value | `budget_month_start_day` | i16 (UnixDay) | 2 |
| Value | `monthly_cpu_ceiling`, `monthly_inference_ceiling` | u32 each | 8 |
| Value | `last_set_cpu`, `last_set_inference` | u32 each | 8 |
| Value | `updated` | i32 (unix s) | 4 |
| Value | `usage_day_period` | i16 | 2 |
| Value | `day_cpu_used`, `day_inference_used` | u32 each | 8 |
| Value | `usage_month_start_day` | i16 | 2 |
| Value | `month_cpu_used`, `month_inference_used` | u32 each | 8 |
| Value | `day_extra_cpu_used`, `month_extra_cpu_used` | u32 each | 8 |
| Value | `usage_updated` | i32 | 4 |

u32 because that is already the persisted maximum (`CreditsOverflow` in `credits_blob.rs`).
`day_*_used`/`month_*_used` existed so Genix would not re-sum usage rows; with the read API they
could go, but they stay so the cold start does not change.

#### `grants`: access per user (replaces reading `users`)

| Part | Field | Type | Bytes |
|---|---|---|---|
| Key | `company_id` | u32 BE | 4 |
| Key | `user_id` | u32 BE | 4 |
| Value | `version` | u8 | 1 |
| Value | `status` | i8 | 1 |
| Value | `updated` | i32 (unix s) | 4 |
| Value | `n_grants` | u16 | 2 |
| Value | `grants` | u16 LE × n | 2n |
| Value | `sub_grants` | u16 LE × rest | 2m |

The grant lists keep the little-endian layout of `accesos_computed`/`accesos_sub_computed`, so
`decode_grants` is reused. `updated` allows incremental resyncs.

#### `server_metrics`: one sample window per slot

| Part | Field | Type | Bytes |
|---|---|---|---|
| Key | `date` | i16 BE, sign flipped (UnixDay) | 2 |
| Key | `slot` | i16 BE, sign flipped (position in the day) | 2 |
| Value | `version` | u8 | 1 |
| Value | `cpu_percent`, `mem_percent`, `disk_percent` | i16 each | 6 |
| Value | `net_rx_rate`, `net_tx_rate` | i16 each | 4 |
| Value | `backend_mem_mb`, `backend_cpu_percent` | i16 each | 4 |
| Value | `fareward_mem_mb`, `fareward_cpu_percent` | i16 each | 4 |
| Value | `db_mem_mb`, `db_cpu_percent` | i16 each | 4 |

The same fields and types as today's `MetricsSample` (`sysmetrics/mod.rs`), `NOT_MEASURED` sentinel
included: a fixed 23-byte value. `scylla_*` becomes `db_*`, which is what it measures. Not a
per-company table, so the key starts with the date: retention (`ttl_days`) deletes the oldest days
by prefix, a few hundred keys per day at most.

#### `meta`: the store's own state

| Key (u8) | Value |
|---|---|
| `1` schema version | u16 |
| `2` last full grants resync | i32 |

#### Per-partition settings

| Partition | Compression | Bloom filter | Why |
|---|---|---|---|
| `budget`, `grants` | none | yes | Point reads on the admission path; tiny values |
| `usage_company`, `usage_user` | lz4 | yes | Point and range reads |
| `server_metrics` | lz4 | no | Append by time, read by date range |
| `meta` | none | no | A handful of keys |

The 15-second flush writes `usage_company`, `usage_user` and `budget` in **one batch**, which fjall
applies atomically across partitions: a crash never leaves half a flush.

Consequences:

- **New protocol surface** (TCP protocol, authenticated like the rest, with Go client functions in
  `go/`):
  - *Write:* set a company's budget (the panel's "set current"), push a user's grants and status
    (replaces reading `users`; the access invalidation becomes the push itself).
  - *Read:* usage by company/user/route over a time range, a company's budget and remaining
    credit, and the server metrics over a date range.
- **Grants at cold start:** with no `users` table to read, Fareward persists the pushed grants in its
  own store, and Genix needs a full resync (all users of a company, or all companies) for the first
  start and for recovery. An unknown user stays a denial, as today.
- **Genix stops touching** `credit_usage_company`, `credit_usage_user`, `company_credit_budget` and
  `server_metrics`. The SaaS, credits and metrics panels move to the read API. `user_logs` and `request_errors` stay in Genix's
  database, written by Genix's backend.
- **Migration:** a one-off import from MariaDB into fjall, then a period where both are written and
  compared, then those three tables are dropped from the contract (README §"The tables it expects to
  already exist").
- **Durability and backups** are now Fareward's job: the store lives on the VPS's local disk, so it
  needs a backup/snapshot routine and a documented restore. The 15-second flush window of lost
  usage on a crash stays as it is today.
- **Order:** this goes after the SPOE work, or in parallel with it, but never mixed in the same
  change. Step 1 (ports) can start at any time; it does not depend on this decision.

### D8. `disableUserLimit`: rate limit by company only

**Why the company is the unit.** Genix is a free service where each `company_id` is one registered
customer, who creates N users. The users of a company are the same customer, so limiting them apart
protects nobody from anybody: a user who spends the company's quota spends their own customer's.

**Flag:** `rate_limit.disable_user_limit` (environment `RATE_LIMIT_DISABLE_USER_LIMIT`), global, off
by default. When on:

- **Off:** the user's cold load from storage (`ensure_subject` for the user: the daily row plus the
  last hour of five-minute rows), the user's `SubjectState` (10 s and 1 h buckets, day counter), the
  user's burst and hourly gates, the user's daily gate (`user_daily_share_pct` stops mattering), and
  `Scope::User` violations.
- **Unchanged:** every company gate, the extra pool, the monthly ceiling, and authorization (grants
  are per user and are not a rate limit).
- **Accounting stays:** `usage_user` keeps recording each user's accumulated credits.

**The per-user rows are summed at flush time.** The flush writes absolute totals, and today it is
`ensure_subject` that seeds the user's existing rows into memory first. Without that load, a restart
followed by a flush would overwrite the user's day with only what was charged since the restart. So
with the flag on, a user row is created **unseeded**: it accumulates from zero, and the flush that
writes it reads the stored row, writes `stored + accumulated`, and then folds the stored value into
the in-memory record so later flushes are plain absolute writes. Charges that land during that flush
stay dirty, as they do today (the version check in `mark_flushed`). The read moves off the admission
path into the flush, where with a local store it costs microseconds.

Requirement: **one flush at a time.** Two concurrent flushes of an unseeded row would add the stored
value twice. Today the periodic flush and the final one are already sequential (`main.rs`); a flush
mutex inside the limiter makes it a guarantee instead of a property of the caller.

What it saves: the per-user storage reads on every cold user and after every restart, and one
`SubjectState` per active user. The per-request saving in the hot path is small (hash lookups and
comparisons).

### D9. Company block cache and rejection counters

**Problem.** Once a company reaches a gate, every further request is refused, and today a refusal
stores nothing: no usage, no counter, no log (`server.rs:410` answers the 429 silently). An abuser
sending thousands of requests a minute is invisible, and each refusal still takes the company's
shard lock (`company_id % shards`), slowing every other company in the same shard.

Per-IP limits are **not** the answer: an IP can be shared (offices, NAT, mobile carriers), and one
abuser would block innocent customers behind it.

**Block cache, by company.** When a company gate refuses, the limiter records
`company_id → blocked_until` in a concurrent map **outside the shard locks**. Every request checks it
first: a blocked company is refused without taking the shard lock and without touching the limiter
state. The whole company is blocked, every one of its users, for the reason in D8: the company is the
customer.

| Gate that refused | `blocked_until` |
|---|---|
| 10-second burst | When the bucket has refilled enough for the refused request (monotonic clock) |
| One hour | The next clock hour: the hourly counter is a fixed clock hour, not a rolling one (wall clock) |
| Day | The next Lima business day (wall clock), **or** a budget mutation for that company |
| Month | Re-judged at the next Lima business day too (a shorter block is only conservative), **or** a budget mutation |

The hour, day and month are calendar windows, so their blocks lift on the wall clock even when it is
stepped; only the burst block runs on the monotonic clock.

**Status:** D8 and D9 are implemented on the current MariaDB store (`src/limiter/block.rs`,
`src/limiter/quota.rs`). The three counters need their columns in `credit_usage_company` (Genix
owns the schema).

Rules:

- The block is a cache of a verdict the limiter already reached, never a new policy: on expiry the
  next request goes through the normal path and is judged again.
- **Extra pool:** a day or month block does **not** apply to a read marked `extra_credits_allowed`,
  which may still be paid by the pool. Once the pool refuses too, marked reads are blocked until the
  next business day.
- A blocked request is refused with the same violation byte the gate produced, so the client sees no
  difference. Its order relative to authorization changes: a blocked company gets 429 even on a
  request that would have been 403. Acceptable: the company is over its limit either way.
- Map size is bounded by the number of companies; expired entries are removed lazily on read and on
  each flush.

**Rejection counters.** Three counters per company, kept in memory as atomics next to the block
entry, so a blocked request increments them without the shard lock. Each counts refusals by the gate
itself and by its block:

- `rejected_10s`: the 10-second burst gate. A sign of **abuse**.
- `rejected_1h`: the one-hour gate. A sign of **abuse**.
- `rejected_no_funds`: the daily entitlement, the monthly ceiling, and a marked read the extra pool
  could not pay. A sign of **lack of credits**, not abuse: a commercial signal (the company needs a
  bigger budget), kept apart so it never inflates the abuse figures.

They are flushed with the usage, every `flush_interval`, into the same `usage_company` row
(`time_frame`: the current five-minute frame and the current day, like the credits), as three
columns of its value (D7). Accumulated counts, not a request log.

With `disable_user_limit` off, a `Scope::User` refusal neither blocks the company nor counts here:
these counters describe the company.

### As implemented: where the code departs from D1–D5

Recorded here, as section 5 asks, so the decisions above stay readable as they were taken.

- **The generator is the backend, at startup** (`genix/backend/fareward_routes.go`), not a separate
  generation step: it resolves every served handler through the very functions the gate calls
  (`resolveRouteAccess`, `chargedMethodFor`), so there is nothing to drift and no golden file. The
  parity test became `TestFarewardRouteTableCoversEveryHandler` plus the tariff test against
  `APICPUCredits`. The file is written only when `[fareward].routes_file` is set, and never on Lambda.
- **The file carries more than D1 listed:** a `[policy]` section (API prefixes, SaaS company,
  access-exempt user 1, operator company), and per route `public`, `saas_only` and `deny`. `deny`
  (an unmapped write, 403; too many accesses, 500) is applied after the identity is known, because
  user 1 passes it in the backend; a denied route therefore carries its tariff too.
- **Statuses match the backend, not section 7's guess:** a bad or missing token, a SaaS-only route
  from another company and an unknown route are all **400** (the backend's default error status).
  Missing or inactive user 401, no access 403, credits 429, limiter unavailable 503; edge-only, 411
  (charged write with no Content-Length) and 413 (a charge that overflows 16 bits).
- **The operator company** (`TolerateCreditRefusal`) is replayed: a credit refusal retries as an
  access-only request, as the backend does.
- **D5 adds the grant:** `x-fareward-grant` carries the granted slots and sub-accesses (hex of the
  TCP reply's tail), so the backend applies sub-accesses without asking again. The backend believes
  the headers only with `[fareward].trust_edge_headers = true`, from a loopback or Unix peer, and only
  when company, user and route match what it derives itself; otherwise it runs its own gate. A grant
  that does not decode fails closed (503): the edge has already charged.
- **HAProxy:** the SPOE backend is `mode spop` (3.1+). Verified end to end against HAProxy 3.2.
  HAProxy also sets `x-real-ip`, which the backend reads the caller's address from.
- **Polling, not inotify:** the watcher compares mtime and size every `spoe.routes_poll_ms`; the
  swap is an `RwLock<Arc<RouteTable>>`.

Status: phases 1–6 are implemented and tested (unit, integration over a real socket, and a real
HAProxy 3.2 run). Phase 0's measurements (latency, body-not-read over HTTP/2 and HTTP/3, Cloudflare)
and phase 7 (shadow on real traffic) need the production environment. D7 is not started: it is its
own change, after this one is committed.

## 6. Phases

Each phase ends in something verifiable. Do not move on without meeting its criteria.

### Phase 0: Validation (spike)

Goal: check, in the real environment, the assumptions the whole plan depends on.

- Confirm the status of SPOE in the chosen HAProxy version (D6).
- A minimal agent that returns a fixed verdict over a Unix socket.
- Measure the latency added per request (p50/p99) with the agent in the path.
- **Prove the body is not read:** upload a large file with an invalid token, over HTTP/3 and
  HTTP/2, and confirm with counters or a capture that only roughly the initial window arrives.
- Check the behavior with Cloudflare in front: the request body buffering mode must not be `Full`,
  or HAProxy only sees the headers once the body has been fully uploaded.

**Exit criterion:** acceptable latency, effective refusal before the body, SPOE viable.

### Phase 1: A core ready for two front-ends

- Confirm that `RateLimiter::admit` is the only entry point both adapters need.
- Add a **no-charge evaluation** (dry-run): same verdict, without deducting credits or marking
  records dirty. Phase 7 (shadow mode) needs it; without it, shadow mode would charge twice.
- Tests: same input → same verdict through the TCP front-end and through a direct core call.

### Phase 2: Identity

- The bridge already verifies the session token today (`bridge::auth::authenticate_user`: colbin +
  BLAKE2s tag keyed with `secret_phrase`). The README says the bridge shares nothing with the rest;
  to keep that principle, extract the verification into a common module used by both the bridge
  and the SPOE adapter.
- **Parity with Go's `CheckUser`** **[verify]**: what Go checks besides the signature (expiry, user
  status, the user-1 case). The agent must accept exactly the same tokens.
- **[verify]** that API requests carry the token in the same header and format the bridge uses.
- Tests with vectors generated from Go, following the `vectors/` pattern.

### Phase 3: Route policy (per D1)

- Genix generates the TOML routes file (D1) from `access_list.yml`, the generated routes and the
  tariff, in the same generation step it already uses, written with temp file + `rename`.
- The generator refuses the invalid cases from D1 (more than 4 slots, open routes, sparse slots).
- Fareward: loader, validation, hot reload with atomic swap, keep the previous table on an invalid
  file, and a metric with the loaded `version`.
- Unmapped routes are refused by the adapter, so an unmapped write can never produce a frame with
  empty slots.
- **Parity test:** Go exports a *golden* file with its resolution for a broad set of
  (method, path, size); the adapter must produce exactly the same. If they diverge, CI fails.
- Decide what to do with POST/PUT requests without `Content-Length` (optional in HTTP/3), since the
  tariff depends on size. Recommendation: refuse with 411 at the edge.

### Phase 4: SPOP front-end

- A new transport module, alongside `service/` and `bridge/`: Unix socket listener, SPOP codec,
  message → `Request` → `Decision` → variables translation.
- Startup and shutdown wired into `main.rs` with the same shutdown signal as the other services.
- Its own configuration section (socket path, routes file path, connection limits, frame size,
  timeouts), with environment-variable overrides like the rest.
- Explicit limits: maximum connections and messages in flight. The lesson from multiplexing in the
  TCP protocol applies here too.
- Metrics: latency per message, verdicts by type, errors, timeouts.
- Implementing SPOP in Rust probably means writing the codec; the protocol is documented in
  HAProxy's `doc/SPOE.txt`. Evaluate existing crates first **[verify]**.

### Phase 5: HAProxy configuration

Ship a reference configuration in the repo that includes:

- The SPOE filter on the frontend, on the event that precedes the `http-request` rules.
- Arguments sent: authorization header, method, path, `Content-Length` and, behind Cloudflare, the
  real client IP.
- The variable-to-response mapping (section 7) and the fail-closed rule (D3).
- Deleting incoming identity headers and adding our own (D5).
- A body size limit as a defense independent of the agent.
- No per-IP limits: an IP can be shared, and blocking it blocks innocent customers. Abuse is
  stopped per company by the block cache (D9).

### Phase 6: Go changes (Genix repository)

- If the request carries the pre-admitted marker and comes from HAProxy, **skip** the pre-handler
  frame and take the identity and `route_id` from the headers.
- The GET top-up stays in Go for every request, pre-admitted or not (D2).
- Charge streamed responses: count the bytes written and settle the top-up when the stream closes.
- Generate and publish the TOML routes file (phase 3).
- Keep unchanged: request log, locks and the whole Lambda path.
- Without the marker, the current behavior is untouched. This allows deploying Go before HAProxy.

### Phase 7: Gradual rollout

1. **Shadow:** the agent evaluates in dry-run and HAProxy only logs the verdict. Go keeps deciding
   as it does today. Compare both verdicts over a period of real traffic.
2. **Enforcement:** once the divergence rate is zero or explained, HAProxy starts refusing and Go
   stops sending the pre-handler frame for marked requests.
3. **Cleanup:** remove shadow mode and document the new flow in the README and in
   `CREDIT_LIMITER_WALKTHROUGH.md`.

## 7. Verdict-to-HTTP mapping

The intent is to **replicate exactly the mapping Go performs today** from the reply's `status` and
`detail`. The agent does not invent new codes: it exposes the verdict in variables and the HAProxy
configuration translates them. As a general reference: no valid identity → 401, no permission →
403, no quota → 429, agent or storage unavailable → 503 **[verify]** against the real mapping in Go.

## 8. Risks

| Risk | Mitigation |
|---|---|
| SPOE goes away or changes | Thin adapter; the TCP path from Go always remains as a fallback (D6) |
| Policy drift between Go and the agent | One generated source of truth + parity test in CI (phase 3) |
| Double charging during the transition | Dry-run in shadow mode; pre-admitted marker so Go does not repeat the frame |
| Spoofed identity headers | HAProxy deletes incoming ones; Go only trusts local connections (D5) |
| The agent becomes a single point of failure | Same process that is already critical today; explicit fail-closed and metrics |
| Cloudflare buffers the whole body | Check the buffering mode in phase 0 |
| A bad routes file refuses everything | Validate before swapping; keep the previous table; never start without one (D1) |
| Legitimate GETs outside the catalogue get refused | Measured in shadow mode before enforcement (D1, phase 7) |

## 9. Acceptance criteria

- A request with an invalid token or no quota is refused **without its body exceeding the initial
  window**, verified over HTTP/3 and HTTP/2.
- For the same traffic, the agent's and Go's verdicts match 100 % in shadow mode.
- No request is charged twice.
- The latency added by the agent stays within the budget defined in phase 0.
- The Lambda path and the services unrelated to admission do not change behavior.
- With the agent down, HAProxy answers 503 and lets no unverified request through.

## 10. Open questions

- ~~What exactly does Go's `CheckUser` check besides the token signature?~~ Nothing: no expiry, no
  status. Status is the limiter's question (401). The agent accepts exactly the same tokens.
- ~~How does Go currently determine the payload size for the POST/PUT tariff?~~ `len(body)`; the agent
  uses Content-Length, assumed equal.
- ~~Do API requests use the same token header and format as the bridge?~~ Yes:
  `Authorization: Bearer <token>`.
- D7: what is the backup routine for the fjall store, and where do the snapshots go?
- Does HAProxy replace Nginx or sit in front of it? If in front, make sure Nginx does not buffer the
  body again unnecessarily.
