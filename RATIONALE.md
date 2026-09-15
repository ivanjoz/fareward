## Six request shapes moved to colbin, and every frame is length-prefixed — `fareward:v11`

**Context** — Phase 3 of `PROTOCOL_SHAPES.md`. Six of the eight request payloads were fixed
layouts read by byte offset on the far side; the request log was the exception, and it was the only
hand-written variable-length parser on the port — three length idioms, a bounds check before each,
and seven error variants for the ways a peer can lie about a length.

**Decision** — `ChargeCredits`, `LockAcquire`, `LockRelease`, `LogRequest`, `MutateCompanyBudget`
and `InvalidateUserAccess` carry colbin messages, one numbered struct per shape with ids 1..16 so
both sides keep four-bit keys. Mirrored by `#[derive(Colbin)]` on the Rust side, field id for field
id. `ReserveSequence` and `SetSequence` stay hand-rolled, as instructed. Validation did **not** move
into the codec: `company_id > 0`, the route ceiling, the no-gaps slot rule and the empty-frame check
are protocol rules and stayed where they were.

Two things fell out that are worth naming separately:

- **Every opcode is length-prefixed now, and the fixed-width framing is gone.** A colbin payload
  varies in length, so all six needed a length header; the two sequence opcodes already had one.
  Nothing was left that a fixed width could describe, so `PayloadWidth`, `Opcode::fixed_frame_size`,
  `opcodeIsLengthPrefixed` and `buildFarewardLengthPrefixedFrame` were all deleted and one path
  replaced two on both sides. Each opcode now declares a `max_payload_size` instead, which is what
  bounds what an unauthenticated peer can make the daemon buffer.
- **The 65535 ms lease ceiling is gone.** `wait_ms` and `lease_ms` were `u16` because fifteen fixed
  bytes had room for no more. They are `u32` now and a short lease still costs two bytes, because a
  colbin integer costs what its value needs. §2.7 of `PROTOCOL_SHAPES.md` is closed rather than
  raised.

`DOMAIN` moved to `fareward:v11`. Backend and daemon cross this in one deploy.

**Rationale** — The request log is the whole case on its own: a parser that acts on a length from a
socket is the kind of code that has to be right every time, and it is now one `decode` call with
the two ceilings that are actually about request logs left behind it. The rest is smaller and still
worth it — an ungated charge is 12 bytes against 20 because the four empty access slots are not
written, a budget mutation naming one resource does not carry the other, and the wildcard
invalidation is the frame with no user field in it. The cost is two bytes of length header per
frame, which the charge and the budget repay several times over and the invalidation does not: 6
bytes fixed against 7 for a named user, 5 for the wildcard. That one is a wash, kept for uniformity
rather than for bytes.

The extra-credit flag came out of bit 15 of the route number in the same change. It rode there
because widening a fixed payload for one boolean was not worth it; with a codec it is a field that
costs one byte when true and nothing when false, and "is this route number clean" stops being a
question either side has to ask.

## colbin carries a slice at the root, and the Rust port had a list-element bug

**Context** — Adopting the rewritten colbin across the ORM turned up two things that were not
fareward's and had to be fixed in colbin before any of this could land.

**Decision** — Both fixed upstream in `github.com/ivanjoz/colbin`:

1. **A slice or map at the root is wrapped in a one-field envelope.** The new format encodes a
   struct and nothing else, but `genix-orm` marshals `[]AccesoGrantRecord` into a blob column and
   the previous format took it. A non-struct root is now written as a one-field message under key 0
   — no format change, no port to update, two bytes, and no copy.
2. **The Rust port closed a narrow list element like a keyed composite.** Any element body reaching
   255 bytes produced a message the crate itself refused, and an encoded size a byte off Go's. That
   is an ordinary request-log row with two errors in it, which is how it surfaced. Go already had
   the fix (`Writer.CloseElement`); the Rust side did not.

**Rationale** — The second one is why the cross-language vectors matter more than round-trip tests:
every Rust test passed against Rust's own encoder, and only a record built to the real ceilings
caught it. Go is the specification, so "what does Go write for this" is the question that settled
both.

## Every reply names its shape in byte 0, and `fareward:v10`

**Context** — A reply was `[correlation:u16][status:u8][detail:u16][extra_len:u8]`, and neither
`status` nor `detail` meant anything on its own: `status` was a five-bit credit-violation bitfield
for a charge, one enum for a lock, a different one for a budget, a third for a sequence, and `0xFF`
for "I could not answer" across all of them; `detail` was a lock generation, or a packed
eleven-bit authorization verdict, or zero. A client could not read a reply without first looking up
what it had asked, which also meant the daemon could not send a frame nobody asked for.

**Decision** — Byte 0 of a reply is a shape: eleven of them, each with a body of its own and a width
that follows from the name. `ReplyShape` and `Reply` in `service/protocol.rs` own the layout; the
Go client mirrors them in `connection.go` and every call site switches on the shape instead of
decoding a shared byte. `0x80` and up is a push range. `DOMAIN` moved to `fareward:v10`, so a peer
still on `:v9` fails at the first frame rather than reading a shape byte as half a correlation.

**Rationale** — The byte is free: it replaces the `extra_len` byte every reply used to carry,
because a shape that knows its own width does not need to state one. Only `ChargeGranted` varies, so
only it still counts its sub bytes. Every other reply came out the same size or smaller — a plain
acknowledgement went from six bytes to three, a sequence value from fourteen to eleven.

What it buys beyond size is that an outcome now has a name. `Ack` and `LockGranted` were the same
`status = 0`; a refused release and a refused acquire shared an enum with a success value in it; and
`0xFF` was a sentinel inside a field that also carried verdicts, which is why the charge decoder had
to reject it by checking that its top bits were set. All of that is gone, and adding an outcome is
now a shape rather than a hunt for space in a field that already means four things.

## `LockLost`: the daemon says a lease expired instead of the client guessing

**Context** — `Lock.Lost()` was a local timer started when the grant arrived, which is a round trip
after the daemon started counting its lease. Its own doc comment called it advisory. The daemon knew
exactly when a hold expired — `drop_expired` logged it — and had no way to say so, because every
frame it could write had to answer a request.

**Decision** — `drop_expired` returns the keys it dropped and the reader loop pushes
`LockLost { action, identifier }` for each, correlation zero. The Go reader routes frames at or
above `0x80` to `handlePush` before the pending map, looks the lock up in a per-connection registry
of what this process holds, and closes its `lost` channel. The local timer stays as the backstop for
the case where no push can arrive, which is the same case a dead connection already covered.

**Rationale** — The push exists because the shape byte made it cheap: a frame with no correlation is
just a shape the reader recognises, and a client that meets a push it does not know can skip it
because a push states its own width. The registry is the only new state, and it is the size of what
this process actually holds — filed when a grant arrives, dropped on release.

It is still advisory under a partition, and work inside a lock still has to be safe to run twice.
What changed is the common case: a slow critical section against a live daemon is now *reported* at
the daemon's own deadline rather than inferred at a later one.

## The sequence payloads read through a cursor, and the Go client pins them

**Context** — `parse_reserve` and `parse_set` counted offsets by hand, and the rule that makes them
work — the scalar leads so the counter name can be the rest of the frame, needing no length of its
own — lived in a comment. Nothing enforced it, and the two sides had no shared vector for either
frame.

**Decision** — A small `Cursor` in `sequence/protocol.rs`: `u32`, `i64`, and `rest`. `rest` is that
rule, stated once in code. Both parsers use it, and a new test parses the exact bytes
`ReserveSequence` and `SetSequence` put on the wire, pasted from the Go client.

**Rationale** — The cursor was measured at 1.1x the hand-rolled parser in Rust (the reads inline
away) and it removes the last literal offsets from the two shapes that stay hand-rolled. The vector
is the more important half: it is the mechanism that catches drift, and a comment saying "mirrors
the Rust constant" is not.

## Three decisions taken without asking, while the wire work ran unsupervised

**Context** — The per-shape codec split was decided: `LockGranted`, `LockRefused`, `ReserveSequence`
and `SetSequence` hand-rolled, everything else colbin. Three things the split did not say came up
during implementation.

**Decision** — (1) `SequenceValue`, the reply shared by the two hand-rolled sequence requests, is
hand-rolled too: one `i64` behind a shape byte, in the same family as the requests it answers.
(2) `ChargeGranted` keeps its hand-rolled body for now — two masks and a counted run of sub bytes —
because it belongs to the colbin phase that is blocked, and a half-moved shape is worse than either
end state. (3) The lock integration suite resolves the shape to an outcome code in one helper
(`outcome_code`) rather than restating shapes across fifty assertions, and two new tests assert the
shapes directly instead.

**Rationale** — Each is reversible in one place, and each is flagged where a reader will meet it:
(1) in `PROTOCOL_SHAPES.md` §10.1, (2) in §7 Phase 3, (3) in the helper's own comment. The
alternative for (3) would have been churn without coverage — those fifty assertions are about lock
behaviour, not byte layout, and `outcome_code` would have been the thing under test either way.

## colbin cannot carry the frames yet, because here it is a database format

**Context** — The plan's Phase 3 moves six request shapes and one reply onto colbin, which the
current colbin earns: re-measured on 2026-09-13 it is 4x faster than its previous self on a charge
and 22x–24x on the request log, at 3.5x–8.4x of the hand-rolled encoders rather than 35x–120x.

**Decision** — Phase 3 is not started, and `fareward/go/go.mod` keeps its zero dependencies. Phases
1, 2 and 4 — which need none of it — shipped instead.

**Rationale** — colbin in this project is not only a wire codec. `genix-orm/scylla/reflect_accessors.go`
and `converter.go` marshal struct fields into blob columns, `dynamo/client.go` does the same for
DynamoDB, `cloud/company_config_blob.go` seals the company config with it, and `security/login.go`
writes the session token. The rewritten colbin says in its own commit message that the format "is
not compatible" — and because the backend imports `fareward/go`, the two share one module version.
Adopting it for frames therefore means re-encoding every colbin blob already in ScyllaDB.

That is a data migration with a deploy ordering across three implementations of the session token
(Go writer, Rust reader, browser reader), not a wire change, and it is not something to start while
nobody is watching. The daemon's own `bridge/token.rs` also will not compile against the new crate —
`Kind`, `Schema`, `decode_one` and `Value` are all gone — so Phase 0 is a project of its own.

## `kv16` lands as an unused module, with continued sizes and three departures from the sketch

**Context** — The wire review in `PROTOCOL_SHAPES.md` measured colbin at 10x-120x the hand-rolled
encoders on this port and recommended a cursor instead, which buys the ordering but none of the
bytes. `kv16` is the third option: a byte-aligned `[key][value]` codec for records of at most sixteen
primitive fields, in `go/kv16` and `src/kv16.rs`, pinned together by cross-language vectors and
**carried by no frame** — `lib.rs` declares the module and nothing calls it.

**Decision** — Sizes are continued rather than capped: a header holds a size's low bits and a flag,
and LEB128 bytes carry whatever is above them, so no string, array or element has a ceiling. Three
departures from the sketch it was drawn from, each recorded in `KV16_DRAFT.md` §2 with its numbers.
The integer array header spends two bits on the element width and eight on the count, where the
sketch drew one and nine. Integer size code 6, which was unassigned, now means "no content bytes, the
magnitude is one", which makes a true bool a single byte. And the writer checks nothing at all — not
the key, not the size — so it has no error and no `Err` method.

**Rationale** — The width is the one place this knowingly diverges, and it is one-way: the sketch's
array header and this one are both sixteen bits and the bit that means "wide" in one is a count bit
in the other, so supporting both is not an option. Two widths cannot serve both a `[]uint16` of
packed grants and a `[]int32` of error ids without one of them wasting half its bytes, and the count
bit it costs stopped mattering once counts continue. The writer's missing checks are the same
principle in two places — *the reader defends against the network, the writer trusts its own
program*: a key is a constant of the record definition rather than data, and checking it once per
field measured 8 ns of a 25 ns ten-field encode. The cost is that a key above fifteen writes a record
nothing can read back, so `doc.go` prescribes a compile-time assertion where the key constants live.
The reader keeps every bound, and gained two the writer does not need: a continuation run past nine
bytes, or one describing more than an `int` holds, is refused rather than wrapped into a small size
whose bounds check would then pass.

The module ships unused because which frames should move to it, if any, is the open question
`KV16_DRAFT.md` §7 puts to review; landing the codec separately from that decision is what lets the
decision be made against real numbers instead of a proposal.

## The counter bind is pinned by a serialization test, and only the sequence log prints its chain

**Context** — `ScyllaSequenceStore::bump` bound the delta as a bare `i64` against a `counter`
column. The driver type-checks binds before a statement leaves the process and accepts `i64` for
`bigint` only, so every reservation failed at serialization — the sequence service had never
allocated an id against a real table. Two things hid it. The adapter has no test: every test here
substitutes an in-memory `SequenceStore`, exactly as the trait's own comment says it is for. And
the failure was unreadable — `warn!(error = %reserve_error)` prints an `anyhow::Error` with
`Display`, which is the outermost `.context()` and nothing below it, so the log said "counter
update failed" and dropped the driver's explanation.

**Decision** — Two narrow ones beyond the fix itself. The bind is pinned by a unit test that
type-checks `Counter` and a bare `i64` against `ColumnType::Native(NativeType::Counter)` directly,
with no cluster. And `{:#}` replaces `%` at the two sequence log sites only, not at the ~20 others
that log an `anyhow::Error` the same way.

**Rationale** — A cluster-backed integration test would catch more, but it would be the first test
here to need a live ScyllaDB, and that is a decision about how this repo is tested rather than a
fix for this bug; the serialization test catches this whole class — every bind-type mismatch — for
the cost of no I/O at all. The logging was left alone elsewhere for the same reason: the request-log
and server-metrics writers swallow their causes identically, and converting them is a sweep through
the daemon's logging, not part of repairing the allocator. The cost of both choices is that the
next such bug in another store is still invisible until someone widens the pattern.

## Moving a counter is an opcode, because a block outlives the value it came from

**Context** — `ResetCounter` in genix-orm realigns a counter with the rows a partition actually
holds, and `RestoreBackup` calls it per table from a live HTTP handler. Once the daemon allocates in
blocks, that write is no longer a peer of the daemon's own: the daemon may be serving ids from a
range it derived from the value being erased. It keeps issuing them, so the durable counter stops
bounding what has been handed out, and the next block it claims overlaps what the abandoned one
already gave away. Waiting for the daemon to be "idle" is not a mitigation — a block is only
re-derived when it is exhausted, so an idle counter is precisely one holding a stale block forever.

**Decision** — Opcode `0x08 SET_SEQUENCE`: absolute `i64` plus counter name, same length-prefixed
shape as a reservation. The daemon takes the same per-name lock, applies the delta the counter
column requires, and marks its in-memory block spent in the same critical section. It answers with
the value it replaced. genix-orm gained a paired `SetCounterValue` hook that `ResetCounter` uses
when one is installed, and Genix installs both hooks together in `db/autoincrement.go`.

**Rationale** — Dropping the block is the actual fix; moving the counter is the easy half. Doing
both under one lock is what makes them atomic with respect to an in-flight reservation, and no
amount of care on the client side could have achieved that from outside the daemon. Costs: the
abandoned block's unused tail is burned on every reset, which is the same gap a restart produces and
just as harmless; and the two hooks are now a pair that must be installed together, since an
allocator that reserves ranges but does not own the resets is worse than either extreme. The reply
carries the previous value because after a destructive repair that figure exists nowhere else, and
that is also why the client uses `requestOnce` — a retry would report the value the first attempt
had already written.

## Sequence reservations claim blocks up front and the daemon owns the row

**Context** — The reservation had to be durable and safe against concurrent callers. Cassandra
counters make an increment atomic but will not report the result of your own increment, so any
allocator built on them has to read separately — which is exactly the race that moved this here.
Two shapes were available: keep the `counter` column and make one process the only writer, or
migrate `sequences.current_value` to a bigint and reserve with an LWT compare-and-set.

**Decision** — Hi-lo blocks over the existing `counter` column. Under a per-name mutex the daemon
bumps the durable counter by a whole block, reads back where that landed, owns `(V-block, V]`, and
serves from memory until it is spent. `block_size` defaults to 64. A counter found non-positive is
repaired to restart at 1, mirroring `nextCounterRange` in genix-orm's `scylla/main.go`.

**Rationale** — No schema migration of a live table and no Paxos on the write path, and the
read-back is sound because nothing else writes the row. Two costs, both real. The daemon must be
the *only* writer — a client still on the ORM's direct path would read a value the daemon is about
to claim — which is why Genix wires the ORM to the daemon unconditionally rather than behind a
setting. And a restart burns each live block's tail; `block_size` stays small because
`updated_version` packs into a
delta-view digit slot as narrow as 10⁸ per partition, so that headroom is not free. Re-deriving the
range from the durable value on every block rather than caching one at startup is what keeps a
counter repaired underneath the daemon (`ResetCounter`) from needing a restart to be seen.

## `RESERVE_SEQUENCE` carries the counter name as a string, not a hash

**Context** — Every other opcode identifies its subject with fixed-width integers, and the lock
service in particular takes an opaque `(action u16, identifier i64)` the daemon never interprets.
The obvious parallel was to SipHash the counter name into a `u64` and keep the frame fixed-width;
the crate already has SipHash for the frame tags.

**Decision** — The name travels verbatim as length-prefixed UTF-8, capped at 128 bytes, making
`0x07` the second length-prefixed opcode and the first that is also answered.

**Rationale** — The daemon does not merely route on this value, it writes it into a `sequences` row
key that the ORM, `deploy.go`'s `ResetCounter` and a person at a CQL prompt all address by that same
name. A hash would have forced either a second key space nothing else can read, or a name the
daemon does not have. What it costs is a variable-width frame and a 128-byte ceiling that closes the
connection when exceeded — the same bound, and the same reason, as the request log's.

## A refused reservation fails the write instead of falling back

**Context** — Every other client-side operation here has a fallback: a charge that gets no answer
proceeds, a lock that cannot be taken lets each call site decide. A reservation could likewise have
fallen back to the ORM's own `GetCounter` whenever the daemon was unreachable, which would keep
inserts working through a daemon restart.

**Decision** — `ReserveCounterRange` returns its error verbatim and genix-orm propagates it; there
is no fallback path. `ReserveSequence` also rejects a success carrying no tail, a short tail, or a
non-positive value.

**Rationale** — The fallback is the failure. The daemon claims ranges of a counter in advance, so
the direct path would read a value the daemon already considers its own and hand out ids inside that
range — the fallback would mint duplicate primary keys precisely when it fired. A failed insert is
recoverable and visible; a silently overwritten record is neither. The extra reply validation is the
same reasoning applied to a daemon that disagrees with the client about the wire.

## The operator company is exempt from the refusal, not from the charge

**Context** — `CreditExemptCompanyID` implemented the operator exemption by zeroing `cpuCredits`
and `inferenceCredits` inside `chargeConfiguredCredits`, and returning before sending a frame at all
when the route required no access. The daemon therefore never saw a charge for company 1: no
`credit_usage_user` / `credit_usage_company` row was ever written, `company_credit_budget.day_cpu_used`
stayed at 0, and the whole Créditos panel read zero for the operator with nothing to explain it.
The requirement is both halves: meter it, never block it.

**Decision** — Renamed to `OperatorCompanyID` and the zeroing is gone; the operator's frames carry
real credits and are charged like any tenant's. `TolerateCreditRefusal(companyID, err)` is the new
seam: true for the operator on anything that is not an `AccessDenied`. The API path applies it in
`enforceAccessAndCredits`, `ChargeInferenceUsage` applies it to itself. The one bypass left inside
`chargeConfiguredCredits` is a missing daemon, and only for a frame carrying no required access.

**Rationale** — Doing it in the daemon instead (skip the quota gates for one company ID, keep
`increment_usage`) would have meant a Rust change, a second place that has to know which company is
the operator, and giving up the property that the operator still gets in when the daemon is down —
which is the reason the exemption exists. Keeping it client-side costs one thing: a refused frame
returns no `AccessGrant`, so tolerating it needs a follow-up authorize-only frame to recover the
grant, or the operator's sub-accesses would silently blank out at exactly the moment its budget ran
out. That second frame is safe by construction — `exceeds(current, 0, limit)` is `current > limit`,
and since a refusal charges nothing the accumulated usage never passes the ceiling — so a
zero-credit frame can never itself be refused on quota. The cost of leaving "a refusal charges
nothing" alone: the specific request that got tolerated is not counted. That is deliberate, so the
usage reports keep meaning "what the daemon actually admitted".

## The `:v9` reply frame carries a length-prefixed tail on every opcode

**Context** — Sub-accesses meant the charge reply had to carry more than a verdict: per required
slot, the sub-access bytes that slot holds. The reply was a fixed 5 bytes
(`[correlation:u16][status:u8][detail:u16]`), one buffer type all the way down to the
`mpsc::Sender<[u8; REPLY_SIZE]>` the connection writer reads from. A variable tail had to go
somewhere, and the alternatives were a second opcode-specific frame shape or widening `detail`.

**Decision** — One shape for every reply: `[correlation:u16][status:u8][detail:u16][extra_len:u8]`
plus `extra_len` bytes. Locks, budget mutations and charges that requested no authorization pay one
byte of `extra_len = 0` and keep their exact `status`/`detail` meaning — locks still carry their
generation in `detail`, which is why `detail` is a `u16` at all. On a charge, `detail` bits 0..2 are
the verdict, 3..6 the granted-slot mask and 7..10 the has-subs mask, and the tail is those slots'
sub-byte runs in ascending slot order, capped at 8 bytes. `DOMAIN` went `fareward:v8` →
`fareward:v9`; SipHash-2-4 itself is unchanged.

**Rationale** — A per-opcode frame shape puts the length in the reader's head instead of in the
bytes: the client would have to know which opcode a correlation id belongs to before it can know how
many bytes to consume, and getting that wrong desynchronizes every later reply on the connection
rather than failing one. `extra_len` costs one byte on the replies that have nothing to say and buys
a reader that can always skip what it does not understand. Bumping only the domain separator is what
makes a mixed backend/daemon pair fail at the *first* frame, loudly, instead of misparsing the new
layout — which is also the cost: backend and daemon must deploy together.

**The tail is copied verbatim out of the cached blob.** The daemon re-encodes nothing and still
knows nothing about what a sub-access means: it holds no copy of `access.toml`, so "id 1 means all"
is expanded in Go and in TypeScript, and this side only reports which slots contributed bytes.
Re-encoding would have required it to parse the mask, which is exactly the knowledge it is
deliberately without — and `accesos_sub_computed` runs are already self-terminating on their `MORE`
bit, so there is nothing to reframe.

## SipHash-2-4 for the internal tags, keyed BLAKE2s-128 for the session token

**Context** — Three relationships were authenticated with HMAC-SHA256 and none of them wanted a
256-bit digest. The raw-TCP frame tag threw away 24 of its 32 bytes on every frame; the browser
session token's `Hash` was a `u64` and took the first eight bytes of a digest; only the bridge's
`X-Bridge-Auth` header carried the whole thing. All three are short, keyed, secret-only
authentications of a few dozen bytes — the case a Merkle–Damgård hash with an ipad/opad wrapper
suits least. But they are not the same *kind* of secret, which is what decided the outcome.

**Decision** — Two primitives, split by who holds the credential.

`src/siphash.rs` and `go/siphash/` implement SipHash-2-4 incrementally, used for the two internal
tags: `fareward:v8` for the frame tag and `sse-bridge:v2` for the service header, both 64-bit, keyed
by `SHA-256(secret)[..16]`. The session token instead uses **keyed BLAKE2s-128** under
`usrToken:v3`, keyed by the full `SHA-256(secret_phrase)` — 32 bytes, exactly BLAKE2s' maximum. Its
`Hash` field widened from `uint64` to 16 bytes, so `core.UsuarioToken` and the Rust `UserToken`
carry `[]byte`/`[u8; 16]` and the colbin field became `Kind::Bytes`. The `hmac` crate is gone;
`sha2` stays for key derivation. `backend/core/usuario-accesos.go` and `backend/agent/bridge.go` are
the mirrors in the parent repository and moved in the same change.

**Rationale** — 64 bits is right for the internal tags and wrong for the token. The frame tag and
the service header are verified by exactly one rate-limited peer on a loopback or private path, and
the header additionally expires in 300 s; blind forgery at 2^-64 per attempt is not a threat there,
and both were already 64-bit on the wire. The session token is the opposite: a long-lived bearer
credential held by an untrusted party, carrying no random component — company, user, `created` and
username are all guessable — so the tag is not integrity protection over a secret, it *is* the
credential, and its width is the session's entire strength. 64 bits sat exactly on the floor NIST
sets for session secrets, below what every mainstream signed-token format uses. Keyed BLAKE2s-128 is
a purpose-built 128-bit MAC rather than a 256-bit digest truncated to fit; `x/crypto` refuses to
construct `New128` without a key for precisely this reason, and RustCrypto's `Blake2sMac<U16>`
agrees with it byte for byte — pinned in `src/bridge/auth.rs` against `x/crypto`'s own `hashes128`
table, since BLAKE2 folds digest and key length into its parameter block and a mismatch there would
be invisible until every browser was rejected.

SipHash is hand-written on both sides rather than taken from a crate: `go/` is a stdlib-only module
by policy, so one side had to be written here anyway, and two implementations that must agree are
easier to keep honest when they read the same way. Each is pinned against the 64 reference vectors
from the SipHash paper. BLAKE2s is *not* hand-written — it is the one tag a user holds, so both
sides use a vetted library. Widening the token also closed a latent hazard: colbin omits a
zero-valued field, so a token issued with an empty `Hash` carries no hash at all, and the decoder
now refuses it rather than reading sixteen zeros into the comparison.

The costs, accepted: all three domain bumps are breaking at once, so the daemon and the backend must
deploy together and every live browser session logs in again; the token grew 8 bytes; and the
backend gained `golang.org/x/crypto` as a direct dependency.

## The crate, the config section and the systemd units all take the fareward name

**Context** — This code moved into its own repository, `github.com/ivanjoz/fareward`, but every
name it exposed still said `server_utils`: the crate was `genix-server-utils`, the daemon read a
`[server_utils]` TOML section, its env overrides were `SERVER_UTILS_*`, and it installed
`genix-server-utils.service`. One component answered to two names depending on which surface you
looked at.

**Decision** — Everything renamed to `fareward`: crate and binary, the TOML section and its keys,
the `FAREWARD_*` env vars, the `RUST_LOG` target, the systemd unit triplet, and the release assets
(`fareward_linux_{amd64,arm64}`). The daemon passed through an interim `auth-limiter` name between
`server_utils` and this one, so a host installed at either point answers to a name this repository
no longer uses. A first pass held two contracts back — the wire domain and the metrics columns —
on the grounds that neither is really a *name*. Both were taken in a second pass, because a name
that survives only on the wire and in the schema is exactly the kind that outlives everyone who
remembers why it is there:

- `DOMAIN` in `src/service/auth.rs` is now `b"fareward:v7"`, mirrored byte for byte in
  `backend/core/fareward/connection.go`. Renaming it is not a frame-format change, but it
  invalidates every tag a peer still signing `genix-server-utils:v6` produces — so it spends a
  version bump rather than pretending not to. That is what the bump buys: the skew fails the first
  frame's tag loudly instead of leaving two incompatible protocols both calling themselves `:v6`.
  Backend and daemon must cross this boundary in a single deploy.
- The metrics columns are now `fareward_mem_mb` / `fareward_cpu_percent` in
  `src/sysmetrics/writer.rs`, matching the Go fields that define them. This is a schema change on a
  table that already holds rows. `genix-orm` adds missing columns and never drops them, so a
  deployed table gains the new pair and keeps the old one until its rows expire under the table's
  TTL; nothing back-fills, so the Server Panel reads the sentinel for windows written before the
  deploy and real values after it. Ordering is not a constraint: `ensure_prepared` retries on a
  one-minute interval, so a daemon started before the backend's schema deploy heals on its own.

**Rationale** — A single name makes the daemon greppable across four languages, and the two
exceptions were the half that made grepping unreliable — they were the names you found only by
already knowing them. The cost is a breaking deploy on three fronts rather than one: an installed
host keeps running whichever unit it was given — `auth-limiter.service` or, older still,
`genix-server-utils.service` — until `configure_fareward.py` is re-run; any `config.toml` whose
section is `[auth_limiter]` or `[server_utils]` rather than `[fareward]` stops being read; and a
backend and daemon that do not cross the `:v7` boundary together fail every frame. That was
accepted deliberately for a pre-alpha project rather than carrying three sets of aliases.

## The Go client moves into this repository as its own module

**Context** — The client the Genix backend used to reach this daemon lived in
`genix/backend/core/fareward/`: ten files, ~1600 lines of implementation plus ~930 of tests,
importing **only the Go standard library** — no `app/*`, no third party. An earlier refactor had
already pushed it out of `core` to break an import cycle, which left it accidentally portable. Two
consequences followed from where it sat. A wire change meant editing two repositories and hoping
they shipped together; the `:v6` → `:v7` bump had to touch the domain string, the Rust vectors and
the Go vectors that pin them across a repository boundary. And a backend that was not Genix had no
client at all — only `src/service/` to read a protocol out of.

**Decision** — `go/`, a module of its own: `github.com/ivanjoz/fareward/go`, package `fareward`.
The move is verbatim; no signature changed. Genix depends on it with
`replace github.com/ivanjoz/fareward/go => ../fareward/go`, the same pattern `genix-orm` and
`facturago` already use, so what is checked out is what compiles. What stayed behind in Genix is
`core/fareward_api.go`, 156 lines of adapter: type aliases that keep call sites saying `core.X`,
and the three methods that take `*HandlerArgs` and return `HandlerResponse` — `LockError.Response`,
`MakeCreditRateLimitResponse`, `MakeAccessDeniedResponse`. Those are HTTP policy and belong to the
backend.

**Rationale** — The wire protocol and its reference implementation now live in one commit. That is
the whole argument: a `DOMAIN` change fails `cargo test` and `go test` in the same repository,
rather than passing here and breaking a consumer later. It also answers the portability question
the README's backend contract raises — a Go backend imports this instead of porting, and a port to
another language reads `go/connection.go`, which is the protocol seen from the caller's side.

Replaced rather than version-pinned deliberately. Resolving the client from the module proxy would
let a backend compile against a client whose `fareward:vN` no longer matches the daemon checked out
beside it, which is exactly the failure the version suffix exists to make loud.

The module keeps a hard rule: **standard library only**. It is the one piece of this system a
backend links into its own binary, so its dependency list becomes somebody else's transitive
dependency list. There is no test-only dependency either — the cross-language vectors are literal
byte arrays.

The cost is a second `go.mod` in a repository whose primary artifact is a Rust binary, and a
`replace` that Genix must carry. `vectors/` had already set that precedent for its own reasons.

## Decode the session token with the colbin crate instead of transcribing the format

**Context** — `src/bridge/token.rs` hand-wrote a colbin decoder: 577 lines mirroring the format's
`format.go`, bitstream and `typeinfo.go` to read exactly one struct, `core.UsuarioToken`. It was
pinned by vectors generated from Go, and it had already gone silently wrong. It targets
`formatVersion 0x01`, whose integer column was a frame-of-reference base plus fixed-width deltas and
whose strings were raw UTF-8; colbin v0.1.0 — which `backend/go.mod` pins — writes the `varint` array
codec and `packed5` frames, and routes every single-record message through **compact mode**. The
token the backend issues now arrives as 27 bytes whose first byte is `0x43`, bit 0 set, where this
decoder expected `0x01` and a columnar layout. Every browser SSE connection would have been rejected
with `MalformedSessionToken`, and the three test suites that pinned the old bytes were all pinning
a message the backend no longer writes.

**Decision** — Depend on `colbin`, a Rust decoder now published out of the repository that defines
the format (`github.com/ivanjoz/colbin`, `rust/`), pinned by `rev`. `token.rs` keeps only what is
genuinely this bridge's: `UserToken`, the five-field layout and the ids it implies,
`decode_session_token` over `colbin::decode_one`, `decode_session_base64`, and the channel token,
which is a separate custom format and is untouched. 577 lines down to 416, of which the channel
token and its cross-language vectors are the larger half; `TokenError`'s four colbin-internal
variants collapse into one `#[from] colbin::Error`. `fareward/vectors` is a small standalone Go
module that prints the session-token vectors the tests assert, so regenerating them after a format
change is a command rather than an archaeology exercise.

**Rationale** — The failure above is the argument: the format's rules lived in one repository and a
partial transcription of them lived here, with nothing but a code review between them, and the
transcription fell three format versions behind without anything reporting it. A decoder in the repo
that defines the format sits next to the codecs it mirrors and next to a corpus generated from them,
which CI regenerates and diffs.

Pinned by `rev` rather than `tag` because that repository's tags are its Go module's version ladder:
`v0.1.0` is a commit that predates the crate, so a tag requirement would either resolve to a tag with
no crate in it or entangle two release cadences that have no reason to move together. The cost is
that updating is a deliberate act — there is no semver range to float on — which for a wire format
shared with a Go backend is the behaviour worth having.

What the crate does not carry is the standard mode's full surface: nested structs, maps and
`interface{}` columns are out, because compact mode excludes them and compact mode is what a
single-record message is. Nothing here reads an ORM blob; a Rust reader that needs one later needs
the crate widened first, which is a decision better taken when there is a caller for it.

The vectors moved with the decoder. `token.rs`, `auth.rs` and `tests/bridge_http.rs` each carried the
same stale `0x01` hex message; all three now carry the base64 the Go generator prints, and the one in
`auth.rs` still proves the Rust and Go token hashes agree byte for byte, since its `Hash` field was
computed by `core.ComputeUsuarioTokenHash` with the same test secret.
