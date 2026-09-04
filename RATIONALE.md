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
