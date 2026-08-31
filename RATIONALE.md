## This repository builds and publishes its own release binaries

**Context** — The crate lived here but nothing here built it. `genix`'s
`release-binaries.yml` compiled both architectures, and its `plan`/`reuse` jobs existed only to
work around the mismatch: a `genix` tag usually means the backend changed and this crate did not,
so the workflow diffed the recorded gitlink and re-downloaded the previous tag's assets to avoid
starting two Rust runners for an unchanged crate. A repository that ships a binary could not
produce that binary on its own.

**Decision** — `.github/workflows/release-binaries.yml` here builds `fareward_linux_amd64` and
`fareward_linux_arm64` on `push` of a `v*` tag (plus `workflow_dispatch` for validation), and
publishes them with a `SHA256SUMS` manifest as a release of this repository. Two native runners,
`ubuntu-24.04` and `ubuntu-24.04-arm`, so `cargo test` runs on the architecture it ships for
instead of only cross-compiling for it. `genix` deleted its three fareward jobs and its
deployer now fetches these assets from here.

**Rationale** — The reuse machinery becomes unnecessary rather than merely simpler: in this
repository a `v*` tag exists only because this crate changed, so there is never an unchanged build
to skip. The costs are real and accepted: releasing is now two tags instead of one, and a host that
takes the backend and the daemon together resolves two `latest` releases that no single tag pins
to each other. The wire protocol is what actually constrains that pairing, and it has its own
version in the HMAC domain — see the rename entry below.

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
  frame's HMAC loudly instead of leaving two incompatible protocols both calling themselves `:v6`.
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
`auth.rs` still proves the Rust and Go token HMACs agree byte for byte, since its `Hash` field was
computed by `core.ComputeUsuarioTokenHash` with the same test secret.
