# fareward wire protocol — the shape map and the plan

Every message that crosses the Rust daemon ↔ Go client boundary, the framing that gives each one a
**shape in byte 0 in both directions**, and which codec carries each shape's body.

**The decision.** `LockGranted`, `LockRefused`, `ReserveSequence` and `SetSequence` stay hand-rolled.
Every other shape with a body moves to **colbin**. §4 is the split and the rule under it, §7 is the
ordered implementation.

**Status, 2026-09-13.** **All five phases are implemented and green.** The reply shape byte, the
cursor under the hand-rolled sequence payloads, the `LockLost` push, the colbin dependency, and the
six colbin request shapes. `DOMAIN` is now `fareward:v11`, so the backend and the daemon must deploy
together.

Two consequences of Phase 3 that were not in the plan and are worth knowing before reading further:
**every opcode is length-prefixed now** — the fixed-width framing had nothing left to describe and
was deleted on both sides — and **the 65.5 s lease ceiling in §2.7 is gone** rather than raised.

**This document changed its mind once, and the reason matters.** It first measured colbin at 10x–120x
the hand-rolled encoders and recommended against it. colbin was then rewritten — byte-aligned, no
varint sizes, a zero field written as nothing, four-bit keys — and re-measured on 2026-09-13 at
**4x on the charge and 22x–24x faster than its own previous self on the request log**. §5 is the new
measurement; §9 keeps the old verdict on the record.

**Sources.** `src/service/protocol.rs`, `src/service/server.rs`, `src/{limiter,lock,reqlog,sequence}/protocol.rs`,
`src/limiter/{access,budget}.rs`; `go/connection.go`, `go/{credits,locks,request_log,sequences,budgets,access_invalidation}.go`.

**Method.** Sizes are read off the constants and the encoders, or measured and round-tripped. Timings
are Go benchmarks (`b.Loop`, `-count=7`, medians) and a `std::time::Instant` harness in Rust
`--release` (11 batches, median, best of four runs — the box throttles), both on an i7-1355U, Go 1.27
/ Rust 1.95. The hand-rolled encoders benchmarked are byte-for-byte copies of the ones in `go/` and
`src/`, validation included. Harnesses: `/tmp/fwsize` (Go) and `/tmp/fwrust` (Rust).

---

## 1. What crosses the boundary

Every phase has landed since this section was first written, so §1.1–§1.3 describe the wire as it
is now. The layout they replaced is kept where it explains a decision: §2 for what was wrong with
it, §9 for the record.

Two independent channels, sharing only the `INTERNAL_APIKEY` secret:

| channel | transport | codec | who talks |
|---|---|---|---|
| **server-utilities port** | raw TCP, one multiplexed connection per process | colbin, and two hand-rolled shapes | `fareward/go` ↔ `src/service` |
| **SSE bridge** | HTTP | JSON (serde / `encoding/json`) | `backend/agent/bridge.go` → `src/bridge/http.rs` → browser |

Everything below is the TCP port. The bridge is §8.

### 1.1 Framing

```
request   [opcode:1] [len:u16] [payload] [tag:8]            len on every opcode
reply     [shape:1] [correlation:u16] [body]                the shape gives the body's width
push      [shape:1] [0x0000] [len:u8] [body]                0x80 and up, sent unasked
```

- `tag` is SipHash-2-4 over `DOMAIN ‖ nonce ‖ sequence ‖ frame-without-tag`, `DOMAIN = "fareward:v11"`.
  The length header is inside the signed bytes, so a peer cannot make the daemon buffer a different
  amount than the one it signed.
- The connection is multiplexed; `correlation` is the low 16 bits of the frame sequence.
- **Both directions carry their shape in byte 0.** The request always did — the opcode is it. The
  reply gained one in `:v10`; before that a client had to look the correlation up in its pending map
  to know what it was reading. The shapes are §3.
- **Every request is length-prefixed.** There used to be a second, fixed-width framing for the
  opcodes whose payload width the opcode alone implied. `:v11` left none: six payloads became colbin
  messages, which write the bytes a value needs and omit a zero-valued field entirely, and the other
  two carry a counter name. Each opcode declares a `max_payload_size` instead, which is what bounds
  what an unauthenticated peer can make the daemon hold before the tag says whether to believe it.

### 1.2 Request shapes (Go → Rust)

Six of the eight are colbin messages: one numbered struct per shape, ids 1..16 so both sides keep
four-bit keys, mirrored field id for field id by a `#[derive(Colbin)]` struct in Rust. The sizes
below are payloads, so add three for the opcode and length header and eight for the tag.

| op | name | codec | payload | answered |
|---|---|---|---:|---|
| `0x01` | ChargeCredits | colbin | 9…19, ceiling 48 | yes |
| `0x02` | LockAcquire | colbin | ≤ 40 | yes |
| `0x03` | LockRelease | colbin | ≤ 24 | yes |
| `0x04` | LogRequest | colbin | ≤ 1264 | **no** |
| `0x05` | MutateCompanyBudget | colbin | ≤ 32 | yes |
| `0x06` | InvalidateUserAccess | colbin | ≤ 16 | **no** |
| `0x07` | ReserveSequence | hand-rolled | 4 + name | yes |
| `0x08` | SetSequence | hand-rolled | 8 + name | yes |

The `cb` ids, which are the whole of what the two sides agree on:

```text
0x01 ChargeCredits          0 company_id i32   > 0
                            1 user_id    i32   > 0
                            2 route_id   u16   ≤ 16383, a plain route number
                            3 cpu        u16
                            4 inference  u16
                            5 extra_allowed bool
                            6 access1    u16   packed (acceso_id << 2 | nivel-1)
                            7 access2    u16   fill from access1, zero terminates
                            8 access3    u16
                            9 access4    u16

0x02 LockAcquire            0 action     u16   opaque namespace
                            1 identifier i64   opaque
                            2 max_waiters u8   0 = try-lock
                            3 wait_ms    u32
                            4 lease_ms   u32   must be > 0; no 65 535 ceiling any more

0x03 LockRelease            0 action     u16
                            1 identifier i64
                            2 generation u16   pins the release to one grant

0x04 LogRequest             0 date       i16   UnixDay
                            1 request_id i64
                            2 route_id   i16
                            3 frame      u8    0..95, fifteen-minute slot
                            4 company_id i32
                            5 user_id    i32
                            6 elapsed_ms i16
                            7 errors     []ErrorEntry, ≤ 4
                                            0 id        i32
                                            1 code_line string ≤ 64 B
                                            2 text      string ≤ 200 B

0x05 MutateCompanyBudget    0 company_id i32   > 0
                            1 operation  u8    1 SetDaily · 2 SetCurrent · 3 IncreaseCurrent
                            2 cpu        u64   ≤ i64::MAX
                            3 inference  u64   ≤ i64::MAX

0x06 InvalidateUserAccess   0 company_id i32   > 0
                            1 user_id    i32   0 = every cached user, and a zero is not written

0x07 ReserveSequence        [0..4)  increment u32  > 0          hand-rolled
                            [4..]   name      UTF-8 ≤ 128, the frame's own length bounds it

0x08 SetSequence            [0..8)  value     i64  ≥ 0          hand-rolled
                            [8..]   name      UTF-8 ≤ 128
```

A colbin field holding its zero value is not written at all, which is where most of the saving is:
an ungated charge carries no access field, a budget mutation naming one resource does not carry the
other, and the wildcard invalidation is the frame with no user in it.

### 1.3 Reply shapes (Rust → Go)

Eleven shapes and one push, each with a body of its own: the table is §3. What they replaced, and
what was wrong with it, is below.

Until `:v10` there was one layout for every opcode — `[correlation:u16][status:u8][detail:u16]
[extra_len:u8]` plus a tail — where neither field meant anything on its own:

| answering | `status` | `detail` | `extra` |
|---|---|---|---|
| charge, allowed, no auth asked | `0` | `0` | — |
| charge, allowed, granted | `0` | `1 \| granted<<3 \| has_subs<<7` | sub-access runs, ≤ 8 B |
| charge, credit violation | `scope \| window<<1 \| inference<<3 \| cpu<<4` | `0` | — |
| charge, access denied | `0` | `2` NoAccess · `3` UnknownUser · `4` InactiveUser | — |
| lock acquire, granted | `0` | generation `u16` | — |
| lock acquire/release, refused | `1` Busy · `2` WaitTimeout · `3` Capacity · `4` Misuse | `0` | — |
| budget mutation | `0` Ok · `1` MonthNotConfigured · `2` Overflow | `0` | — |
| sequence reserve/set | `0` Ok · `1` Invalid | `0` | value `i64`, 8 B |
| anything the daemon could not do | `0xFF` | `0` | — |

---

## 2. What is actually disorderly

1. ~~**The reply has no shape.**~~ **Fixed in Phase 1.** Parsing depended on the pending map, so a
   reply could never be validated against the request kind it claimed to answer, and the daemon
   could not push an *unsolicited* frame — which is why `Lock.Lost()` was a client-side timer that
   admitted, in its own doc comment, to being advisory. Phase 4 then used the push range that
   opened up, and `Lost()` now closes when the daemon says so.
2. ~~**`status` and `detail` are overloaded per opcode.**~~ **Fixed in Phase 1.** `status` was a
   five-bit credit-violation bitfield for a charge, an enum for a lock, a different enum for a
   budget, a third for a sequence, and `0xFF` for everyone; `detail` was a generation, or a packed
   11-bit authorization verdict, or zero. Every new outcome had to find room inside fields that
   already meant four things. Each outcome is now a shape with a body of its own.
3. ~~**Field-stuffing has started.**~~ **Fixed in Phase 3.** `EXTRA_CREDIT_FLAG` lived in bit 15 of
   the route number, with a comment explaining that bit 14 was deliberately left unassigned as a
   guard. It is a field now, and the route number is a route number.
4. ~~**Three length-prefix idioms in one payload.**~~ **Fixed in Phase 3.** The request log had a
   `u16` frame length, a `u8` line length and a `u16` text length, hand-parsed against seven error
   variants. Five of the seven are gone; what is left is `Malformed`, which is colbin saying no, and
   the two ceilings that are about request logs rather than about bytes.
5. ~~**Layout trivia is load-bearing.**~~ **Fixed in Phase 2.** "Both payloads put their scalar first
   so the name can be the tail and need no length of its own" was a real constraint on two opcodes,
   documented in a comment and enforced by nothing. It is now `Cursor::rest()`, stated once in code
   and pinned by a vector taken from the Go client.
6. **Every constant is declared twice** and kept in step by comments — **much less so after Phase 3.**
   Every payload size and every offset is gone: a field is named by an id in a `cb` tag on one side
   and a `#[cb(N)]` on the other, and a mismatch is now a field that decodes as absent rather than a
   payload read at the wrong offset. What is still doubled is the genuinely shared numbers —
   `MAX_REQUIRED_ACCESS` / `MaxRequiredAccess`, `SEQUENCE_NAME_MAX` / `sequenceNameMax`, the request
   log's two string ceilings — and the cross-language vectors now cover the charge, the acquire, the
   invalidation and the request log rather than the request log alone.
7. **Fixed widths that are already tight.** ~~`wait_ms`/`lease_ms` are `u16` milliseconds, so a lease
   can never exceed 65.5 s.~~ **Fixed in Phase 3** — both are `u32` and a short one still costs two
   bytes. `elapsed_ms` is still `i16`, so a request slower than 32.7 s logs a wrong number: it is a
   `cb` field now and widening it is a one-line change on each side, but it has not been made.
8. **There is precedent for this going wrong.** `RATIONALE.md`, "Decode the session token with the
   colbin crate instead of transcribing the format": a hand-transcribed copy of a format drifted
   three versions behind and would have rejected every browser SSE connection.

All eight are answered except the `elapsed_ms` half of item 7, which is now a one-line change
nobody has asked for. Items 1–5 were about **shape and framing**, item 6 about a **codec**, and
item 7 about widths a codec makes irrelevant.

---

## 3. The framing: byte 0 is the shape, both directions

```
request   [shape:1] [len:u16] [body] [tag:8]
reply     [shape:1] [correlation:u16] ([len:u8])? [body]
```

The request side barely moved — the opcode already *is* the shape — but the length header stopped
being conditional. Every colbin body is variable, so after §4 only the two sequence shapes could
still have implied their own width, and keeping a second reader path for two buys nothing:
`PayloadWidth` and `Opcode::fixed_frame_size` are deleted, `opcodeIsLengthPrefixed` and
`buildFarewardLengthPrefixedFrame` with them, and each opcode declares a `max_payload_size` instead.

The reply gains a shape, and it is **free**: the shape byte replaces `extra_len`, because a shape
that knows its own body width does not need to state one. Only variable-bodied shapes carry a length.

| shape | name | body | codec | bytes | today |
|---|---|---|---|---:|---:|
| `0x01` | ChargeAllowed | — | — | 3 | 6 |
| `0x02` | ChargeGranted | `granted`, `has_subs`, sub-access bytes | **hand-rolled** | 3 + body | 6 + subs |
| `0x03` | ChargeCreditViolation | `[violation:u8]` | raw scalar | 4 | 6 |
| `0x04` | ChargeAccessDenied | `[reason:u8]` | raw scalar | 4 | 6 |
| `0x05` | LockGranted | `[generation:u16]` | **hand-rolled** | 5 | 6 |
| `0x06` | LockRefused | `[reason:u8]` | **hand-rolled** | 4 | 6 |
| `0x07` | Ack | — | — | 3 | 6 |
| `0x08` | BudgetRefused | `[reason:u8]` | raw scalar | 4 | 6 |
| `0x09` | SequenceValue | `[value:i64]` | **hand-rolled** | 11 | 14 |
| `0x0A` | SequenceInvalid | — | — | 3 | 6 |
| `0x7F` | Unavailable | — | — | 3 | 6 |
| `0x80…` | *pushes*, `[len:u8][body]` so an unknown one is skippable | — | | — | impossible today |
| `0x00` | never assigned | | | | |

Every reply is the same size or smaller, `status`/`detail` stop being general-purpose fields, and
`0x80…` is the space that makes a `LockLost` push a protocol change instead of an architecture
change. The reply's `Vec<u8>` sender in `server.rs` already carries a variable-length buffer (the
`:v9` change), so nothing structural resists this.

A push carries a one-byte length its correlated siblings do not, which is what makes the range
extensible: a client that meets a push it predates steps over it instead of losing the connection,
because an unknown *reply* has no width and is necessarily fatal.

**This depended on no codec and landed first**, in Phase 1.

---

## 4. Which codec carries which shape

### 4.1 The rule

> **A body that is nothing, or one scalar, needs no codec — the shape byte already names the field.
> A body that is a record of several fields, where some are usually zero or variable-length, is worth
> a codec. The exception is a record so hot or so simple that the keys cost more than they buy.**

The first sentence is why six of the eleven reply shapes have no codec question at all: four carry no
body, and three carry a single byte or a single integer. Wrapping one scalar in a key/value codec
costs a key nibble and a header to say what the shape byte already said.

The second sentence is the colbin case, and it is most of the request side.

The exception is the shapes below, by decision — four by instruction, and `ChargeGranted` on
inspection once Phase 3 reached it.

### 4.2 The split

**Requests (Go → Rust)**

| op | name | codec | why |
|---|---|---|---|
| `0x01` | ChargeCredits | **colbin** | Ten fields of which five are usually zero; 20 B → 9…19 B. The extra-credit flag stopped riding in bit 15 of the route number (§2.3) and became a field that costs one byte when true and nothing when false. |
| `0x02` | LockAcquire | **colbin** | Five fields, and `wait_ms`/`lease_ms` stopped being `u16` milliseconds — the 65.5 s lease ceiling in §2.7 disappeared rather than being raised. |
| `0x03` | LockRelease | **colbin** | Three fields, and the common small identifier costs the bytes it needs. |
| `0x04` | LogRequest | **colbin** | The prize. Deletes the only hand-written variable-length parser on the port: three length idioms, seven error variants, ~90 lines of Rust and the clamping half of the Go encoder. |
| `0x05` | MutateCompanyBudget | **colbin** | Two `u64` that are almost always small, and a mutation naming one resource does not carry the other. Admin path, so it was also the safest place to prove the dependency. |
| `0x06` | InvalidateUserAccess | **colbin** | Two fields, and the wildcard user is zero — which colbin writes as nothing. On whole frames this one is a wash: see §5.3. |
| `0x07` | ReserveSequence | **hand-rolled** | Decided. See 4.3. |
| `0x08` | SetSequence | **hand-rolled** | Decided. See 4.3. |

**Replies (Rust → Go)**

| shape | codec | why |
|---|---|---|
| ChargeGranted | **hand-rolled** | Planned as colbin, kept hand-rolled when Phase 3 got to it. Its body is two masks and one opaque run, and the decoder's real work is checking the three agree with each other — a protocol rule a codec would not carry. Moving it would have traded a byte-counted body for a keyed one and kept every check. |
| LockGranted · LockRefused | **hand-rolled** | Decided. See 4.3. |
| SequenceValue | **hand-rolled** | Inferred, not stated: it is the answer to the two hand-rolled sequence requests, and its body is one `i64`. Flagged in §10.1 — say the word and it flips. |
| ChargeCreditViolation · ChargeAccessDenied · BudgetRefused | raw scalar | One byte each. Nothing to encode. |
| ChargeAllowed · Ack · SequenceInvalid · Unavailable | none | No body. The shape byte is the whole message. |

### 4.3 Why these four stay hand-rolled

`LockGranted` and `LockRefused` follow straight from the rule: a `u16` generation and a one-byte
reason. A codec on either is a key and a header to describe a field the shape already named, and the
lock path is the one a caller waits on.

`ReserveSequence` and `SetSequence` are a deliberate exception to the rule — they *are* records, of a
scalar and a counter name — and they are worth making:

- **The reserve path is the ORM insert path.** Every row that needs an id waits on this round trip,
  and the daemon usually answers from an in-memory block, so the codec is a real share of it.
- **The shape is already minimal and has no room to grow.** A scalar and a name, where the name is
  the frame's own tail. There is no optional field to omit and no third field anybody wants.
- **It keeps one frame family readable without colbin on either side**, which is worth something
  while the dependency is new.

What they give up is §2.5 — "the scalar leads so the name can be the tail" stays a real constraint
enforced by nothing, which §6 turns into a cursor rather than deleting.

### 4.4 What "colbin" means concretely

One numbered struct per shape, mirrored by a `#[derive(Colbin)]` struct on the Rust side, with ids
1..16 so both sides keep four-bit keys:

```go
type ChargeRequest struct {
	CompanyID    int32  `cb:"1"`
	UserID       int32  `cb:"2"`
	RouteID      uint16 `cb:"3"`   // a plain route number again
	CPU          uint16 `cb:"4"`
	Inference    uint16 `cb:"5"`
	ExtraAllowed bool   `cb:"6"`   // one byte when true, nothing when false
	Access1      uint16 `cb:"7"`   // four scalars, not a slice: measured cheaper, see §5.3
	Access2      uint16 `cb:"8"`
	Access3      uint16 `cb:"9"`
	Access4      uint16 `cb:"10"`
}
```

```rust
#[derive(Colbin, Default, PartialEq, Debug)]
struct ChargeRequest {
    #[cb(1)] company_id: i32,
    #[cb(2)] user_id: i32,
    #[cb(3)] route_id: u16,
    #[cb(4)] cpu: u16,
    #[cb(5)] inference: u16,
    #[cb(6)] extra_allowed: bool,
    #[cb(7)] access1: u16,
    #[cb(8)] access2: u16,
    #[cb(9)] access3: u16,
    #[cb(10)] access4: u16,
}
```

Ids count from one; the wire key is the id minus one, so `cb:"1"` writes key 0 and the sixteen a
nibble holds are ids 1..16. The two numbers differ in exactly that one place — source counts from
one, bytes count from zero — and `colbin.FieldIDs` reports the *key*, because it describes bytes
that already exist rather than the tags that produced them.

Go holds a package-level `colbin.MustCodec[T]()` and appends onto the connection's buffer; Rust calls
the derived `decode`. Validation does **not** move into the codec: `company_id > 0`, the route
ceiling, the sparse-slot check and the empty-frame check stay exactly where they are, because they
are protocol rules rather than encoding rules.

---

## 5. Measured, against the current colbin

`colbin` here is `github.com/ivanjoz/colbin` `v0.3.0`, through
`Codec[T].Append` / `Codec[T].Unmarshal` in Go and `#[derive(Colbin)]` in Rust.

### 5.1 Go

| operation | hand-rolled fixed | cursor (§6) | **colbin now** | colbin before | gain |
|---|---:|---:|---:|---:|---:|
| charge, encode | 2.8 | 7.7 | **23.1** | 92.2 | 4.0x |
| charge, decode | 6.7 | 17.9 | **28.2** | 124 | 4.4x |
| charge, `Marshal` (allocating) | — | — | **57.4** | 1020 | 18x |
| request log 1 error, encode | 11.7 | — | **56.7** | 1266 | 22x |
| request log 2 errors, encode | 18.0 | — | **63.1** | 1512 | 24x |
| request log 1 error, decode | 36.8 | — | **168.5** | — | — |

### 5.2 Rust — the daemon's side

| operation | hand-rolled | cursor | **colbin now** | colbin before |
|---|---:|---:|---:|---:|
| parse a charge | 5.0 | 4.0 | **21** | 53 |
| encode a charge (buffer reused) | 1.6 | — | **21** | 42 |
| encode a reply | 13.0 *(allocates)* | — | **12.2** | 33 |

The reply row flipped outright: colbin now beats the hand-rolled `encode_reply`, because that one
allocates a `Vec` per call and `append_encoded` writes into a reused buffer.

### 5.3 Bytes

The planning numbers were payload-only. These are **whole frames as the two implementations now
build them** — opcode, length header, payload, tag — measured off the Go encoder after Phase 3
landed, which is the comparison that actually decides anything.

| message | frame before | **frame now** |
|---|---:|---:|
| charge, ungated GET | 29 | **21** |
| charge, 1 required access | 29 | **26** |
| charge, worst case | 29 | 34 |
| lock acquire · release | 24 · 21 | **22 · 16** |
| budget mutation | 29 | **20** |
| invalidate one user · the company | 15 · 15 | 17 · **14** |
| request log, 0 / 1 / 2 errors | 34 / 87 / 142 | 33 / 91 / 146 |

Three findings, and the second and third are the honest ones:

- **Four scalar access slots, not a `[]uint16`.** An array field in a one-record message was 10x the
  cost and three bytes larger when this was first measured; the current colbin is kinder, but four
  scalars still win and they omit individually — which is the whole of the ungated charge's saving.
- **The length header eats part of the win, and on two shapes it eats all of it.** Every frame pays
  two bytes it did not before. The charge and the budget repay that several times over; the
  invalidation does not — 15 bytes before against 17 for a named user, and 14 for the wildcard. That
  shape was moved for uniformity, not for bytes, and §4.2's "6 B → 5 B" was payload-only and
  therefore misleading.
- **The request log is a few bytes larger, not smaller.** 91 against 87 for a one-error row. packed5
  is opt-in now and leaving it off costs exactly what it would save. The request log was never moved
  for size — it was moved to delete a hand-written parser that acts on lengths from a socket — but
  §4.2 called it "the prize" next to a byte table, and on bytes it is a small loss.

### 5.4 Against the 4x rule

| | ratio to hand-rolled | verdict |
|---|---:|---|
| Rust, parse a charge | 4.2x | borderline, was 11x |
| Go, charge decode | 4.2x | borderline |
| Go, request log encode, 2 errors | 3.5x | passes |
| Go, request log encode, 1 error | 4.8x | over |
| Go, charge encode | 8.4x | over, against a 2.8 ns baseline |

The rule was written against a codec that was 35x–120x. At 3.5x–8.4x the question stops being
whether the codec is affordable and becomes what it buys per shape, which is what §4 answers.

---

## 6. The cursor, for the shapes that stay hand-rolled

The four hand-rolled shapes keep their bytes and lose their offsets. A sequential cursor removes
every literal offset while keeping the layout explicit in source order, and it was measured at 2.7x
in Go and **1.1x in Rust** — where the reads inline away entirely:

```go
// today
binary.BigEndian.PutUint32(payload[0:4], increment)
payload = append(payload, name...)

// cursor
w := frameWriter{buffer: buffer[:0]}
w.u32(increment)
w.tail(name)        // names the "scalar first, name last" rule instead of commenting it
```

| candidate | Go encode | Go decode | Rust decode |
|---|---:|---:|---:|
| hand-rolled today | 2.8 | 6.7 | 5.0 |
| **cursor** | 7.7 (2.7x) | 17.9 (2.6x) | **4.0 (0.8x)** |
| runtime layout table | 11.9 (4.3x) | — | — |

The runtime table was rejected: 4.3x, and it cannot express a flag riding inside another field's bits
or a zero-terminated slot list.

### 6.1 The duplicated constants

Independent of any codec, and cheaper than either: extend the cross-language vector test that already
exists for the request log (`parses_bytes_produced_by_the_go_encoder`, fed by `fareward/vectors/`) to
**every shape, in both directions**. That is the mechanism that catches drift — a comment saying
"mirrors the Rust constant" does not. Each phase below lands with its vectors.

---

## 7. Implementation

Every phase changes the wire, so every phase bumps `DOMAIN` (`fareward:v9` → `v10` → …, and `:v10`
is what is deployed now) and deploys
the backend and the daemon together. That is already the documented rule in `connection.go` and
`auth.rs`; the bump is what makes a mismatched pair fail at the first frame instead of misreading one.

### Phase 0 — the colbin dependency · **DONE**

It was blocked, and the blocker was real: colbin is not only a wire codec here, it is what the ORM
marshals struct fields into for ScyllaDB and DynamoDB, what seals the company-config blob, and what
writes the session token. Because the backend imports `fareward/go`, the two share one module
version, so moving colbin for the frames meant re-encoding every colbin blob already stored.

**What unblocked it was a decision, not a discovery: the database is being wiped.** Pre-alpha, no
production data, and the operator chose to re-seed rather than migrate. That turns a data migration
into a version bump.

What it took:

1. **colbin tagged `v0.3.0`**, Go and Rust, and every pin moved: `backend/go.mod`,
   `backend/genix-orm/go.mod`, `backend/genix-orm/dynamo/go.mod`, `fareward/vectors/go.mod`,
   `fareward/go/go.mod` (its first and only dependency) and `fareward/Cargo.toml`, which moved off
   the pre-rewrite `rev = 9643bc8` and onto the crate with `features = ["derive"]`.
2. **`SetOmitEmpty` is gone** from the ORM's two `init()`s. Omitting a zero-valued field is not a
   mode any more — the byte-aligned format never writes one — so the call had nothing to set.
3. **`src/bridge/token.rs` ported to `#[derive(Colbin)]`.** `Kind`, `Schema`, `decode_one` and
   `Value` no longer exist. The session token's five wire fields were also given explicit `cb` ids
   in `core.UsuarioToken`, which is a change on its own merits: it puts the message on four-bit keys
   (34 bytes against 37) and replaces "two hash implementations in two languages agree" with a
   number both sides can read. Vectors regenerated from `go run ./fareward/vectors`.
4. **Two fixes upstream in colbin**, both found by this work and neither fareward's:
   a slice at the root is now carried in a one-field envelope (the ORM stores
   `[]AccesoGrantRecord`), and the Rust port's narrow list element no longer closes like a keyed
   composite — that bug refused any element body reaching 255 bytes, which is an ordinary
   request-log row with two errors in it.

`fareward/go` now has exactly one dependency, and colbin has none of its own, so the module still
pulls nothing else in.

### Phase 1 — the shape byte · **DONE**

- Rust: a `ReplyShape` enum and one typed constructor per shape, replacing `encode_reply(status,
  detail, extra)`. `server.rs` names an outcome instead of packing two integers.
- Go: `readLoop` reads `[shape:1][correlation:u16]`, then the body the shape implies. `muxReply`
  carries the shape; `credits.go`, `locks.go`, `sequences.go` and `budgets.go` switch on it instead
  of decoding overloaded `status`/`detail`.
- Delete: `encode_access_detail`, `decodeCreditLimitResponse`'s bit-unpacking of a shared byte,
  `UNAVAILABLE_STATUS` as a sentinel inside a field that also carries verdicts.
- Vectors for all eleven reply shapes.

Result: §2.1 and §2.2 gone, every reply the same size or smaller, `0x80…` open.

**Landed.** `ReplyShape` / `Reply` in `service/protocol.rs`; `server.rs` names an outcome at every
one of its fifteen reply sites; the Go reader parses `[shape][correlation][body]` and dispatches on
the shape. `encode_access_detail`, `UNAVAILABLE_STATUS`, `SequenceReply`, `encode_sequence_value`
and the `status`/`detail` pair are deleted. The cross-language auth vectors were regenerated from
the Go client for `:v10` — the payloads are byte for byte what they were, only the tags moved, which
is what says the bump changed the domain and nothing else about a request. 180 lib + 15 lock + 10
request-log + 17 bridge tests, and the Go module's own suite, all green; the backend still builds.

One thing deliberately not done here: `ChargeGranted` keeps its hand-rolled body until Phase 3,
because it is a colbin shape and a half-moved shape is worse than either end state.

### Phase 2 — the hand-rolled shapes onto a cursor · **DONE**

`LockGranted` and `LockRefused` needed nothing in the end: their bodies are a `u16` and a byte, and
`Reply::encode` leaves no offset to remove. What was left was the two sequence payloads, which now
read through a `Cursor` whose `rest()` states the rule that used to live in a comment — the scalar
leads so the counter name can be the rest of the frame. A new test parses the exact bytes the Go
client puts on the wire for both, which is the §6.1 mechanism applied to the two shapes that keep
their own codec.

### Phase 3 — the colbin shapes · **DONE**

All six landed in one domain bump rather than six, because they deploy together anyway and six
bumps would have meant six lockstep deploys for one change.

| shape | what it looks like now |
|---|---|
| `MutateCompanyBudget` | `budgetMutationFrame` / `BudgetMutationFrame`. A mutation naming one resource does not carry the other. |
| `InvalidateUserAccess` | The wildcard is the frame with no user field in it. |
| `LockRelease` · `LockAcquire` | And `wait_ms`/`lease_ms` widened to `u32`, closing §2.7. |
| `LogRequest` | The prize. `parse_request_log` is a `decode` call and two ceilings; three length idioms, a bounds check before each and five of the seven error variants are deleted. |
| `ChargeCredits` | The route number is a plain route number again — `EXTRA_CREDIT_FLAG` is gone and `extra_allowed` is a field. |

`ChargeGranted` **stayed hand-rolled**, and that is a change from the plan. Its body is
`[granted_mask][has_subs_mask][sub_len][sub bytes]` — two masks and one opaque run — and the Go
decoder's real work is checking that the three agree with each other, which is a protocol rule a
codec would not carry. Moving it would have traded a byte-counted body for a keyed one and kept
every check. It is the one shape where §4.1's "a record of several fields" reads as false on
inspection: it is one mask and one blob.

What did not move, as instructed: `ReserveSequence` and `SetSequence`, and with them
`SequenceValue`.

### Phase 4 — the `LockLost` push · **DONE**

`drop_expired` now returns the keys it dropped and the reader loop pushes
`LockLost { action, identifier }` for each. The Go reader routes anything at or above `0x80` to
`handlePush` before the pending map, finds the lock in a per-connection registry of what this
process holds, and closes its `Lost()` channel; the local timer stays as the backstop for the case
no push can arrive. `Lock.Lost()` now closes at the daemon's own deadline rather than at one started
a round trip later. Still advisory under a partition — work inside a lock has to stay safe to run
twice — but the common case is reported instead of inferred.

---

## 8. The SSE bridge (unchanged)

`backend/agent/bridge.go` → `src/bridge/http.rs`, JSON over HTTP:

```text
POST /publish   { Channel, Message, WaitMs }                → { Delivered }
POST /rpc       { Channel, ID, Message, TimeoutMs, WaitMs }  → { Kind, Payload }
GET  /client/stream                                          → SSE frames, { Type, ... }
POST /client/inbound  { ID, Type, Payload }                  → { Delivered }
```

`Message` and `Payload` are opaque passthrough — the backend hands the bridge a blob addressed to a
browser tab. Re-coding that would mean three ports (Go, Rust, the browser's AssemblyScript) for a
human-paced path whose far end is JavaScript. **Leave it as JSON.**

---

## 9. What this document got wrong, and when

- **The first draft recommended colbin for the request log, the budget and the sequences on bytes
  alone.** Withdrawn once timed: on the colbin of the day the request log was the worst case on the
  port at 92x–121x.
- **The second draft recommended against colbin everywhere** and proposed a cursor instead, on
  measurements of 10x–120x. Those numbers were real for that colbin. It was then rewritten —
  byte-aligned, no varint sizes, zero fields omitted, four-bit keys — and §5 is the re-measurement:
  4x–24x faster than itself, and 3.5x–8.4x of hand-rolled rather than 35x–120x. The conclusion moved
  because the thing being measured moved.
- **`kv16` / minimal mode is gone.** A standalone byte-aligned key/value codec was built in fareward
  (`go/kv16`, `src/kv16.rs`) and then moved into colbin as `minimal` mode. Neither survives: colbin's
  tree was reset and fareward's copies were deleted mid-migration. It matters less than it looks —
  the current colbin converged on the same design (byte-aligned, no varint sizes, omit-zero, 4-bit
  keys, `Append(dst, *T) []byte`), and its decode is now *faster* than minimal mode's was.
  `KV16_DRAFT.md` keeps the format and the reasoning if any of it is ever wanted back.

---

## 10. Open

1. **`SequenceValue` is hand-rolled by inference, not instruction** (§4.2). The two sequence requests
   were named; their shared reply was not. One `i64` behind a shape byte, so it reads as part of the
   same family — but say so if the whole sequence conversation should be colbin on the reply side.
2. **`ChargeGranted` stayed hand-rolled, against the plan** (§4.2, §7 Phase 3). The plan said colbin;
   on inspection its body is one mask and one opaque run, not a record, and the decoder's work is
   agreement checking that a codec would not carry. Reversible in an afternoon if the reasoning does
   not hold up.
3. **The session token's `cb` ids are new** (§7 Phase 0). `core.UsuarioToken` had none, so the ids
   came from colbin's name hash and the Rust reader had to agree with it by running the same hash.
   They are declared `0..4` now, which is smaller on the wire and checkable by eye — but it is a
   change to the credential format, so every live session ends at the deploy.
4. **`elapsed_ms` is still `i16`** (§2.7). A request slower than 32.7 s logs a wrong number. It is a
   `cb` field now, so widening it is one line on each side; left alone because nothing asked.
5. ~~The `LockLost` push needs its own yes.~~ **Built** (Phase 4), under "do all phases". It is the
   one behavioural change in this batch rather than a refactor, so it is the first thing to look at
   if lock behaviour surprises you: `handlePush` in `go/connection.go` and the push loop at the top
   of `handle_connection` in `src/service/server.rs`.
6. ~~Phase 0 is a project, not a step.~~ **Done**, once the operator chose to wipe the database
   rather than migrate it. What it actually took is in §7 Phase 0, including two bugs it turned up
   in colbin itself.
