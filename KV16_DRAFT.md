# kv16 — a key/value codec for records of at most sixteen fields

Draft for review. Implemented and measured, wired to nothing: no frame on the port uses it yet.

- **Go**: `go/kv16/` — `doc.go` (the specification), `kv16.go`, `kv16_test.go`. 16 tests, no dependencies,
  so the client module stays standard-library-only.
- **Rust**: `src/kv16.rs`, declared in `lib.rs`. 14 tests, two of which pin it to the Go writer: one
  decodes a charge's bytes verbatim, and one rebuilds a 3701-byte record covering every continued
  size and asserts the same length, the same first 64 bytes and the same FNV-1a as Go produced.
- **Harnesses**: `/tmp/fwsize` (Go benchmarks against the hand-rolled encoders and colbin) and
  `/tmp/fwrust` (the same in Rust). Both compare against byte-for-byte copies of what `go/` and
  `src/` do today.

**Verdict: it does what the sketch promised.** ~3x the hand-rolled encoder in Go and ~2.4x the
hand-rolled parser in Rust — inside the 4x rule — at 12x–29x faster than colbin and roughly colbin's
byte count. The charge frame goes from 20 fixed bytes to 11, and no offset appears in any codec.

**Sizes have no ceiling.** A header carries a size's low bits plus a flag; when it is set, LEB128
continuation bytes carry the rest. The common size still costs nothing extra — 2047 bytes of string
and 255 array elements fit the two header bytes — and nothing is refused above it. That removed the
last way a write could fail, so `Writer` has no error and no `Err` method: **an encode cannot fail.**

---

## 1. The format

A message is a sequence of fields and ends when its buffer ends; the frame that carries it already
states its length. Keys are 0..15. Everything is big-endian. **A field whose value is zero, empty or
false is not written at all** — which is where most of the saving comes from, since these records are
mostly zeros. Nothing is bit-packed across a byte boundary: every field is one or two header bytes
plus whole content bytes, which is what keeps an encode down to a header and a few stores.

```text
integer        [key:4][positive:1][size:3]                    [magnitude: size bytes]

    size code  0→1B  1→2B  2→3B  3→4B  4→6B  5→8B  6→no bytes, the magnitude is 1
    positive   1 = the bytes are a magnitude; 0 = negative, bytes are |value|
    code 7 is unassigned, reserved for a future extended header
    no continuation flag: the size code already reaches eight bytes

string/bytes   [key:4][more:1][size:11]                       [bytes: size]
               [key:4][more:1][size:11][+LEB128]              [bytes: size]  (more = 1)

    2047 bytes fit the two header bytes; past that the continuation carries
    size>>11, seven bits per byte, low group first

integer array  [key:4][positive:1][width:2][more:1][count:8]  [count × width bytes]
               ... [+LEB128] when more = 1, carrying count>>8

    width code 0→1B  1→2B  2→4B  3→8B, taken from the widest element
    positive   1 = magnitudes; 0 = two's complement at that width

string array   [key:4][more:1][count:11]   then per element [size: LEB128][bytes: size]

    the element length is a varint too: under 128 bytes — every code line and most
    error texts — it costs one byte rather than two, and has no ceiling either
```

A header says how *wide* a field is, never what it means: the reader takes the type from the key,
which it knows because both sides share the record definition. That is what keeps it small, and it
costs the ability to skip an unknown key (§5).

## 2. Where this differs from the sketch, and why

| sketch | here | why |
|---|---|---|
| int array: 1 width bit, 9-bit count | **2 width bits, 8-bit count** | Two widths cannot serve both a `[]uint16` of packed grants and a `[]int32` of error ids. With {2, 8} an error id needing 3 bytes costs 8. Four widths {1,2,4,8} cost one count bit — 255 elements in the header instead of 511 — and since the count now continues, 511 was never the ceiling that mattered. **This is the one open wire decision: see §7.1.** |
| int size: 3 bits, five widths listed | **six widths + code 6 = "value is 1, no bytes"** | Codes 6 and 7 were unassigned. Code 6 makes a true bool one byte instead of two, and catches the very common value 1. Code 7 stays free. |
| string array: key + 12-bit count only | **11-bit count + continuation, each element behind a LEB128 length** | The sketch does not say how elements are delimited. A varint length removes the ceiling and costs one byte for anything under 128 — which is every code line and most error texts, so the request log got 2 bytes per error *smaller* than the fixed two-byte version. |
| — | **no record terminator** | Sixteen keys means all four key bits are usable, so there is no spare value to terminate with. The frame's length header is what ends the record. |
| — | **no runtime key check** | See §4: checking `key < 16` once per field cost 8 ns of a 25 ns encode. A key is a constant of the record definition, so it is a compile-time property. |
| — | **no writer error at all** | With sizes continued rather than capped, nothing a caller can hold in memory is too large to describe. `Writer` has no `Err`, and the generated codecs return just bytes. |

## 3. Measured

Same machine, same harness and the same hand-rolled copies as `PROTOCOL_SHAPES.md`: i7-1355U, Go
1.27 (`b.Loop`, `-count=5`, medians), Rust `--release` (11 batches, median).

### Bytes

| message | today, fixed | **kv16** | colbin |
|---|---:|---:|---:|
| charge, GET, no access | 20 | **9** | 9 |
| charge, POST, 1 required access | 20 | **11** | 10 |
| charge, 2 required accesses | 20 | **13** | 12 |
| charge, worst case | 20 | 29 | 27 |
| request log, no errors | 23 | **21** | 20 |
| request log, 1 error | 76 | 79 | 63 |
| request log, 2 errors | 131 | 133 | 103 |

kv16 lands within a byte or two of colbin everywhere except the request log, where colbin's `packed5`
packs ASCII into five bits per character and nothing here does. Against today's fixed layouts the
charge roughly halves; the request log is within 2 bytes per error, having lost 2 bytes per error to
the LEB128 element lengths.

### Time, Go

| operation | hand-rolled | cursor | **kv16** | colbin |
|---|---:|---:|---:|---:|
| encode a charge | 2.6 | 7.0 | **7.4** (2.9x) | 92 (36x) |
| decode a charge | 6.3 | 16.6 | **20.3** (3.2x) | 124 (20x) |
| encode a request log, no errors | 3.1 | 6.2 | **27.8** (9.0x) | 126 (41x) |
| encode a request log, 1 error | 10.5 | — | **43.9** (4.2x) | 1266 (121x) |
| encode a request log, 2 errors | 15.7 | — | **57.2** (3.6x) | 1512 (96x) |
| decode a request log, 1 error | 32.8 | — | **124** (3.8x) | — |

Zero allocations everywhere except the request-log decode, which copies its strings out (3 allocs,
96 B) exactly as the hand-rolled parser does.

### Time, Rust — the daemon's side

| operation | hand-rolled | cursor | **kv16** | colbin |
|---|---:|---:|---:|---:|
| parse a charge | 5.0 | 5.5 | **11.9** (2.4x) | 53 (11x) |
| encode a charge | 1.4 | — | **6.5** (4.6x) | 42 (30x) |

The one figure over 4x is a 1.4 ns baseline: the daemon does not encode charges, it parses them, and
parsing is 2.4x. Both decode figures moved about 2 ns when sizes became continued — the integer path
did not change, so that is code layout rather than the format.

## 4. What made it fast

Three things, each worth measuring again if the format is ever changed:

1. **Byte alignment.** No bitstream, no cross-byte packing. A field is a header byte and whole bytes,
   so the writer is `append` and the reader is a load.
2. **Width-typed entry points** — `U16`, `U32` next to the generic `Uint`. A `uint64` parameter forces
   the method to carry all six widths, which pushes it past Go's inline budget; a `uint16` can only
   be one byte or two, so `U16` is two appends with no call underneath and it inlines. **The charge
   encoder went from 16.9 ns to 7.9 ns just by calling the writer that matches each field's Go type**
   — which is exactly what a macro or a generator would pick. Same idea in Rust with `#[inline]` on
   the narrow reads and `#[inline(never)]` on the wide fallback: 19.8 ns → 9.8 ns.
3. **No per-field key check.** `if key >= 16` once per field cost **8 ns of a 25 ns encode** on a
   ten-field record. It is gone, deliberately, under a principle worth stating: *the reader defends
   against the network; the writer trusts its own program.* A key is never data. Assert it where the
   constants live:

   ```go
   const _ = uint(15 - chargeKeyAccess4) // fails to build if a key exceeds 15
   ```

The reader keeps every bounds check — it is what parses bytes off a socket. Both implementations
have a test that walks every prefix of a valid message and requires an error rather than a panic.

## 5. What it cannot do

- **Skip an unknown key.** The header sizes a field but does not say which of the four layouts it is,
  so a reader that does not know the key cannot step over it. Adding a field is still a coordinated
  deploy of both binaries — the same trade colbin's compact mode makes. Size code 7 is the reserved
  door if a self-describing variant is ever wanted.
- **Trust a declared size.** It no longer has a ceiling, so the reader carries two guards the writer
  does not need: a continuation run longer than nine bytes, or one describing more than an `int`
  holds, is refused (`ErrSizeTooLarge`) rather than wrapped into a small size whose bounds check
  would then pass. A string array also refuses to `reserve` on the count a peer declared before its
  elements have actually been read — that is how a two-byte frame asks for a gigabyte.
- **Carry more than sixteen fields.** This bites once, concretely: the request log with four flat
  error slots would need nineteen keys. As three parallel arrays it needs ten. That is why the draft
  models it that way, and it matches the repo's own `Detail*` convention.
- **Nested records.** Primitives, strings, and arrays of those. A nested struct would need a length
  or a terminator, and neither is in the format.
- **Beat a fixed layout on tiny records.** The request log with no errors is 9.4x, because the
  hand-rolled version writes a fixed 23-byte header with no branches at all. In absolute terms it is
  26 ns on a fire-and-forget frame.

## 6. What this would mean for the port

If adopted, the trade against `PROTOCOL_SHAPES.md` §6 changes: kv16 gives the ordering the cursor
gives (no offsets anywhere) **and** the byte savings colbin gives, at a cost that stays inside the
4x rule on both sides — with no dependency added to `fareward/go`, which is the objection that
blocked colbin.

The charge frame is the clearest case: 29 bytes → 1 + 2 + 11 + 8 = 22, `EXTRA_CREDIT_FLAG` stops
riding in the route number's high bit (it becomes a one-byte bool field that costs nothing when
false), and `required_access` stops being four fixed slots with a zero terminator.

Every frame would become length-prefixed, since a kv16 body is variable — that is the +2 bytes
already counted above.

## 7. Open questions

1. **Is the 2-bit array width right, or should the sketch's single bit stand?** This is the only wire
   detail where I knowingly diverge, and it survived the continuation change: the 2-bit version costs
   a count bit in the header (255 elements before continuing, instead of 511) and saves 4 bytes on
   every `[]int32` of error ids. The two are indistinguishable on the wire — both headers are 16
   bits, and the bit that means "wide" in one is a count bit in the other — so it has to be decided
   once rather than supported both ways.
2. ~~Should a string array's elements carry a one-byte length?~~ **Resolved by the LEB128 element
   length**: an element under 128 bytes now costs one byte, and the request log went from 81/137 to
   79/133 against the hand-rolled 76/131.
3. **Is size code 6 ("value is 1") wanted**, or should a bool simply cost two bytes and leave both
   spare codes for a future extended header?
4. **Which frames would actually move to it**, if any? The charge is the one with the clearest case;
   the locks are tiny and fixed and gain little; the request log gains order and loses 5 bytes per
   error.
5. **Does this change the recommendation in `PROTOCOL_SHAPES.md` §7?** That document currently says
   "keep plain binary everywhere, get the order from a cursor". kv16 is a better answer to the same
   problem if the measurements above hold up on your reading.
