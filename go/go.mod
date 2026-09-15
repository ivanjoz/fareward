// The Go client for the fareward daemon, and the reference implementation of the raw-TCP
// frame protocol described in ../README.md. A module of its own so a backend can depend on the
// client without depending on the daemon's repository layout.
//
// It has exactly one dependency, and it was a decision somebody made on purpose: colbin carries
// the request frames that are records rather than fixed layouts (PROTOCOL_SHAPES.md §4), and the
// daemon decodes them with the same format's Rust crate. The alternative was a hand-written
// variable-length parser on both sides of every one of them, which is what the request log used
// to be and what §4.2 costs out.
//
// colbin has no dependencies of its own, so this module still pulls nothing else in.
module github.com/ivanjoz/fareward/go

go 1.27

require github.com/ivanjoz/colbin v0.3.0
