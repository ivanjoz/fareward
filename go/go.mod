// The Go client for the fareward daemon, and the reference implementation of the raw-TCP
// frame protocol described in ../README.md. A module of its own so a backend can depend on the
// client without depending on the daemon's repository layout, and so it stays honest: this module
// has no dependencies at all beyond the standard library, and adding one should be a decision
// somebody has to make on purpose.
module github.com/ivanjoz/fareward/go

go 1.27
