//! Autoincrement and write-sequence reservation, reached through opcode `0x07`.
//!
//! The counters themselves belong to genix-orm: the same `sequences(name text, current_value
//! counter)` table, the same names, the same "return the first of `n` consecutive values"
//! contract. What moves here is only who is allowed to advance them. The ORM's own allocator reads
//! and then increments, so concurrent writers hand out the same id; one process doing the
//! reservation removes the race entirely.
//!
//! Values are handed out from in-memory blocks, so the common case costs no I/O at all. See
//! `allocator` for what that buys and what it requires — chiefly that this daemon is the only
//! writer of those rows, which is already true of every other service on this port.

pub mod allocator;
pub mod protocol;
pub mod store;
