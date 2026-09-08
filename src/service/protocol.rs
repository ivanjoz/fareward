//! Opcode routing for the shared server-utilities TCP port.
//!
//! Every operation on this port is framed as `[opcode:1][payload][tag:8]`. The opcode is a
//! routing header and nothing more: each operation owns its own payload layout, its own width,
//! and its own codec in its own module. What the operations share is only the socket, the
//! handshake nonce, and the frame sequence that binds each tag to that connection.

use crate::{
    limiter::access::INVALIDATE_ACCESS_PAYLOAD_SIZE,
    limiter::access::MAX_REQUIRED_ACCESS,
    limiter::budget::MUTATE_BUDGET_PAYLOAD_SIZE,
    limiter::protocol::CHARGE_PAYLOAD_SIZE,
    lock::protocol::{ACQUIRE_PAYLOAD_SIZE, RELEASE_PAYLOAD_SIZE},
    reqlog::protocol::REQUEST_LOG_MAX_PAYLOAD_SIZE,
    sequence::protocol::{
        SEQUENCE_REPLY_EXTRA_SIZE, SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE, SEQUENCE_SET_MAX_PAYLOAD_SIZE,
    },
};

pub const OPCODE_SIZE: usize = 1;
pub const AUTH_TAG_SIZE: usize = 8;
/// Fixed head of every reply. The tail that may follow it is described by `extra_len`, the sixth
/// byte, which is zero for every opcode but a charge that asked for authorization.
pub const REPLY_HEAD_SIZE: usize = 6;

/// Widest tail a reply may carry, over every opcode that has one: `MAX_REQUIRED_ACCESS` slots of at
/// most two sub bytes each for a charge, and one `i64` for a sequence reservation. The two are the
/// same width today, which is exactly why this is a `max` — a narrower `MAX_REQUIRED_ACCESS` would
/// otherwise silently truncate a reserved value.
pub const REPLY_MAX_EXTRA_SIZE: usize = if 2 * MAX_REQUIRED_ACCESS > SEQUENCE_REPLY_EXTRA_SIZE {
    2 * MAX_REQUIRED_ACCESS
} else {
    SEQUENCE_REPLY_EXTRA_SIZE
};
/// Width of the length header a variable-payload opcode carries between the opcode and its
/// payload. Only `LOG_REQUEST` uses one — every other operation describes a fixed record whose
/// width the opcode already implies.
pub const LENGTH_PREFIX_SIZE: usize = 2;

/// "I could not answer." Deliberately not a valid decision for any opcode: the charge decoder
/// rejects it because its top bits are set, and the lock decoder treats an unknown status as
/// unavailable. The client applies operation policy—credits fail closed, while lock call sites
/// decide individually—instead of mistaking it for a real verdict.
pub const UNAVAILABLE_STATUS: u8 = 0xFF;

/// Builds the reply frame: `[correlation:u16][status:u8][detail:u16][extra_len:u8][extra…]`.
///
/// `correlation` is the low 16 bits of the request's frame sequence. Nothing new travels in the
/// request to carry it — the sequence already exists, is already per-connection and monotonic,
/// and both sides already track it for the tag. It is what lets a client match a reply to the
/// caller that is waiting for it once several requests are in flight at once; truncating to 16
/// bits only becomes ambiguous past 65_535 concurrent requests on one connection.
///
/// `status` keeps its per-opcode meaning, and zero is still success everywhere. `detail` carries
/// the lock generation on a granted acquire, and on a charge it packs the authorization verdict:
/// bits 0..2 the code, bits 3..6 which required slots were granted, bits 7..10 which of those
/// contributed sub bytes to the tail.
///
/// `extra_len` costs one byte on every reply that has nothing to say, and buys a single framing
/// that every opcode shares — the alternative was a per-opcode reply width, which the mux reader
/// would have to know the opcode to parse, having already forgotten it by then.
pub fn encode_reply(sequence: u64, status: u8, detail: u16, extra: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(REPLY_HEAD_SIZE + extra.len());
    reply.extend_from_slice(&((sequence & 0xFFFF) as u16).to_be_bytes());
    reply.push(status);
    reply.extend_from_slice(&detail.to_be_bytes());
    reply.push(extra.len() as u8);
    reply.extend_from_slice(extra);
    reply
}

/// Widest payload across every opcode, so one stack buffer serves them all. The request log is the
/// widest by far — it carries strings — but still small enough to keep the buffer on the stack.
const PREVIOUS_LARGEST_FIXED_PAYLOAD_SIZE: usize = if CHARGE_PAYLOAD_SIZE > ACQUIRE_PAYLOAD_SIZE {
    CHARGE_PAYLOAD_SIZE
} else {
    ACQUIRE_PAYLOAD_SIZE
};
const LARGEST_FIXED_PAYLOAD_SIZE: usize =
    if MUTATE_BUDGET_PAYLOAD_SIZE > PREVIOUS_LARGEST_FIXED_PAYLOAD_SIZE {
        MUTATE_BUDGET_PAYLOAD_SIZE
    } else {
        PREVIOUS_LARGEST_FIXED_PAYLOAD_SIZE
    };
// A set carries an i64 where a reservation carries a u32, so it is the wider of the two.
const LARGEST_SEQUENCE_PAYLOAD_SIZE: usize =
    if SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE > SEQUENCE_SET_MAX_PAYLOAD_SIZE {
        SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE
    } else {
        SEQUENCE_SET_MAX_PAYLOAD_SIZE
    };
const LARGEST_LENGTH_PREFIXED_PAYLOAD_SIZE: usize =
    if REQUEST_LOG_MAX_PAYLOAD_SIZE > LARGEST_SEQUENCE_PAYLOAD_SIZE {
        REQUEST_LOG_MAX_PAYLOAD_SIZE
    } else {
        LARGEST_SEQUENCE_PAYLOAD_SIZE
    };
const LARGEST_PAYLOAD_SIZE: usize =
    if LARGEST_FIXED_PAYLOAD_SIZE > LENGTH_PREFIX_SIZE + LARGEST_LENGTH_PREFIXED_PAYLOAD_SIZE {
        LARGEST_FIXED_PAYLOAD_SIZE
    } else {
        LENGTH_PREFIX_SIZE + LARGEST_LENGTH_PREFIXED_PAYLOAD_SIZE
    };
pub const MAX_FRAME_SIZE: usize = OPCODE_SIZE + LARGEST_PAYLOAD_SIZE + AUTH_TAG_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    ChargeCredits = 0x01,
    LockAcquire = 0x02,
    LockRelease = 0x03,
    LogRequest = 0x04,
    MutateCompanyBudget = 0x05,
    InvalidateUserAccess = 0x06,
    ReserveSequence = 0x07,
    SetSequence = 0x08,
}

/// How the reader learns where a frame's payload ends.
///
/// Every operation before the request log described a fixed record, so the opcode alone gave the
/// width. A request log carries a variable number of variable-length error strings, so it states
/// its own length — and is the only opcode that may, since a length header is what lets a client
/// ask the daemon to buffer an arbitrary amount before the tag is checked. The ceiling below is
/// what bounds that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadWidth {
    Fixed(usize),
    LengthPrefixed { maximum: usize },
}

impl Opcode {
    /// 0x00 stays permanently unassigned, so an all-zero frame from a broken or misconfigured
    /// client cannot route to a real operation.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::ChargeCredits),
            0x02 => Some(Self::LockAcquire),
            0x03 => Some(Self::LockRelease),
            0x04 => Some(Self::LogRequest),
            0x05 => Some(Self::MutateCompanyBudget),
            0x06 => Some(Self::InvalidateUserAccess),
            0x07 => Some(Self::ReserveSequence),
            0x08 => Some(Self::SetSequence),
            _ => None,
        }
    }

    pub fn payload_width(self) -> PayloadWidth {
        match self {
            Self::ChargeCredits => PayloadWidth::Fixed(CHARGE_PAYLOAD_SIZE),
            Self::LockAcquire => PayloadWidth::Fixed(ACQUIRE_PAYLOAD_SIZE),
            Self::LockRelease => PayloadWidth::Fixed(RELEASE_PAYLOAD_SIZE),
            Self::LogRequest => PayloadWidth::LengthPrefixed {
                maximum: REQUEST_LOG_MAX_PAYLOAD_SIZE,
            },
            Self::MutateCompanyBudget => PayloadWidth::Fixed(MUTATE_BUDGET_PAYLOAD_SIZE),
            Self::InvalidateUserAccess => PayloadWidth::Fixed(INVALIDATE_ACCESS_PAYLOAD_SIZE),
            // Length-prefixed for the same reason as the request log: it carries a counter name,
            // and a name is a string. The ceiling is what bounds what an unauthenticated peer can
            // ask the daemon to buffer.
            Self::ReserveSequence => PayloadWidth::LengthPrefixed {
                maximum: SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE,
            },
            // Same shape as a reservation, one field wider: an absolute i64 instead of a u32 count.
            Self::SetSequence => PayloadWidth::LengthPrefixed {
                maximum: SEQUENCE_SET_MAX_PAYLOAD_SIZE,
            },
        }
    }

    /// Whether the daemon answers this opcode at all.
    ///
    /// Two operations have nothing to say back. The request log is best effort, and making the
    /// caller wait for an acknowledgement would put the daemon's latency on the response path of
    /// every request in the system. An access invalidation is the same shape of promise: the TTL
    /// bounds the damage if it is lost, so a user save must not wait on it. Both write the frame
    /// and move on.
    pub fn expects_reply(self) -> bool {
        !matches!(self, Self::LogRequest | Self::InvalidateUserAccess)
    }

    /// Whole frame width for the fixed-width opcodes: opcode, payload, and tag.
    pub fn fixed_frame_size(self) -> Option<usize> {
        match self.payload_width() {
            PayloadWidth::Fixed(payload) => Some(OPCODE_SIZE + payload + AUTH_TAG_SIZE),
            PayloadWidth::LengthPrefixed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_fits_the_shared_buffer() {
        for opcode in [
            Opcode::ChargeCredits,
            Opcode::LockAcquire,
            Opcode::LockRelease,
            Opcode::LogRequest,
            Opcode::MutateCompanyBudget,
            Opcode::InvalidateUserAccess,
            Opcode::ReserveSequence,
            Opcode::SetSequence,
        ] {
            let widest = match opcode.payload_width() {
                PayloadWidth::Fixed(payload) => OPCODE_SIZE + payload + AUTH_TAG_SIZE,
                PayloadWidth::LengthPrefixed { maximum } => {
                    OPCODE_SIZE + LENGTH_PREFIX_SIZE + maximum + AUTH_TAG_SIZE
                }
            };
            assert!(widest <= MAX_FRAME_SIZE);
        }
    }

    #[test]
    fn the_string_carrying_opcodes_are_length_prefixed_and_two_are_unanswered() {
        // Both of these carry a string, which is the only reason an opcode may state its own
        // length: the width cannot be implied by the operation.
        for opcode in [Opcode::LogRequest, Opcode::ReserveSequence, Opcode::SetSequence] {
            assert!(matches!(
                opcode.payload_width(),
                PayloadWidth::LengthPrefixed { .. }
            ));
            assert_eq!(opcode.fixed_frame_size(), None);
        }
        assert_eq!(Opcode::from_byte(0x04), Some(Opcode::LogRequest));
        assert_eq!(Opcode::from_byte(0x07), Some(Opcode::ReserveSequence));
        assert_eq!(Opcode::from_byte(0x08), Some(Opcode::SetSequence));
        // A reservation is length-prefixed but still answered — the reserved value is the point of
        // the call, so unlike the request log a client does park a caller waiting for it.
        assert!(Opcode::ReserveSequence.expects_reply());
        // A set is answered too: it reports the value it replaced, which is the caller's only
        // record of what the counter held before a destructive repair.
        assert!(Opcode::SetSequence.expects_reply());

        // Nothing is sent back for either of these, so a client must not park a caller waiting.
        assert!(!Opcode::LogRequest.expects_reply());
        assert_eq!(Opcode::from_byte(0x06), Some(Opcode::InvalidateUserAccess));
        assert!(!Opcode::InvalidateUserAccess.expects_reply());
        for opcode in [
            Opcode::ChargeCredits,
            Opcode::LockAcquire,
            Opcode::LockRelease,
            Opcode::MutateCompanyBudget,
        ] {
            assert!(opcode.expects_reply());
            assert!(matches!(opcode.payload_width(), PayloadWidth::Fixed(_)));
        }
    }

    /// The reserved value is an `i64`, so a reply tail that could not carry eight bytes would
    /// truncate an id into a different, valid-looking id.
    #[test]
    fn the_reply_tail_can_carry_a_reserved_value() {
        assert!(REPLY_MAX_EXTRA_SIZE >= SEQUENCE_REPLY_EXTRA_SIZE);
    }

    #[test]
    fn the_reply_carries_the_truncated_sequence() {
        // The sixth byte is extra_len, zero on every reply that has no tail — which is every
        // opcode but a charge that asked for authorization.
        assert_eq!(encode_reply(0, 0, 0, &[]), [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(encode_reply(1, 27, 0, &[]), [0x00, 0x01, 0x1B, 0x00, 0x00, 0x00]);
        assert_eq!(encode_reply(7, 0, 300, &[]), [0x00, 0x07, 0x00, 0x01, 0x2C, 0x00]);
        // Only the low 16 bits travel, so a client correlates on the same truncation.
        assert_eq!(
            encode_reply(0x1_0002, 0, 0, &[]),
            [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// The tail is length-prefixed rather than implied by the opcode, because the mux reader that
    /// parses it has only the correlation id — by then it no longer knows which opcode this
    /// answers.
    #[test]
    fn the_reply_tail_is_length_prefixed() {
        assert_eq!(
            encode_reply(7, 0, 0b0000_0100_1001, &[0x06, 0x81, 0x20]),
            [0x00, 0x07, 0x00, 0x00, 0x49, 0x03, 0x06, 0x81, 0x20]
        );
        // A tail can never outgrow two sub bytes per required slot.
        assert!(REPLY_MAX_EXTRA_SIZE <= usize::from(u8::MAX));
    }

    #[test]
    fn every_opcode_keeps_its_documented_width() {
        assert_eq!(Opcode::from_byte(0x01), Some(Opcode::ChargeCredits));
        assert_eq!(Opcode::from_byte(0x02), Some(Opcode::LockAcquire));
        assert_eq!(Opcode::from_byte(0x03), Some(Opcode::LockRelease));
        // Opcode, then company, user, route, cpu, inference and four authorization slots, then
        // the tag.
        assert_eq!(Opcode::ChargeCredits.fixed_frame_size(), Some(29));
        // Company and user, and nothing else: which grants to drop is implied by the pair.
        assert_eq!(Opcode::InvalidateUserAccess.fixed_frame_size(), Some(15));
        assert_eq!(Opcode::LockAcquire.fixed_frame_size(), Some(24));
        // Release names the lock it ends: action, identifier, generation.
        assert_eq!(Opcode::LockRelease.fixed_frame_size(), Some(21));
        // Unassigned bytes must not resolve, or a garbage frame would be dispatched.
        assert_eq!(Opcode::from_byte(0x00), None);
        assert_eq!(Opcode::from_byte(0x09), None);
        assert_eq!(Opcode::from_byte(0xFF), None);
    }
}
