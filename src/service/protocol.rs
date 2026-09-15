//! Opcode routing for the shared server-utilities TCP port.
//!
//! Every operation on this port is framed as `[opcode:1][length:u16][payload][tag:8]`. The opcode
//! is a routing header and nothing more: each operation owns its own payload layout and its own
//! codec in its own module. What the operations share is only the socket, the handshake nonce, and
//! the frame sequence that binds each tag to that connection.
//!
//! The length header is on every frame because every payload is now variable. Six of the eight are
//! colbin messages, which write the bytes a value needs and omit a zero-valued field entirely, and
//! the other two carry a counter name. Nothing is left that a fixed width could describe, so the
//! two framings that used to exist collapsed into the one that could carry both.

use crate::{
    limiter::access::INVALIDATE_ACCESS_MAX_PAYLOAD_SIZE,
    limiter::access::MAX_REQUIRED_ACCESS,
    limiter::budget::MUTATE_BUDGET_MAX_PAYLOAD_SIZE,
    limiter::protocol::CHARGE_MAX_PAYLOAD_SIZE,
    lock::protocol::{ACQUIRE_MAX_PAYLOAD_SIZE, RELEASE_MAX_PAYLOAD_SIZE},
    reqlog::protocol::REQUEST_LOG_MAX_PAYLOAD_SIZE,
    sequence::protocol::{
        SEQUENCE_REPLY_EXTRA_SIZE, SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE, SEQUENCE_SET_MAX_PAYLOAD_SIZE,
    },
};

pub const OPCODE_SIZE: usize = 1;
pub const AUTH_TAG_SIZE: usize = 8;
/// Fixed head of every reply: `[shape:1][correlation:u16]`. What follows is the body the shape
/// names, which is nothing at all for four of the eleven shapes.
pub const REPLY_HEAD_SIZE: usize = 3;

/// Widest body a reply may carry. A granted charge is the only variable one — two masks, a length
/// and at most two sub bytes per required slot — and a sequence value is the widest fixed one.
pub const REPLY_MAX_BODY_SIZE: usize = if 3 + 2 * MAX_REQUIRED_ACCESS > SEQUENCE_REPLY_EXTRA_SIZE {
    3 + 2 * MAX_REQUIRED_ACCESS
} else {
    SEQUENCE_REPLY_EXTRA_SIZE
};
/// Width of the length header every opcode carries between the opcode and its payload.
pub const LENGTH_PREFIX_SIZE: usize = 2;

/// What a reply is an answer to, and the whole of its layout.
///
/// Byte 0 of a reply used to be the correlation, and the answer itself lived in a `status` byte and
/// a `detail` u16 whose meaning depended on which request the correlation belonged to — so a client
/// could not read a reply without first remembering what it had asked. The shape says it instead:
/// each outcome has a name, a body of its own, and a width that follows from the name.
///
/// The byte costs nothing. It replaces the `extra_len` byte every reply used to carry, because a
/// shape that knows its own width does not need to state one, and only `ChargeGranted` has a body
/// that varies.
///
/// `0x80` and up are pushes: a frame the daemon sends without being asked. Nothing but `LockLost`
/// uses that range yet, and a client that meets an unknown one can skip it, because a push states
/// its own body length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplyShape {
    /// The charge went through and asked for no authorization.
    ChargeAllowed = 0x01,
    /// The charge went through and the user holds some of the required accesses.
    ChargeGranted = 0x02,
    /// Quota refused the charge. The body is the packed scope/window/resource bits.
    ChargeCreditViolation = 0x03,
    /// The session may not do this. The body is `AccessDenial`.
    ChargeAccessDenied = 0x04,
    /// The lock is held. The body is the generation that pins a later release to this grant.
    LockGranted = 0x05,
    /// The lock is not held. The body is `LockReply`, minus its success value.
    LockRefused = 0x06,
    /// It was done and there is nothing to say back: a released lock, a mutated budget.
    Ack = 0x07,
    /// The budget was not mutated. The body is `BudgetMutationReply`, minus its success value.
    BudgetRefused = 0x08,
    /// A reserved or replaced counter value.
    SequenceValue = 0x09,
    /// The sequence request was malformed, which no retry fixes.
    SequenceInvalid = 0x0A,
    /// "I could not answer." Every operation's policy for it stays on the client: credits fail
    /// closed, a sequence fails the write, lock call sites decide individually.
    Unavailable = 0x7F,
    /// A push: a lease elapsed and the daemon dropped a hold the client still believes it owns.
    LockLost = 0x80,
}

impl ReplyShape {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::ChargeAllowed),
            0x02 => Some(Self::ChargeGranted),
            0x03 => Some(Self::ChargeCreditViolation),
            0x04 => Some(Self::ChargeAccessDenied),
            0x05 => Some(Self::LockGranted),
            0x06 => Some(Self::LockRefused),
            0x07 => Some(Self::Ack),
            0x08 => Some(Self::BudgetRefused),
            0x09 => Some(Self::SequenceValue),
            0x0A => Some(Self::SequenceInvalid),
            0x7F => Some(Self::Unavailable),
            0x80 => Some(Self::LockLost),
            _ => None,
        }
    }

    /// Whether this shape is a push: a frame the daemon sends without being asked.
    ///
    /// Every push is `[len:u8][body]`, so a client that does not know one can step over it and keep
    /// the stream aligned. That is the whole point of reserving a range rather than adding shapes
    /// to the same space as the replies — a newer daemon can push something an older client has
    /// never heard of without killing its connection.
    pub fn is_push(self) -> bool {
        (self as u8) >= PUSH_FLOOR
    }

    /// How wide this shape's body is, or `None` when it states its own length — which is every
    /// push, and the one reply whose body varies.
    pub fn body_size(self) -> Option<usize> {
        match self {
            Self::ChargeAllowed | Self::Ack | Self::SequenceInvalid | Self::Unavailable => Some(0),
            Self::ChargeCreditViolation
            | Self::ChargeAccessDenied
            | Self::LockRefused
            | Self::BudgetRefused => Some(1),
            Self::LockGranted => Some(2),
            Self::SequenceValue => Some(SEQUENCE_REPLY_EXTRA_SIZE),
            // Two masks, a sub-byte count, and that many sub bytes.
            Self::ChargeGranted => None,
            // A push states its own length, so an unknown one is skippable.
            Self::LockLost => None,
        }
    }
}

/// The first shape byte reserved for pushes. Everything at or above it is a frame the daemon sends
/// without being asked, and carries `[len:u8][body]` so an unknown one can be skipped.
pub const PUSH_FLOOR: u8 = 0x80;

/// `[action:u16][identifier:i64]`: which hold the daemon dropped, behind the length every push has.
pub const LOCK_LOST_BODY_SIZE: usize = 10;

/// One answer, with its body. Building the frame is [`Reply::encode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    ChargeAllowed,
    /// `granted_mask` is which required slots the user holds; `sub_bytes` are those slots'
    /// sub-access runs, ascending, copied verbatim out of `accesos_sub_computed` — the daemon
    /// re-encodes nothing and still knows nothing about what a sub-access means.
    ChargeGranted {
        granted_mask: u8,
        has_subs_mask: u8,
        sub_bytes: Vec<u8>,
    },
    ChargeCreditViolation(u8),
    ChargeAccessDenied(u8),
    LockGranted {
        generation: u16,
    },
    LockRefused(u8),
    Ack,
    BudgetRefused(u8),
    SequenceValue(i64),
    SequenceInvalid,
    Unavailable,
    LockLost {
        action: u16,
        identifier: i64,
    },
}

impl Reply {
    pub fn shape(&self) -> ReplyShape {
        match self {
            Self::ChargeAllowed => ReplyShape::ChargeAllowed,
            Self::ChargeGranted { .. } => ReplyShape::ChargeGranted,
            Self::ChargeCreditViolation(_) => ReplyShape::ChargeCreditViolation,
            Self::ChargeAccessDenied(_) => ReplyShape::ChargeAccessDenied,
            Self::LockGranted { .. } => ReplyShape::LockGranted,
            Self::LockRefused(_) => ReplyShape::LockRefused,
            Self::Ack => ReplyShape::Ack,
            Self::BudgetRefused(_) => ReplyShape::BudgetRefused,
            Self::SequenceValue(_) => ReplyShape::SequenceValue,
            Self::SequenceInvalid => ReplyShape::SequenceInvalid,
            Self::Unavailable => ReplyShape::Unavailable,
            Self::LockLost { .. } => ReplyShape::LockLost,
        }
    }

    /// Builds the frame: `[shape:1][correlation:u16][body…]`.
    ///
    /// `correlation` is the low 16 bits of the request's frame sequence. Nothing new travels in the
    /// request to carry it — the sequence already exists, is already per-connection and monotonic,
    /// and both sides already track it for the tag. It is what lets a client match a reply to the
    /// caller that is waiting for it once several requests are in flight at once; truncating to 16
    /// bits only becomes ambiguous past 65_535 concurrent requests on one connection.
    ///
    /// A push has no request to correlate with and sends zero, which is a sequence a real reply can
    /// only reach after 65_535 frames — and a client routes on the shape before the correlation.
    pub fn encode(&self, sequence: u64) -> Vec<u8> {
        let mut frame = Vec::with_capacity(REPLY_HEAD_SIZE + REPLY_MAX_BODY_SIZE);
        frame.push(self.shape() as u8);
        frame.extend_from_slice(&((sequence & 0xFFFF) as u16).to_be_bytes());
        match self {
            Self::ChargeAllowed | Self::Ack | Self::SequenceInvalid | Self::Unavailable => {}
            Self::ChargeGranted {
                granted_mask,
                has_subs_mask,
                sub_bytes,
            } => {
                frame.push(*granted_mask);
                frame.push(*has_subs_mask);
                frame.push(sub_bytes.len() as u8);
                frame.extend_from_slice(sub_bytes);
            }
            Self::ChargeCreditViolation(code)
            | Self::ChargeAccessDenied(code)
            | Self::LockRefused(code)
            | Self::BudgetRefused(code) => frame.push(*code),
            Self::LockGranted { generation } => {
                frame.extend_from_slice(&generation.to_be_bytes())
            }
            Self::SequenceValue(value) => frame.extend_from_slice(&value.to_be_bytes()),
            Self::LockLost { action, identifier } => {
                // Length first: every push carries one so a client that predates the shape can
                // step over it instead of losing the connection.
                frame.push(LOCK_LOST_BODY_SIZE as u8);
                frame.extend_from_slice(&action.to_be_bytes());
                frame.extend_from_slice(&identifier.to_be_bytes());
            }
        }
        frame
    }
}

/// Widest payload across every opcode, so one stack buffer serves them all. The request log is the
/// widest by far — it carries strings — but still small enough to keep the buffer on the stack.
///
/// `const fn` rather than a chain of `if` expressions, which is what this was while the widths
/// came from two different families: eight opcodes, one rule, one place to add the ninth.
const fn larger(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

const LARGEST_PAYLOAD_SIZE: usize = larger(
    larger(
        larger(CHARGE_MAX_PAYLOAD_SIZE, ACQUIRE_MAX_PAYLOAD_SIZE),
        larger(RELEASE_MAX_PAYLOAD_SIZE, MUTATE_BUDGET_MAX_PAYLOAD_SIZE),
    ),
    larger(
        larger(INVALIDATE_ACCESS_MAX_PAYLOAD_SIZE, REQUEST_LOG_MAX_PAYLOAD_SIZE),
        larger(
            SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE,
            SEQUENCE_SET_MAX_PAYLOAD_SIZE,
        ),
    ),
);
pub const MAX_FRAME_SIZE: usize =
    OPCODE_SIZE + LENGTH_PREFIX_SIZE + LARGEST_PAYLOAD_SIZE + AUTH_TAG_SIZE;

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

    /// The most this opcode's payload may ever be, and therefore the most an unauthenticated peer
    /// can ask the daemon to buffer before its tag is checked. A frame declaring more than this is
    /// refused without being read.
    pub fn max_payload_size(self) -> usize {
        match self {
            Self::ChargeCredits => CHARGE_MAX_PAYLOAD_SIZE,
            Self::LockAcquire => ACQUIRE_MAX_PAYLOAD_SIZE,
            Self::LockRelease => RELEASE_MAX_PAYLOAD_SIZE,
            Self::LogRequest => REQUEST_LOG_MAX_PAYLOAD_SIZE,
            Self::MutateCompanyBudget => MUTATE_BUDGET_MAX_PAYLOAD_SIZE,
            Self::InvalidateUserAccess => INVALIDATE_ACCESS_MAX_PAYLOAD_SIZE,
            Self::ReserveSequence => SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE,
            // Same shape as a reservation, one field wider: an absolute i64 instead of a u32 count.
            Self::SetSequence => SEQUENCE_SET_MAX_PAYLOAD_SIZE,
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
            let widest =
                OPCODE_SIZE + LENGTH_PREFIX_SIZE + opcode.max_payload_size() + AUTH_TAG_SIZE;
            assert!(widest <= MAX_FRAME_SIZE);
        }
    }

    #[test]
    fn two_opcodes_are_unanswered_and_the_rest_are_answered() {
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
        }
    }

    /// The reserved value is an `i64`, so a body that could not carry eight bytes would truncate an
    /// id into a different, valid-looking id.
    #[test]
    fn the_widest_body_can_carry_a_reserved_value() {
        assert!(REPLY_MAX_BODY_SIZE >= SEQUENCE_REPLY_EXTRA_SIZE);
        // And a body length always fits the one byte that states it.
        assert!(REPLY_MAX_BODY_SIZE <= usize::from(u8::MAX));
    }

    #[test]
    fn a_bodiless_reply_is_three_bytes_and_carries_the_truncated_sequence() {
        assert_eq!(Reply::Ack.encode(0), [0x07, 0x00, 0x00]);
        assert_eq!(Reply::ChargeAllowed.encode(1), [0x01, 0x00, 0x01]);
        assert_eq!(Reply::Unavailable.encode(7), [0x7F, 0x00, 0x07]);
        assert_eq!(Reply::SequenceInvalid.encode(300), [0x0A, 0x01, 0x2C]);
        // Only the low 16 bits travel, so a client correlates on the same truncation.
        assert_eq!(Reply::Ack.encode(0x1_0002), [0x07, 0x00, 0x02]);
    }

    /// Each shape's body is its own, and the one that varies states its length — the rest are as
    /// wide as the shape says, which is what let the old `extra_len` byte go.
    #[test]
    fn every_shape_encodes_the_width_it_declares() {
        let cases = [
            Reply::ChargeAllowed,
            Reply::ChargeCreditViolation(0b1_1011),
            Reply::ChargeAccessDenied(3),
            Reply::LockGranted { generation: 300 },
            Reply::LockRefused(2),
            Reply::Ack,
            Reply::BudgetRefused(1),
            Reply::SequenceValue(9_876_543_210),
            Reply::SequenceInvalid,
            Reply::Unavailable,
        ];
        for reply in cases {
            let frame = reply.encode(42);
            let shape = ReplyShape::from_byte(frame[0]).expect("a shape it just wrote");
            assert_eq!(shape, reply.shape());
            assert!(!shape.is_push());
            assert_eq!(
                frame.len() - REPLY_HEAD_SIZE,
                shape.body_size().expect("a fixed body"),
                "{reply:?}"
            );
        }
    }

    /// A push states its own length, which is what lets a client step over one it does not know.
    #[test]
    fn a_push_is_length_prefixed_and_uncorrelated() {
        let frame = Reply::LockLost {
            action: 9,
            identifier: -7,
        }
        .encode(0);
        let shape = ReplyShape::from_byte(frame[0]).expect("a shape it just wrote");
        assert!(shape.is_push());
        assert_eq!(shape.body_size(), None);
        assert_eq!(u16::from_be_bytes([frame[1], frame[2]]), 0, "no correlation");
        assert_eq!(usize::from(frame[REPLY_HEAD_SIZE]), LOCK_LOST_BODY_SIZE);
        assert_eq!(frame.len(), REPLY_HEAD_SIZE + 1 + LOCK_LOST_BODY_SIZE);
    }

    #[test]
    fn the_bodies_carry_their_values() {
        assert_eq!(
            Reply::LockGranted { generation: 300 }.encode(7),
            [0x05, 0x00, 0x07, 0x01, 0x2C]
        );
        assert_eq!(
            Reply::SequenceValue(1).encode(7),
            [0x09, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            Reply::LockLost {
                action: 9,
                identifier: -7
            }
            .encode(0),
            [0x80, 0x00, 0x00, 0x0A, 0x00, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF9]
        );
    }

    /// A granted charge is the only reply whose body varies, so it is the only one that states its
    /// own length — the sub-access runs of the slots the user turned out to hold.
    #[test]
    fn a_granted_charge_states_its_sub_byte_count() {
        let frame = Reply::ChargeGranted {
            granted_mask: 0b101,
            has_subs_mask: 0b100,
            sub_bytes: vec![0x06, 0x81, 0x20],
        }
        .encode(7);
        assert_eq!(frame, [0x02, 0x00, 0x07, 0b101, 0b100, 0x03, 0x06, 0x81, 0x20]);
        assert_eq!(ReplyShape::ChargeGranted.body_size(), None);

        // And one that holds no sub-accesses still says so.
        let frame = Reply::ChargeGranted {
            granted_mask: 0b1,
            has_subs_mask: 0,
            sub_bytes: Vec::new(),
        }
        .encode(7);
        assert_eq!(frame, [0x02, 0x00, 0x07, 0b1, 0, 0]);
    }

    /// 0x00 must not resolve, or an all-zero frame from a broken peer would route to an outcome.
    /// The push range is what makes a `LockLost` a frame rather than an architecture change.
    #[test]
    fn the_shape_byte_is_a_closed_set_with_room_for_pushes() {
        assert_eq!(ReplyShape::from_byte(0x00), None);
        assert_eq!(ReplyShape::from_byte(0x0B), None);
        assert_eq!(ReplyShape::from_byte(0x81), None);
        assert_eq!(ReplyShape::from_byte(0x80), Some(ReplyShape::LockLost));
        assert!(ReplyShape::LockLost.is_push());
        assert!(!ReplyShape::Unavailable.is_push());
    }

    #[test]
    fn every_opcode_routes_and_bounds_what_it_will_buffer() {
        assert_eq!(Opcode::from_byte(0x01), Some(Opcode::ChargeCredits));
        assert_eq!(Opcode::from_byte(0x02), Some(Opcode::LockAcquire));
        assert_eq!(Opcode::from_byte(0x03), Some(Opcode::LockRelease));
        // Unassigned bytes must not resolve, or a garbage frame would be dispatched.
        assert_eq!(Opcode::from_byte(0x00), None);
        assert_eq!(Opcode::from_byte(0x09), None);
        assert_eq!(Opcode::from_byte(0xFF), None);

        // A ceiling is what an unauthenticated peer can make the daemon hold before the tag at the
        // end of the frame says whether to believe any of it, so every opcode needs one and none
        // of them may be large. The request log is the only one that carries strings.
        for opcode in [
            Opcode::ChargeCredits,
            Opcode::LockAcquire,
            Opcode::LockRelease,
            Opcode::MutateCompanyBudget,
            Opcode::InvalidateUserAccess,
        ] {
            let ceiling = opcode.max_payload_size();
            assert!(
                (1..=64).contains(&ceiling),
                "{opcode:?} declares a {ceiling}-byte ceiling"
            );
        }
        assert!(Opcode::LogRequest.max_payload_size() <= 4096);
    }
}
