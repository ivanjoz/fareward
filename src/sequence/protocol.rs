//! Payload codecs for opcodes `0x07` (reserve sequence) and `0x08` (set sequence).
//!
//! Transport concerns belong to `service`: this module decodes the two requests and nothing else.
//! The counter name travels verbatim as UTF-8 rather than as a hash, because the daemon has to
//! write it into the `sequences` row key that the ORM, `deploy.go` and a human at a CQL prompt all
//! read by that same name. Both payloads put their scalar first so the name can be the tail and
//! need no length of its own — the frame's own length header already bounds it.

use thiserror::Error;

/// The widest counter name accepted. The ORM's own names (`x{partition}_{table}_{part}`) are far
/// under this; the ceiling exists so a length header from a not-yet-authenticated peer cannot ask
/// the daemon to buffer an arbitrary string.
pub const SEQUENCE_NAME_MAX: usize = 128;
/// Width of the `increment` field that leads a reservation payload.
pub const SEQUENCE_INCREMENT_SIZE: usize = 4;
/// Width of the absolute `value` field that leads a set payload.
pub const SEQUENCE_VALUE_SIZE: usize = 8;
pub const SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE: usize = SEQUENCE_INCREMENT_SIZE + SEQUENCE_NAME_MAX;
pub const SEQUENCE_SET_MAX_PAYLOAD_SIZE: usize = SEQUENCE_VALUE_SIZE + SEQUENCE_NAME_MAX;
/// Both replies carry one `i64` in the tail, big-endian like every other fixed-width field on this
/// wire: the first reserved value for a reservation, the previous value for a set.
pub const SEQUENCE_REPLY_EXTRA_SIZE: usize = 8;

/// One reservation: `increment` consecutive values from the counter called `name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveRequest {
    pub name: String,
    pub increment: u32,
}

/// One absolute assignment: move the counter called `name` to `value`.
///
/// This is the repair path — restoring a backup, realigning a counter with the rows that actually
/// exist — and it is the reason it must come through the daemon rather than being written directly.
/// The daemon may be holding a block it derived from the old value; only it can drop that block in
/// the same breath as moving the counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRequest {
    pub name: String,
    pub value: i64,
}

/// The one-byte reply status. Zero is success for every opcode on this port.
///
/// A storage failure is not represented here: it answers with the shared `UNAVAILABLE_STATUS`,
/// like any other operation the daemon could not carry out. `Invalid` is separate because it means
/// the client sent something impossible, which no retry will fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SequenceReply {
    Ok = 0,
    Invalid = 1,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SequenceProtocolError {
    #[error("payload is too short to carry its leading scalar")]
    TooShort,
    #[error("increment must be positive")]
    EmptyIncrement,
    #[error("a counter cannot be set to a negative value")]
    NegativeValue,
    #[error("counter name is empty")]
    EmptyName,
    #[error("counter name exceeds {SEQUENCE_NAME_MAX} bytes")]
    NameTooLong,
    #[error("counter name is not valid UTF-8")]
    NonUtf8Name,
}

/// Shared tail of both payloads. Returns the name once it is known to be a usable row key.
fn parse_counter_name(name_bytes: &[u8]) -> Result<String, SequenceProtocolError> {
    if name_bytes.is_empty() {
        return Err(SequenceProtocolError::EmptyName);
    }
    // Unreachable from the wire, where the reader already refused anything past the ceiling, but
    // the codec has to hold on its own: it is what defines the limit the reader enforces.
    if name_bytes.len() > SEQUENCE_NAME_MAX {
        return Err(SequenceProtocolError::NameTooLong);
    }
    Ok(std::str::from_utf8(name_bytes)
        .map_err(|_| SequenceProtocolError::NonUtf8Name)?
        .to_owned())
}

pub fn parse_set(payload: &[u8]) -> Result<SetRequest, SequenceProtocolError> {
    if payload.len() < SEQUENCE_VALUE_SIZE {
        return Err(SequenceProtocolError::TooShort);
    }
    let value = i64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);
    // Zero is legitimate and means "this partition has no rows, hand out 1 next". Negative is not:
    // ids are primary keys, and a counter below zero is the damaged state the reserve path repairs.
    if value < 0 {
        return Err(SequenceProtocolError::NegativeValue);
    }
    Ok(SetRequest {
        name: parse_counter_name(&payload[SEQUENCE_VALUE_SIZE..])?,
        value,
    })
}

pub fn parse_reserve(payload: &[u8]) -> Result<ReserveRequest, SequenceProtocolError> {
    if payload.len() < SEQUENCE_INCREMENT_SIZE {
        return Err(SequenceProtocolError::TooShort);
    }
    let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    // A zero increment would reserve nothing and still have to answer with some value, which the
    // caller would then use as an id.
    if increment == 0 {
        return Err(SequenceProtocolError::EmptyIncrement);
    }

    Ok(ReserveRequest {
        name: parse_counter_name(&payload[SEQUENCE_INCREMENT_SIZE..])?,
        increment,
    })
}

/// Encodes the `i64` both replies carry: the first reserved value, or the value a set replaced.
pub fn encode_sequence_value(value: i64) -> [u8; SEQUENCE_REPLY_EXTRA_SIZE] {
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(increment: u32, name: &str) -> Vec<u8> {
        let mut bytes = increment.to_be_bytes().to_vec();
        bytes.extend_from_slice(name.as_bytes());
        bytes
    }

    #[test]
    fn parses_the_exact_wire_offsets() {
        let request = parse_reserve(&payload(7, "x12_productos_0")).unwrap();
        assert_eq!(request.increment, 7);
        assert_eq!(request.name, "x12_productos_0");
    }

    #[test]
    fn a_zero_increment_is_rejected() {
        assert_eq!(
            parse_reserve(&payload(0, "counter")),
            Err(SequenceProtocolError::EmptyIncrement)
        );
    }

    #[test]
    fn a_nameless_or_truncated_payload_is_rejected() {
        assert_eq!(
            parse_reserve(&payload(1, "")),
            Err(SequenceProtocolError::EmptyName)
        );
        assert_eq!(
            parse_reserve(&[0x00, 0x00, 0x01]),
            Err(SequenceProtocolError::TooShort)
        );
    }

    #[test]
    fn an_oversized_or_non_utf8_name_is_rejected() {
        let long_name = "n".repeat(SEQUENCE_NAME_MAX + 1);
        assert_eq!(
            parse_reserve(&payload(1, &long_name)),
            Err(SequenceProtocolError::NameTooLong)
        );

        let mut invalid = 1_u32.to_be_bytes().to_vec();
        invalid.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(
            parse_reserve(&invalid),
            Err(SequenceProtocolError::NonUtf8Name)
        );
    }

    /// The widest legal name must still fit the payload ceiling the reader enforces, or a valid
    /// request would be refused as an oversized frame.
    #[test]
    fn the_widest_legal_name_fits_the_payload_ceiling() {
        let widest = payload(u32::MAX, &"n".repeat(SEQUENCE_NAME_MAX));
        assert_eq!(widest.len(), SEQUENCE_RESERVE_MAX_PAYLOAD_SIZE);
        assert!(parse_reserve(&widest).is_ok());

        let widest_set = set_payload(i64::MAX, &"n".repeat(SEQUENCE_NAME_MAX));
        assert_eq!(widest_set.len(), SEQUENCE_SET_MAX_PAYLOAD_SIZE);
        assert!(parse_set(&widest_set).is_ok());
    }

    #[test]
    fn the_reply_value_travels_big_endian() {
        assert_eq!(encode_sequence_value(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            i64::from_be_bytes(encode_sequence_value(9_876_543_210)),
            9_876_543_210
        );
    }

    fn set_payload(value: i64, name: &str) -> Vec<u8> {
        let mut bytes = value.to_be_bytes().to_vec();
        bytes.extend_from_slice(name.as_bytes());
        bytes
    }

    #[test]
    fn a_set_parses_the_exact_wire_offsets() {
        let request = parse_set(&set_payload(4_242, "x7_ventas_0")).unwrap();
        assert_eq!(request.value, 4_242);
        assert_eq!(request.name, "x7_ventas_0");
    }

    /// Zero is the ordinary case for a partition whose rows were all deleted: the next reservation
    /// must then hand out 1.
    #[test]
    fn a_set_to_zero_is_allowed_but_a_negative_is_not() {
        assert_eq!(parse_set(&set_payload(0, "counter")).unwrap().value, 0);
        assert_eq!(
            parse_set(&set_payload(-1, "counter")),
            Err(SequenceProtocolError::NegativeValue)
        );
    }

    #[test]
    fn a_set_rejects_the_same_broken_names_a_reservation_does() {
        assert_eq!(
            parse_set(&set_payload(5, "")),
            Err(SequenceProtocolError::EmptyName)
        );
        assert_eq!(
            parse_set(&set_payload(5, &"n".repeat(SEQUENCE_NAME_MAX + 1))),
            Err(SequenceProtocolError::NameTooLong)
        );
        assert_eq!(
            parse_set(&[0x00, 0x00, 0x01]),
            Err(SequenceProtocolError::TooShort)
        );
    }
}
