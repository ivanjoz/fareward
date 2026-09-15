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
/// Both answers carry one `i64`, big-endian like every other fixed-width field on this wire: the
/// first reserved value for a reservation, the previous value for a set. The outcome itself is the
/// reply's shape — `SequenceValue`, `SequenceInvalid`, or the shared `Unavailable` for a storage
/// failure — so no status byte rides alongside it.
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

/// A cursor over a payload, so a parser names the widths it reads instead of counting offsets.
///
/// The two requests here share one layout rule — a scalar, then the counter name as the rest of the
/// frame — and it used to live in a comment with the offsets spelled out at every use. `rest` is
/// that rule, stated once.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(SEQUENCE_INCREMENT_SIZE)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i64(&mut self) -> Option<i64> {
        let bytes = self.take(SEQUENCE_VALUE_SIZE)?;
        Some(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Everything the scalar did not consume, which is where the counter name lives: it needs no
    /// length of its own because the frame's own length header already bounds it.
    fn rest(self) -> &'a [u8] {
        &self.bytes[self.at..]
    }
}

pub fn parse_set(payload: &[u8]) -> Result<SetRequest, SequenceProtocolError> {
    let mut cursor = Cursor::new(payload);
    let value = cursor.i64().ok_or(SequenceProtocolError::TooShort)?;
    // Zero is legitimate and means "this partition has no rows, hand out 1 next". Negative is not:
    // ids are primary keys, and a counter below zero is the damaged state the reserve path repairs.
    if value < 0 {
        return Err(SequenceProtocolError::NegativeValue);
    }
    Ok(SetRequest {
        name: parse_counter_name(cursor.rest())?,
        value,
    })
}

pub fn parse_reserve(payload: &[u8]) -> Result<ReserveRequest, SequenceProtocolError> {
    let mut cursor = Cursor::new(payload);
    let increment = cursor.u32().ok_or(SequenceProtocolError::TooShort)?;
    // A zero increment would reserve nothing and still have to answer with some value, which the
    // caller would then use as an id.
    if increment == 0 {
        return Err(SequenceProtocolError::EmptyIncrement);
    }

    Ok(ReserveRequest {
        name: parse_counter_name(cursor.rest())?,
        increment,
    })
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

    /// Bytes produced by the Go client, pasted in verbatim.
    ///
    /// Every other test here round-trips through this module's own `payload` helper, which would
    /// agree with itself even if both halves drifted from Go together. This one cannot: it is what
    /// `ReserveSequence` and `SetSequence` actually put on the wire in
    /// fareward/go/sequences.go, and it is what pins the one layout rule neither side states in
    /// code — the scalar leads, and the counter name is the rest of the frame.
    ///
    /// Regenerate from the Go side if the layout ever changes on purpose.
    #[test]
    fn parses_payloads_produced_by_the_go_client() {
        // ReserveSequence(name: "x12_productos_0", increment: 5).
        let reserve = [
            0x00, 0x00, 0x00, 0x05, 0x78, 0x31, 0x32, 0x5F, 0x70, 0x72, 0x6F, 0x64, 0x75, 0x63,
            0x74, 0x6F, 0x73, 0x5F, 0x30,
        ];
        let request = parse_reserve(&reserve).expect("the Go client produced an unparsable frame");
        assert_eq!(request.increment, 5);
        assert_eq!(request.name, "x12_productos_0");

        // SetSequence(name: "x7_ventas_0", value: 4242).
        let set = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x92, 0x78, 0x37, 0x5F, 0x76, 0x65, 0x6E,
            0x74, 0x61, 0x73, 0x5F, 0x30,
        ];
        let request = parse_set(&set).expect("the Go client produced an unparsable frame");
        assert_eq!(request.value, 4242);
        assert_eq!(request.name, "x7_ventas_0");
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
