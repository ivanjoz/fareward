//! Payload codec for opcode `0x04`, the end-of-request record.
//!
//! Transport concerns — the opcode byte, the length header, the authentication tag — belong to
//! `service`, so this module never sees them: it decodes exactly the bytes that describe one
//! finished request and the handful of code lines that failed inside it.
//!
//! This used to be the only hand-written variable-length parser on the port: three length idioms
//! (a byte, a `u16`, a count), a bounds check before each of them, and seven error variants for
//! the ways a peer could lie about a length. All of that is now colbin's, and what is left here is
//! the two rules that are about request logs rather than about bytes — the frame is inside the
//! day, and there are not more errors than the cap.

use colbin::Colbin;
use thiserror::Error;

/// Four errors is the cap the Go side enforces; past that a request is one failure cascading.
pub const MAX_ERRORS_PER_REQUEST: usize = 4;
/// Enough for "product-stock-movement.go:1204" several times over.
pub const MAX_CODE_LINE_BYTES: usize = 64;
/// The preview only. CloudWatch has the message in full.
pub const MAX_ERROR_TEXT_BYTES: usize = 200;

/// Ceiling on one request-log payload, and therefore on what a client can make the daemon buffer
/// before its tag has been verified.
///
/// Worth over-estimating rather than deriving exactly: it bounds a buffer, and a constant that
/// undercounts the widest legitimate frame would make the daemon refuse it as oversized. One error
/// row costs its key, a descriptor, an escape byte and the bytes themselves for each of two
/// strings, plus the id — call it 300 against a real worst case near 290.
pub const REQUEST_LOG_MAX_PAYLOAD_SIZE: usize = 64 + MAX_ERRORS_PER_REQUEST * 300;

/// Fifteen-minute slots in a day, four per hour.
pub const FRAMES_PER_DAY: u8 = 96;

/// One failing code line. A `Vec<ErrorEntry>` is a colbin field like any other: short runs travel
/// as a list of key runs and long ones transpose into columns, which the format decides per value.
///
/// Mirrors `RequestLogError` in fareward/go/request_log.go.
#[derive(Colbin, Clone, Debug, Default, PartialEq, Eq)]
pub struct ErrorEntry {
    /// Hashed from the code line by the Go side, which is the sole authority on the value. The
    /// daemon stores it and never recomputes it.
    #[cb(1)]
    pub id: i32,
    #[cb(2)]
    pub code_line: String,
    #[cb(3)]
    pub text: String,
}

/// Mirrors `RequestLogRecord` in fareward/go/request_log.go.
#[derive(Colbin, Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestLogRecord {
    #[cb(1)]
    pub date: i16,
    #[cb(2)]
    pub request_id: i64,
    #[cb(3)]
    pub route_id: i16,
    #[cb(4)]
    pub frame: u8,
    #[cb(5)]
    pub company_id: i32,
    #[cb(6)]
    pub user_id: i32,
    #[cb(7)]
    pub elapsed_ms: i16,
    #[cb(8)]
    pub errors: Vec<ErrorEntry>,
}

impl RequestLogRecord {
    /// Packs the three dimensions the dashboard groups by into one sortable integer.
    ///
    /// The frame leads deliberately: it makes one fifteen-minute slice of the day a single
    /// contiguous clustering range, which is what lets the dashboard poll forward instead of
    /// rereading the day.
    ///
    ///   bits 47..40  frame     (0..95)
    ///   bits 39..24  route_id
    ///   bits 23..0   company_id
    ///
    /// Mirrored in backend/core/types/user_logs.go — that is the side that *reads* the column, so
    /// the two must agree byte for byte or the dashboard silently ranges over the wrong rows. The
    /// vectors in both test files pin them together.
    pub fn frame_route_company_agg(&self) -> i64 {
        (self.frame as i64) << 40
            | ((self.route_id as u16) as i64) << 24
            | (self.company_id as i64) & 0xFF_FFFF
    }

    /// What lands in the error_count column. Capped by the parser, so this is always small.
    pub fn error_count(&self) -> i8 {
        self.errors.len() as i8
    }

    pub fn error_ids(&self) -> Vec<i32> {
        self.errors.iter().map(|entry| entry.id).collect()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestLogError {
    #[error("request log payload is not a valid colbin message: {0}")]
    Malformed(#[from] colbin::Error),
    #[error("frame {0} is outside the {FRAMES_PER_DAY} slots of a day")]
    InvalidFrame(u8),
    #[error("error count {0} exceeds the cap of {MAX_ERRORS_PER_REQUEST}")]
    TooManyErrors(usize),
    #[error("error block {0} declares a {1}-byte {2}, over its ceiling")]
    FieldTooLong(usize, usize, &'static str),
}

/// Decodes one request-log record.
///
/// The two string ceilings are still enforced here rather than left to the codec. They are not
/// framing — colbin would carry a 4 KB code line perfectly well — they are what stops one bad
/// record from widening a database column, and the Go client truncates to exactly these numbers
/// before sending. A frame past them means the two sides disagree, not that a string was long.
pub fn parse_request_log(payload: &[u8]) -> Result<RequestLogRecord, RequestLogError> {
    let record = RequestLogRecord::decode(payload)?;

    if record.frame >= FRAMES_PER_DAY {
        return Err(RequestLogError::InvalidFrame(record.frame));
    }
    if record.errors.len() > MAX_ERRORS_PER_REQUEST {
        return Err(RequestLogError::TooManyErrors(record.errors.len()));
    }
    for (block, entry) in record.errors.iter().enumerate() {
        if entry.code_line.len() > MAX_CODE_LINE_BYTES {
            return Err(RequestLogError::FieldTooLong(
                block,
                entry.code_line.len(),
                "code line",
            ));
        }
        if entry.text.len() > MAX_ERROR_TEXT_BYTES {
            return Err(RequestLogError::FieldTooLong(block, entry.text.len(), "text"));
        }
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> RequestLogRecord {
        RequestLogRecord {
            date: 20_500,
            request_id: 1_767_225_600_123,
            route_id: 102,
            frame: 41,
            company_id: 7,
            user_id: 42,
            elapsed_ms: 318,
            errors: vec![
                ErrorEntry {
                    id: 1_234_567,
                    code_line: "responses.go:539".to_string(),
                    text: "no se pudo obtener el registro".to_string(),
                },
                ErrorEntry {
                    id: 7_654_321,
                    code_line: "product-stock.go:1204".to_string(),
                    text: "error al consultar el stock".to_string(),
                },
            ],
        }
    }

    #[test]
    fn round_trips_a_record_with_errors() {
        let record = sample();
        assert_eq!(parse_request_log(&record.encode()).unwrap(), record);
    }

    /// The common case by far, and the one the format is kindest to: no errors means no error
    /// field at all, and every zero-valued header field is absent too.
    #[test]
    fn round_trips_a_record_with_no_errors() {
        let mut record = sample();
        record.errors.clear();
        let payload = record.encode();
        assert_eq!(parse_request_log(&payload).unwrap(), record);
        assert!(payload.len() < 40, "an error-free row is {} bytes", payload.len());
    }

    #[test]
    fn carries_every_field_of_a_record() {
        let record = parse_request_log(&sample().encode()).unwrap();
        assert_eq!(record.date, 20_500);
        assert_eq!(record.request_id, 1_767_225_600_123);
        assert_eq!(record.route_id, 102);
        assert_eq!(record.frame, 41);
        assert_eq!(record.company_id, 7);
        assert_eq!(record.user_id, 42);
        assert_eq!(record.elapsed_ms, 318);
        assert_eq!(record.error_count(), 2);
        assert_eq!(record.error_ids(), vec![1_234_567, 7_654_321]);
    }

    /// These are the same vectors as TestMakeFrameRouteCompanyAgg in
    /// backend/core/types/user_logs_test.go. If either side moves, the dashboard ranges over rows
    /// that were packed under a different layout and silently reports the wrong numbers.
    #[test]
    fn the_packed_key_matches_the_go_vectors() {
        let pack = |frame: u8, route_id: i16, company_id: i32| {
            RequestLogRecord {
                route_id,
                frame,
                company_id,
                ..Default::default()
            }
            .frame_route_company_agg()
        };

        assert_eq!(pack(0, 0, 0), 0);
        assert_eq!(pack(1, 0, 0), 1 << 40);
        assert_eq!(pack(0, 1, 0), 1 << 24);
        assert_eq!(pack(0, 0, 1), 1);
        assert_eq!(pack(95, 0, 0), 95 << 40);
        assert_eq!(pack(41, 102, 7), 41 << 40 | 102 << 24 | 7);
        assert_eq!(
            pack(95, 32767, 16_777_215),
            95_i64 << 40 | 32767_i64 << 24 | 16_777_215
        );
        // A frame's rows must never leak into the next frame's clustering range.
        assert!(pack(41, 32767, 16_777_215) < pack(42, 0, 0));
    }

    /// Bytes produced by the Go encoder, pasted in verbatim.
    ///
    /// Every other test here round-trips through this module's own encoder, which would agree with
    /// itself even if both halves drifted from Go together. This one cannot: it is the actual
    /// output of `encodeRequestLog(sampleRecord())` in fareward/go/request_log.go, printed by
    /// `TestEncodeRequestLogWireBytes`. Regenerate it from there if the layout changes on purpose.
    #[test]
    fn parses_bytes_produced_by_the_go_encoder() {
        let hex = "d00a14501e7ba8da769b01296638294907592a6a3e01703801360b87d61210107265737\
                   06f6e7365732e676f3a353339201e6e6f207365207075646f206f6274656e657220656c20\
                   726567697374726f";
        let payload: Vec<u8> = (0..hex.len() / 2)
            .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
            .collect();

        let record =
            parse_request_log(&payload).expect("the Go encoder produced an unparsable frame");
        assert_eq!(record.date, 20_500);
        assert_eq!(record.request_id, 1_767_225_600_123);
        assert_eq!(record.route_id, 102);
        assert_eq!(record.frame, 41);
        assert_eq!(record.company_id, 7);
        assert_eq!(record.user_id, 42);
        assert_eq!(record.elapsed_ms, 318);
        assert_eq!(record.errors.len(), 1);
        assert_eq!(record.errors[0].id, 1_234_567);
        assert_eq!(record.errors[0].code_line, "responses.go:539");
        assert_eq!(record.errors[0].text, "no se pudo obtener el registro");
        // And the column the dashboard ranges over comes out of those bytes correctly.
        assert_eq!(
            record.frame_route_company_agg(),
            41_i64 << 40 | 102_i64 << 24 | 7
        );
    }

    #[test]
    fn a_frame_outside_the_day_is_refused() {
        let mut record = sample();
        record.frame = FRAMES_PER_DAY;
        record.errors.clear();
        assert_eq!(
            parse_request_log(&record.encode()),
            Err(RequestLogError::InvalidFrame(FRAMES_PER_DAY))
        );
    }

    #[test]
    fn more_errors_than_the_cap_are_refused() {
        let mut record = sample();
        record.errors = (0..MAX_ERRORS_PER_REQUEST + 1)
            .map(|index| ErrorEntry {
                id: index as i32 + 1,
                code_line: "a.go:1".to_string(),
                text: "x".to_string(),
            })
            .collect();
        assert_eq!(
            parse_request_log(&record.encode()),
            Err(RequestLogError::TooManyErrors(MAX_ERRORS_PER_REQUEST + 1))
        );
    }

    /// A length that runs past the buffer is the one thing a variable-length frame must never act
    /// on: believing one is how a parser reads memory it was not given. It is colbin's job now
    /// rather than this module's, so what is asserted is that the job is being done.
    ///
    /// The claim is deliberately not "every truncation errors", because that is false and the
    /// reason is worth stating. Fields are `[key][descriptor][payload]` and a zero-valued field is
    /// not written, so a cut landing exactly on a field boundary yields a valid message with fewer
    /// fields — indistinguishable, by construction, from a record that never set them. What must
    /// never happen is the other thing: a truncated payload decoding as if it carried data it does
    /// not. So every cut either fails or yields strictly less than the original.
    ///
    /// Nothing reaches this function truncated in the first place. The frame's own length header
    /// and the tag over it are what say a payload arrived whole, and both are checked before this
    /// is called; this is the second line.
    #[test]
    fn a_truncated_payload_never_decodes_as_the_whole_record() {
        let record = sample();
        let full = record.encode();
        for truncated_at in 1..full.len() {
            let Ok(partial) = parse_request_log(&full[..truncated_at]) else {
                continue;
            };
            assert_ne!(
                partial, record,
                "a payload cut at {truncated_at} bytes decoded as the whole record"
            );
            assert!(
                partial.errors.len() < record.errors.len()
                    || partial.errors.iter().zip(&record.errors).all(|(a, b)| a == b),
                "a cut at {truncated_at} bytes invented an error block"
            );
        }
    }

    #[test]
    fn an_oversized_field_is_refused() {
        let mut record = sample();
        record.errors.truncate(1);
        record.errors[0].code_line = "x".repeat(MAX_CODE_LINE_BYTES + 1);
        assert_eq!(
            parse_request_log(&record.encode()),
            Err(RequestLogError::FieldTooLong(
                0,
                MAX_CODE_LINE_BYTES + 1,
                "code line"
            ))
        );
    }

    /// The Go codec is byte exact and will carry a string that is not UTF-8; a Rust `String`
    /// cannot be, so the decoder refuses it rather than replacing characters.
    #[test]
    fn invalid_utf8_is_refused() {
        let mut record = sample();
        record.errors.truncate(1);
        let mut payload = record.encode();
        let code_line_at = payload
            .windows(4)
            .position(|window| window == b"resp")
            .expect("the code line is in the payload");
        payload[code_line_at] = 0x80;
        assert_eq!(
            parse_request_log(&payload),
            Err(RequestLogError::Malformed(colbin::Error::NotUtf8))
        );
    }

    #[test]
    fn the_widest_possible_record_fits_the_declared_ceiling() {
        let record = RequestLogRecord {
            date: i16::MAX,
            request_id: i64::MAX,
            route_id: i16::MAX,
            frame: FRAMES_PER_DAY - 1,
            company_id: 16_777_215,
            user_id: i32::MAX,
            elapsed_ms: i16::MAX,
            errors: (0..MAX_ERRORS_PER_REQUEST)
                .map(|index| ErrorEntry {
                    id: i32::MAX,
                    code_line: "c".repeat(MAX_CODE_LINE_BYTES),
                    text: format!("{}{}", index, "t".repeat(MAX_ERROR_TEXT_BYTES - 1)),
                })
                .collect(),
        };
        let payload = record.encode();
        assert!(
            payload.len() <= REQUEST_LOG_MAX_PAYLOAD_SIZE,
            "widest record is {} bytes, ceiling is {REQUEST_LOG_MAX_PAYLOAD_SIZE}",
            payload.len()
        );
        assert_eq!(parse_request_log(&payload).unwrap(), record);
    }
}
