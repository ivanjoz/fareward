//! Two independent token codecs the bridge needs at its HTTP boundary.
//!
//! 1. The browser's session token: a colbin message holding the backend's
//!    `core.UsuarioToken`. The format itself lives in the `colbin` crate, which is the
//!    repository that defines it; what belongs here is the shape of *this* struct.
//! 2. The channel token, a small custom varint format naming one browser tab. It is not
//!    colbin and shares nothing with it beyond sitting at the same boundary.
//!
//! Both are mirrors of Go code in another repository, so every rule here is pinned by
//! vectors generated from that Go code — see `fareward/vectors`, which prints them.

use base64::{Engine, engine::general_purpose};
use colbin::Colbin;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("session token is not valid base64")]
    SessionBase64,
    #[error("session token is not a valid colbin message: {0}")]
    Session(#[from] colbin::Error),
    #[error("session token does not carry a 16-byte hash")]
    SessionHashWidth,
    #[error("channel token is not valid unpadded base64url")]
    ChannelBase64,
    #[error("channel token does not contain a company id")]
    ChannelCompanyID,
    #[error("channel token does not contain a user id")]
    ChannelUserID,
    #[error("channel token does not contain a 6-byte tab id")]
    ChannelTabID,
    #[error("channel token contains out-of-range identifiers")]
    ChannelRange,
    #[error("channel token is not canonically encoded")]
    ChannelNotCanonical,
}

/// Session identity proven by the token. Mirrors `core.UsuarioToken`; the `Error` and
/// `SubAccesos` fields carry `cb:"-"` in Go and are never on the wire.
///
/// `hash` is a fixed sixteen bytes here where Go has a `[]byte`, because this is the
/// credential the bridge compares and a width is the one thing the comparison cannot
/// check for itself. `SessionMessage` is what the wire actually carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserToken {
    pub company_id: i32,
    pub id: i32,
    pub created: i32,
    pub hash: [u8; 16],
    pub user: String,
}

/// The token exactly as colbin carries it.
///
/// The ids are the backend's own `cb` tags (`core.UsuarioToken`), copied rather than
/// derived. colbin can hash a field name into an id, but that would make this decoder agree
/// with the encoder only as long as two hash implementations in two languages agree, and
/// nothing would report a disagreement — every token would simply decode to zeros. A
/// declared id is a number, and `fareward/vectors` prints the backend's so the two can be
/// compared by eye. Ids under sixteen also put the message on four-bit keys, which is what
/// makes the token four bytes shorter than a derived-id one.
#[derive(Colbin, Debug, Default)]
struct SessionMessage {
    #[cb(1)]
    company_id: i32,
    #[cb(2)]
    id: i32,
    #[cb(3)]
    created: i32,
    #[cb(4)]
    hash: Vec<u8>,
    #[cb(5)]
    user: String,
}

/// Decodes the colbin payload of a session token.
///
/// A field holding its zero value is not written at all, so an absent key is not an error —
/// the generated decoder leaves the field at its default, which is the same answer the Go
/// decoder writes into the destination struct.
pub fn decode_session_token(payload: &[u8]) -> Result<UserToken, TokenError> {
    let message = SessionMessage::decode(payload)?;
    Ok(UserToken {
        company_id: message.company_id,
        id: message.id,
        created: message.created,
        // A wrong-width hash is refused here rather than compared: colbin omits a zero-valued
        // field entirely, so a token with no hash at all would otherwise arrive as an empty
        // slice and reach the tag comparison as if it had claimed something.
        hash: <[u8; 16]>::try_from(message.hash.as_slice())
            .map_err(|_| TokenError::SessionHashWidth)?,
        user: message.user,
    })
}

/// Undoes the backend's `MakeB64UrlEncode` alphabet substitution before standard base64
/// decoding (`core/helpers.go`).
pub fn decode_session_base64(encoded_token: &str) -> Result<Vec<u8>, TokenError> {
    let standard_alphabet: String = encoded_token
        .chars()
        .map(|character| match character {
            '_' => '/',
            '-' => '+',
            '~' => '=',
            other => other,
        })
        .collect();
    general_purpose::STANDARD
        .decode(standard_alphabet)
        .map_err(|_| TokenError::SessionBase64)
}

// --- Channel token (mirrored in backend/agent/channel.go, frontend/core/agent/channel.ts) ---

/// The tab's entropy: 6 bytes = 48 bits, exactly 8 base64url characters.
const TAB_RANDOM_BYTES: usize = 6;

/// Decodes a channel token into its company, user and tab parts.
///
/// Non-canonical encodings are rejected (an overlong varint names the same numbers with
/// different bytes). That rejection is what makes the token a bijection with the triple,
/// which is what lets it be used directly as the channel registry key: two distinct strings
/// can never name the same channel.
pub fn decode_channel_token(channel_token: &str) -> Result<(i32, i32, String), TokenError> {
    let token_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(channel_token)
        .map_err(|_| TokenError::ChannelBase64)?;

    let (company_value, company_byte_count) =
        read_uvarint(&token_bytes).ok_or(TokenError::ChannelCompanyID)?;
    let (user_value, user_byte_count) =
        read_uvarint(&token_bytes[company_byte_count..]).ok_or(TokenError::ChannelUserID)?;

    let tab_bytes = &token_bytes[company_byte_count + user_byte_count..];
    if tab_bytes.len() != TAB_RANDOM_BYTES {
        return Err(TokenError::ChannelTabID);
    }
    if company_value == 0
        || user_value == 0
        || company_value > i32::MAX as u64
        || user_value > i32::MAX as u64
    {
        return Err(TokenError::ChannelRange);
    }

    let company_id = company_value as i32;
    let user_id = user_value as i32;
    let tab_id = general_purpose::URL_SAFE_NO_PAD.encode(tab_bytes);

    // Canonicality by round-trip: cheaper than validating each varint by hand, and it
    // cannot miss a case.
    if encode_channel_token(company_id, user_id, &tab_id).as_deref() != Some(channel_token) {
        return Err(TokenError::ChannelNotCanonical);
    }
    Ok((company_id, user_id, tab_id))
}

/// Builds the token naming one tab. `tab_id` is the 8-character base64url form of the tab's
/// 6 random bytes; anything else yields `None`.
pub fn encode_channel_token(company_id: i32, user_id: i32, tab_id: &str) -> Option<String> {
    let tab_bytes = general_purpose::URL_SAFE_NO_PAD.decode(tab_id).ok()?;
    if tab_bytes.len() != TAB_RANDOM_BYTES || company_id <= 0 || user_id <= 0 {
        return None;
    }
    let mut token_bytes = Vec::with_capacity(8 + TAB_RANDOM_BYTES);
    append_uvarint(&mut token_bytes, company_id as u64);
    append_uvarint(&mut token_bytes, user_id as u64);
    token_bytes.extend_from_slice(&tab_bytes);
    Some(general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes))
}

/// Reads one LEB128 varint, returning the value and the bytes it consumed.
fn read_uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for (index, byte) in bytes.iter().enumerate() {
        if shift > 63 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}

fn append_uvarint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(value as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids are the whole of what this decoder and the backend's encoder agree on, and a
    /// disagreement is silent — a message names its fields by id, so a token whose ids moved
    /// decodes to zero values with nothing reported.
    ///
    /// Asserting the attributes would only restate them. Encoding a record and demanding the
    /// bytes Go wrote for the same one checks the ids, the key width and the field widths at
    /// once, in the only terms that matter.
    #[test]
    fn encodes_the_bytes_the_go_encoder_writes() {
        let (encoded, token) = &plain_vector();
        let message = SessionMessage {
            company_id: token.company_id,
            id: token.id,
            created: token.created,
            hash: token.hash.to_vec(),
            user: token.user.clone(),
        };
        assert_eq!(
            message.encode(),
            decode_session_base64(encoded).unwrap(),
            "the Rust encoder and the Go encoder disagree about this struct"
        );
        // Four-bit keys, which is what the ids under sixteen buy and what a derived id
        // would silently give up.
        assert_eq!(message.encode()[0], colbin::ROOT_STRUCT_NARROW);
    }

    /// The first vector, kept apart because two tests need it: this one to decode and
    /// `encodes_the_bytes_the_go_encoder_writes` to re-encode.
    fn plain_vector() -> (&'static str, UserToken) {
        (
            "0AkHGSoq0gQwEKPF9f1VhoUc4pBU9cq/paxABnRlc3Rlcg==",
            UserToken {
                company_id: 7,
                id: 42,
                created: 1234,
                hash: [
                    0xa3, 0xc5, 0xf5, 0xfd, 0x55, 0x86, 0x85, 0x1c, 0xe2, 0x90, 0x54, 0xf5, 0xca, 0xbf, 0xa5, 0xac,
                ],
                user: "tester".to_owned(),
            },
        )
    }

    /// Tokens produced by `colbin.Marshal` on the real Go struct, printed by
    /// `go run ./fareward/vectors`. Each covers a different shape: the plain case, an
    /// omitted field (`Created` is zero) with an empty string, the i32 maximum, multi-byte
    /// UTF-8, a long user name, and a negative value, which is what puts an integer on the
    /// zigzag path rather than the plain one.
    #[test]
    fn decodes_the_go_colbin_vectors() {
        let vectors: [(&str, UserToken); 6] = [
            plain_vector(),
            (
                "0AkBGQEwEJiOTkiEnLTMP17BTxX6aHs=",
                UserToken {
                    company_id: 1,
                    id: 1,
                    created: 0,
                    hash: [
                        0x98, 0x8e, 0x4e, 0x48, 0x84, 0x9c, 0xb4, 0xcc, 0x3f, 0x5e, 0xc1, 0x4f, 0x15, 0xfa, 0x68, 0x7b,
                    ],
                    user: String::new(),
                },
            ),
            (
                "0Az///9/HP///38s////fzAQ0+ETCkyqjMqzoW7D5ME/wEABeA==",
                UserToken {
                    company_id: 2_147_483_647,
                    id: 2_147_483_647,
                    created: 2_147_483_647,
                    hash: [
                        0xd3, 0xe1, 0x13, 0x0a, 0x4c, 0xaa, 0x8c, 0xca, 0xb3, 0xa1, 0x6e, 0xc3, 0xe4, 0xc1, 0x3f, 0xc0,
                    ],
                    user: "x".to_owned(),
                },
            ),
            (
                "0As/Qg8aOTAsAPFTZTAQb3gk58L3PbRDFHVREif2J0ATw7FhbmTDukBleGFtcGxlLmNvbQ==",
                UserToken {
                    company_id: 999_999,
                    id: 12_345,
                    created: 1_700_000_000,
                    hash: [
                        0x6f, 0x78, 0x24, 0xe7, 0xc2, 0xf7, 0x3d, 0xb4, 0x43, 0x14, 0x75, 0x51, 0x12, 0x27, 0xf6, 0x27,
                    ],
                    user: "ñandú@example.com".to_owned(),
                },
            ),
            (
                "0AmAGX8rAAABMBBOvsNoiyfP8pNCRHhqrsyPQCdhLXZlcnktbG9uZy11c2VyLW5hbWUtZm9yLXdpZHRoLXRlc3Rpbmc=",
                UserToken {
                    company_id: 128,
                    id: 127,
                    created: 65_536,
                    hash: [
                        0x4e, 0xbe, 0xc3, 0x68, 0x8b, 0x27, 0xcf, 0xf2, 0x93, 0x42, 0x44, 0x78, 0x6a, 0xae, 0xcc, 0x8f,
                    ],
                    user: "a-very-long-user-name-for-width-testing".to_owned(),
                },
            ),
            (
                "0AkDGQQhBTAQIG+CiZBEwb9cCidNHrQ2cUADbmVn",
                UserToken {
                    company_id: 3,
                    id: 4,
                    created: -5,
                    hash: [
                        0x20, 0x6f, 0x82, 0x89, 0x90, 0x44, 0xc1, 0xbf, 0x5c, 0x0a, 0x27, 0x4d, 0x1e, 0xb4, 0x36, 0x71,
                    ],
                    user: "neg".to_owned(),
                },
            ),
        ];

        for (encoded, expected) in vectors {
            let payload = decode_session_base64(encoded).unwrap();
            assert_eq!(
                decode_session_token(&payload).unwrap(),
                expected,
                "{encoded}"
            );
            // The backend publishes the same bytes under its own alphabet, so both spellings
            // of one token must name one identity.
            let url_alphabet: String = encoded
                .chars()
                .map(|character| match character {
                    '/' => '_',
                    '+' => '-',
                    '=' => '~',
                    other => other,
                })
                .collect();
            assert_eq!(
                decode_session_base64(&url_alphabet).unwrap(),
                payload,
                "{url_alphabet}"
            );
        }
    }

    #[test]
    fn rejects_a_truncated_or_mistyped_session_token() {
        // No root byte at all, which is a message that ended before it began.
        assert_eq!(
            decode_session_token(&[]),
            Err(TokenError::Session(colbin::Error::Truncated))
        );
        // Outside colbin's reserved 0xD0..0xDF range, so not a colbin message at all.
        assert_eq!(
            decode_session_token(&[0x0a, 0x01, 0x00]),
            Err(TokenError::Session(colbin::Error::BadRoot(0x0a)))
        );
        // A four-bit key run holding a key this struct does not declare. It cannot be
        // stepped over: four descriptor bits have no room for a class, so nothing can size
        // a field it cannot classify.
        assert!(matches!(
            decode_session_token(&[colbin::ROOT_STRUCT_NARROW, 0x59, 0x00]),
            Err(TokenError::Session(colbin::Error::UnknownKey(5)))
        ));
        // A token carrying a hash of the wrong width is refused before the comparison, not
        // padded into one that could be compared.
        let mut short_hash = SessionMessage::default();
        short_hash.hash = vec![1, 2, 3];
        assert_eq!(
            decode_session_token(&short_hash.encode()),
            Err(TokenError::SessionHashWidth)
        );
        assert_eq!(
            decode_session_base64("not base64!!"),
            Err(TokenError::SessionBase64)
        );
    }

    /// Cross-language vectors: the expected column was produced by the TypeScript codec in
    /// `frontend/core/agent/channel.ts` and already pinned Go. All three must agree.
    #[test]
    fn matches_the_cross_language_channel_vectors() {
        let vectors = [
            (1, 1, "N2xQaG8x", "AQE3bFBobzE"),
            (7, 42, "N2xQaG8x", "Byo3bFBobzE"),
            (127, 128, "N2xQaG8x", "f4ABN2xQaG8x"),
            (128, 127, "AAAAAAAA", "gAF_AAAAAAAA"),
            (999999, 1, "____buff", "v4Q9Af___27n3w"),
            (2147483647, 2147483647, "-_-_-_-_", "_____wf_____B_v_v_v_vw"),
            (16383, 16384, "N2xQaG8x", "_3-AgAE3bFBobzE"),
            (2097151, 2097152, "dGFyZGlv", "__9_gICAAXRhcmRpbw"),
        ];

        for (company_id, user_id, tab_id, expected_token) in vectors {
            assert_eq!(
                encode_channel_token(company_id, user_id, tab_id).as_deref(),
                Some(expected_token),
                "encode {company_id}/{user_id}/{tab_id}"
            );
            assert_eq!(
                decode_channel_token(expected_token).unwrap(),
                (company_id, user_id, tab_id.to_owned()),
                "decode {expected_token}"
            );
        }
    }

    #[test]
    fn rejects_non_canonical_and_malformed_channel_tokens() {
        // Overlong company varint (0x81 0x00 == 1): decodes to the same triple as "AQE...",
        // so accepting it would let one tab own two registry keys.
        let overlong =
            general_purpose::URL_SAFE_NO_PAD.encode([0x81, 0x00, 0x01, 1, 2, 3, 4, 5, 6]);
        assert_eq!(
            decode_channel_token(&overlong),
            Err(TokenError::ChannelNotCanonical)
        );

        // A zero id is not a valid identity.
        let zero_company = general_purpose::URL_SAFE_NO_PAD.encode([0x00, 0x01, 1, 2, 3, 4, 5, 6]);
        assert_eq!(
            decode_channel_token(&zero_company),
            Err(TokenError::ChannelRange)
        );

        // Tab id must be exactly 6 bytes.
        let short_tab = general_purpose::URL_SAFE_NO_PAD.encode([0x01, 0x01, 1, 2, 3]);
        assert_eq!(
            decode_channel_token(&short_tab),
            Err(TokenError::ChannelTabID)
        );

        assert_eq!(
            decode_channel_token("not base64!!"),
            Err(TokenError::ChannelBase64)
        );
        // Non-positive ids and a tab id that is not 6 decoded bytes have no valid encoding.
        assert_eq!(encode_channel_token(0, 1, "N2xQaG8x"), None);
        assert_eq!(encode_channel_token(1, -1, "N2xQaG8x"), None);
        assert_eq!(encode_channel_token(1, 1, "QUJD"), None);
    }

    #[test]
    fn session_base64_undoes_the_backend_alphabet() {
        // "_-~" stand in for "/+=" in the backend's URL-safe substitution.
        let payload = [0xFF_u8, 0xFE, 0xFD, 0x01];
        let standard = general_purpose::STANDARD.encode(payload);
        let substituted: String = standard
            .chars()
            .map(|character| match character {
                '/' => '_',
                '+' => '-',
                '=' => '~',
                other => other,
            })
            .collect();
        assert_eq!(decode_session_base64(&substituted).unwrap(), payload);
        // Standard base64 is accepted unchanged, which is what the Go tests emit.
        assert_eq!(decode_session_base64(&standard).unwrap(), payload);
    }
}
