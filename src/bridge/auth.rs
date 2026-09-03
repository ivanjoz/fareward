//! The bridge's two authentication schemes, each keyed by a different config secret.
//!
//!   - The **browser** presents the session token the backend already issued
//!     (`Authorization: Bearer <token>`). It is self-contained (colbin payload + tag), so
//!     identity is verified without touching ScyllaDB. Keyed by `secret_phrase`, because
//!     that is what signed it.
//!   - The **backend** presents a timestamped signature (`X-Bridge-Auth`). Keyed by
//!     `internal_apikey`, the project's service-to-service secret.
//!
//! Different primitives on purpose. The session token is a bearer credential held by an
//! untrusted party, so its tag is keyed BLAKE2s-128 — 128 bits, because the tag *is* the
//! credential. The service header is SipHash-2-4 like the raw-TCP frame tag: internal, verified
//! by one peer, and valid for 300 seconds. Each has its own domain string.
//!
//! The bridge only establishes *identity*. Permissions stay in the backend, which already
//! evaluated them when it accepted the turn.

use subtle::ConstantTimeEq;
use thiserror::Error;

use blake2::Blake2sMac;
use blake2::digest::{KeyInit, Mac, consts::U16};
use sha2::{Digest, Sha256};

use crate::bridge::token::{TokenError, UserToken, decode_session_base64, decode_session_token};
use crate::siphash::{SipHasher24, derive_key};

pub const SERVICE_AUTH_HEADER: &str = "X-Bridge-Auth";

/// Domain separation: keeps a service signature from ever validating against another tag
/// the project computes with the same key. `:v2` is SipHash-2-4; `:v1` was HMAC-SHA256.
const SERVICE_AUTH_PREFIX: &str = "sse-bridge:v2|";
/// Tolerates clock drift between the Lambda and this host while keeping a captured header
/// from being replayable forever.
const SERVICE_AUTH_MAX_SKEW_SECONDS: i64 = 300;
/// Domain separation for the session token, mirroring `core.ComputeUsuarioTokenHash`. `:v3` is
/// keyed BLAKE2s-128; `:v1` was truncated HMAC-SHA256 and `:v2` SipHash-2-4, both 64-bit. A bump
/// invalidates every token issued under the old one, so backend and daemon deploy together and
/// every browser session logs in again.
const SESSION_TOKEN_DOMAIN: &[u8] = b"usrToken:v3";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeAuthError {
    #[error("session token is missing")]
    MissingSessionToken,
    #[error("session token is malformed: {0}")]
    MalformedSessionToken(#[from] TokenError),
    #[error("session token does not identify a user")]
    NoIdentity,
    #[error("session token signature is invalid")]
    InvalidSessionSignature,
    #[error("the {SERVICE_AUTH_HEADER} header is missing")]
    MissingServiceAuth,
    #[error("service authentication header is malformed")]
    MalformedServiceAuth,
    #[error("service authentication expired ({0}s of skew)")]
    ExpiredServiceAuth(i64),
    #[error("service authentication signature is invalid")]
    InvalidServiceSignature,
}

/// Recomputes the session token's own keyed hash. Exact mirror of
/// `core.ComputeUsuarioTokenHash`: any change on the backend must be replicated here, since
/// a mismatch rejects every client.
///
/// Keyed BLAKE2s-128, not the 64-bit tag the frame protocol uses. This token is a bearer
/// credential held by an untrusted party and carrying no random component of its own, so the tag
/// *is* the credential and 128 bits is its whole strength. The key is SHA-256 of the phrase:
/// exactly the 32 bytes BLAKE2s takes at most, with every byte of a configuration string of any
/// length reaching it.
fn compute_user_token_hash(user_token: &UserToken, secret_phrase: &[u8]) -> [u8; 16] {
    let mut identity_bytes = [0_u8; 12];
    identity_bytes[0..4].copy_from_slice(&(user_token.company_id as u32).to_be_bytes());
    identity_bytes[4..8].copy_from_slice(&(user_token.id as u32).to_be_bytes());
    identity_bytes[8..12].copy_from_slice(&(user_token.created as u32).to_be_bytes());

    let token_key = Sha256::digest(secret_phrase);
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&token_key)
        .expect("BLAKE2s accepts a 32-byte key");
    mac.update(SESSION_TOKEN_DOMAIN);
    mac.update(&identity_bytes);
    mac.update(user_token.user.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Verifies the `Authorization: Bearer <token>` header and returns the identity it proves.
pub fn authenticate_user(
    authorization_header: Option<&str>,
    secret_phrase: &[u8],
) -> Result<UserToken, BridgeAuthError> {
    let header_value = authorization_header.unwrap_or_default().trim();
    if header_value.len() < 8 {
        return Err(BridgeAuthError::MissingSessionToken);
    }

    let encoded_token = header_value
        .strip_prefix("Bearer ")
        .unwrap_or(header_value)
        .trim();
    let user_token = decode_session_token(&decode_session_base64(encoded_token)?)?;
    if user_token.company_id <= 0 || user_token.id <= 0 {
        return Err(BridgeAuthError::NoIdentity);
    }

    // Constant-time comparison: a byte-by-byte early exit would leak the expected hash to a
    // caller able to time many attempts.
    let expected_hash = compute_user_token_hash(&user_token, secret_phrase);
    if !bool::from(expected_hash.ct_eq(&user_token.hash)) {
        return Err(BridgeAuthError::InvalidSessionSignature);
    }
    Ok(user_token)
}

/// Builds the value the backend sends on `X-Bridge-Auth`. Mirrored in
/// `backend/agent/bridge.go`, which lives in another module and cannot import this one.
pub fn make_service_auth_header(internal_apikey: &[u8], unix_seconds: i64) -> String {
    let mut hasher = SipHasher24::new(&derive_key(internal_apikey));
    hasher.write(format!("{SERVICE_AUTH_PREFIX}{unix_seconds}").as_bytes());
    // 16 hex characters, big-endian like every other tag the project puts on a wire.
    format!("{unix_seconds}.{:016x}", hasher.finish())
}

/// Validates the backend's signature and its freshness.
pub fn verify_service_auth(
    header_value: Option<&str>,
    internal_apikey: &[u8],
    now_unix_seconds: i64,
) -> Result<(), BridgeAuthError> {
    let header_value = header_value.unwrap_or_default().trim();
    if header_value.is_empty() {
        return Err(BridgeAuthError::MissingServiceAuth);
    }

    let (timestamp_text, _) = header_value
        .split_once('.')
        .ok_or(BridgeAuthError::MalformedServiceAuth)?;
    let signed_unix_seconds: i64 = timestamp_text
        .parse()
        .map_err(|_| BridgeAuthError::MalformedServiceAuth)?;

    let elapsed_seconds = (now_unix_seconds - signed_unix_seconds).abs();
    if elapsed_seconds > SERVICE_AUTH_MAX_SKEW_SECONDS {
        return Err(BridgeAuthError::ExpiredServiceAuth(elapsed_seconds));
    }

    let expected_header = make_service_auth_header(internal_apikey, signed_unix_seconds);
    if !bool::from(header_value.as_bytes().ct_eq(expected_header.as_bytes())) {
        return Err(BridgeAuthError::InvalidServiceSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The secret the Go-generated vectors below were produced with.
    const TEST_SECRET: &[u8] = b"K1OzWIN0yarCc9ge";

    /// Vector 1 of the colbin set: company 7, user 42, created 1234, user "tester", whose
    /// Hash field was computed by Go's `core.ComputeUsuarioTokenHash` with TEST_SECRET. If
    /// this passes, the Rust and Go session-token hashes agree byte for byte. Printed by
    /// `go run ./fareward/vectors`, which is also where token.rs's vectors come from.
    const GO_SESSION_TOKEN: &str = "Q5mjBvVTyUQDaLS4vr/KsJBDHJKqXvm3lFUt5ZPISSLgHw==";

    /// The official keyed BLAKE2s-128 vectors, taken from `golang.org/x/crypto/blake2s`'s own
    /// `hashes128` test table: key `00 01 … 1f`, message `00 01 … n-1`.
    ///
    /// This is what proves `Blake2sMac<U16>` here and `blake2s.New128` in Go are the same
    /// function. BLAKE2 folds the digest length and the key length into its parameter block, so
    /// BLAKE2s-128 keyed is *not* BLAKE2s-256 truncated — a mismatch would be invisible until
    /// every browser was rejected.
    #[test]
    fn matches_the_official_blake2s_128_keyed_vectors() {
        const OFFICIAL_VECTORS: [(usize, &str); 11] = [
        (0, "9536f9b267655743dee97b8a670f9f53"),
        (1, "13bacfb85b48a1223c595f8c1e7e82cb"),
        (2, "d47a9b1645e2feae501cd5fe44ce6333"),
        (31, "d114cc11e7d5b33a360c45f18d4c7c6e"),
        (32, "c43b5e836af88620a8a71b1652cb8640"),
        (33, "9491c653e8867ed73c1b4ac6b5a9bb4d"),
        (63, "ece382a8bd5018f1de5da44b72cea75b"),
        (64, "f1efa90d2547036841ecd3627fafbc36"),
        (65, "811ff8686d23a435ecbd0bdafcd27b1b"),
        (127, "25887fab1422700d7fa3edc0b20206e2"),
        (128, "8c09f698d03eaf88abf69f8147865ef6"),
        ];

        let key: [u8; 32] = core::array::from_fn(|index| index as u8);
        for (length, expected_hex) in OFFICIAL_VECTORS {
            let message: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key).unwrap();
            mac.update(&message);
            let tag: [u8; 16] = mac.finalize().into_bytes().into();
            let tag_hex: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(tag_hex, expected_hex, "length {length}");
        }
    }

    #[test]
    fn accepts_the_go_issued_session_token() {
        let authenticated =
            authenticate_user(Some(&format!("Bearer {GO_SESSION_TOKEN}")), TEST_SECRET).unwrap();
        assert_eq!(authenticated.company_id, 7);
        assert_eq!(authenticated.id, 42);
        assert_eq!(authenticated.user, "tester");
    }

    #[test]
    fn rejects_a_session_token_signed_with_another_secret() {
        // This is what stops a client from minting its own identity.
        assert_eq!(
            authenticate_user(Some(&format!("Bearer {GO_SESSION_TOKEN}")), b"otro-secreto"),
            Err(BridgeAuthError::InvalidSessionSignature)
        );
    }

    /// colbin omits a zero-valued field, so a token issued with an empty `Hash` carries no hash
    /// at all. Decoding must refuse it outright: reading the absent field as sixteen zeros and
    /// letting it reach the tag comparison is the one way widening the tag could be bypassed.
    /// Printed by `go run ./fareward/vectors`.
    #[test]
    fn rejects_a_token_that_carries_no_hash() {
        const HASHLESS_TOKEN: &str = "Q5mjBvVTyUQt5ZPISSLgHw~~";
        assert_eq!(
            authenticate_user(Some(&format!("Bearer {HASHLESS_TOKEN}")), TEST_SECRET),
            Err(BridgeAuthError::MalformedSessionToken(
                TokenError::SessionHashWidth
            ))
        );
    }

    #[test]
    fn rejects_a_missing_session_token() {
        assert_eq!(
            authenticate_user(None, TEST_SECRET),
            Err(BridgeAuthError::MissingSessionToken)
        );
        assert_eq!(
            authenticate_user(Some("Bearer "), TEST_SECRET),
            Err(BridgeAuthError::MissingSessionToken)
        );
    }

    /// Pins the service-auth header against the Go implementation. Produced by
    /// Go's `MakeServiceAuthHeader("K1OzWIN0yarCc9ge", 1700000000)`, which the backend mirrors
    /// in `backend/agent/bridge.go`.
    #[test]
    fn matches_the_go_service_auth_header() {
        assert_eq!(
            make_service_auth_header(TEST_SECRET, 1_700_000_000),
            "1700000000.7fde5fb0aac81f6e"
        );
    }

    #[test]
    fn accepts_a_fresh_service_signature_and_rejects_the_rest() {
        let now = 1_700_000_000_i64;
        let header = make_service_auth_header(TEST_SECRET, now);
        assert_eq!(verify_service_auth(Some(&header), TEST_SECRET, now), Ok(()));
        // Inside the skew window in both directions.
        assert_eq!(
            verify_service_auth(Some(&header), TEST_SECRET, now + 299),
            Ok(())
        );
        assert_eq!(
            verify_service_auth(Some(&header), TEST_SECRET, now - 299),
            Ok(())
        );

        assert_eq!(
            verify_service_auth(Some(&header), TEST_SECRET, now + 400),
            Err(BridgeAuthError::ExpiredServiceAuth(400))
        );
        let tampered = format!("{}ff", &header[..header.len() - 2]);
        assert_eq!(
            verify_service_auth(Some(&tampered), TEST_SECRET, now),
            Err(BridgeAuthError::InvalidServiceSignature)
        );
        assert_eq!(
            verify_service_auth(Some(&header), b"otra-clave", now),
            Err(BridgeAuthError::InvalidServiceSignature)
        );
        assert_eq!(
            verify_service_auth(Some("no-dot"), TEST_SECRET, now),
            Err(BridgeAuthError::MalformedServiceAuth)
        );
        assert_eq!(
            verify_service_auth(None, TEST_SECRET, now),
            Err(BridgeAuthError::MissingServiceAuth)
        );
    }
}
