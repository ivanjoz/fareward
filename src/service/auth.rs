//! Domain-separated SipHash-2-4 authentication bound to a connection nonce and frame sequence.
//!
//! Transport-level, not service-level: every opcode on the shared port authenticates the same
//! way, and the opcode byte is inside the signed bytes so a frame cannot be replayed as a
//! different operation.

use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::siphash::{SipHasher24, derive_key};

/// Names the whole shared-port framing, request *and* reply, not one service.
///
/// Bumped on every wire change so a mismatched peer fails loudly at the first frame instead of
/// misreading bytes. `genix-rate-limiter:v1` was the opcode-less 19-byte frame; `:v1` here added
/// the opcode byte; `:v2` widened the reply to 5 bytes; `:v3` gave `LOCK_RELEASE` a payload; `:v4`
/// added `LOG_REQUEST`, the first length-prefixed frame and the first that is never answered; `:v5`
/// added `MUTATE_COMPANY_BUDGET`; `:v6` widened `CHARGE_CREDITS` with four authorization slots and
/// gave the reply's `detail` a meaning for that opcode, and added `INVALIDATE_USER_ACCESS`; `:v7`
/// renamed the string itself to `fareward` without changing a frame; `:v8` replaced truncated
/// HMAC-SHA256 with SipHash-2-4.
/// Replies are not themselves authenticated, so without the bump an old client would keep
/// authenticating fine, read 1 byte of a 5-byte reply, and silently misinterpret everything
/// after that.
/// A bump also covers changes that leave the frame layout alone: the `:v7` rename from
/// `genix-server-utils:v6` and the `:v8` primitive swap both invalidate every tag a peer on the
/// old string produces, which is exactly what a bump is for — the skew surfaces as a failed tag
/// on the first frame rather than as a silent misread. Backend and daemon must therefore be
/// deployed together across this boundary.
const DOMAIN: &[u8] = b"fareward:v9";

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("operating system random source failed: {0}")]
    Random(#[from] getrandom::Error),
}

pub fn new_nonce() -> Result<[u8; 8], AuthError> {
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce)?;
    Ok(nonce)
}

/// The tag is written big-endian, like every other fixed-width field on this wire.
///
/// The key is derived per frame: one SHA-256 compression of a short secret, which is less work
/// than the ipad/opad pair the HMAC this replaced needed before it hashed anything.
pub fn compute_hash(
    secret: &[u8],
    nonce: &[u8; 8],
    sequence: u64,
    authenticated_payload: &[u8],
) -> [u8; 8] {
    let mut hasher = SipHasher24::new(&derive_key(secret));
    hasher.write(DOMAIN);
    hasher.write(nonce);
    hasher.write(&sequence.to_be_bytes());
    hasher.write(authenticated_payload);
    hasher.finish().to_be_bytes()
}

pub fn verify_hash(
    secret: &[u8],
    nonce: &[u8; 8],
    sequence: u64,
    authenticated_payload: &[u8],
    received: &[u8; 8],
) -> bool {
    // Constant-time comparison avoids revealing a valid tag byte by byte.
    let expected = compute_hash(secret, nonce, sequence, authenticated_payload);
    bool::from(expected.ct_eq(received))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_and_sequence_change_the_hash() {
        let secret = b"test secret";
        let payload = b"12345678901";
        let first = compute_hash(secret, &[1; 8], 0, payload);
        assert_ne!(first, compute_hash(secret, &[2; 8], 0, payload));
        assert_ne!(first, compute_hash(secret, &[1; 8], 1, payload));
        assert!(verify_hash(secret, &[1; 8], 0, payload, &first));
    }

    #[test]
    fn the_opcode_is_part_of_the_signature() {
        // Same charge bytes under two opcodes must not share a tag, or a frame could be replayed
        // into a different operation.
        let secret = b"test-secret";
        let charge = [
            0x12, 0x34, 0x56, 0x00, 0x00, 0x2A, 0x04, 0x00, 0x07, 0x00, 0x09,
        ];
        let mut as_charge = vec![0x01_u8];
        as_charge.extend_from_slice(&charge);
        let mut as_other = vec![0x02_u8];
        as_other.extend_from_slice(&charge);
        assert_ne!(
            compute_hash(secret, &[1; 8], 0, &as_charge),
            compute_hash(secret, &[1; 8], 0, &as_other)
        );
    }

    #[test]
    fn matches_the_go_client_vectors() {
        // Regenerated for `fareward:v9`. Every tag here moved when the domain did, which is the
        // point of the domain: a peer still on `:v8` produces different bytes for the same frame
        // and is rejected at the first one rather than misreading the new reply layout.
        let secret = b"test-secret";
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        // Opcode 0x01 followed by the 20-byte charge payload: company, user, route 103, cpu 300,
        // inference 25, then two filled authorization slots so the vector covers the new bytes.
        let payload = [
            0x01, 0x12, 0x34, 0x56, 0x00, 0x00, 0x2A, 0x00, 0x67, 0x01, 0x2C, 0x00, 0x19, 0x01,
            0x39, 0x00, 0x8B, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            compute_hash(secret, &nonce, 0, &payload),
            [0xD2, 0xA6, 0x9B, 0x95, 0xEC, 0x5E, 0x0C, 0x94]
        );
        assert_eq!(
            compute_hash(secret, &nonce, 1, &payload),
            [0xF1, 0x7B, 0x93, 0xF3, 0xA4, 0x9D, 0x7D, 0x3E]
        );

        // Opcode 0x02 with action 7, identifier -42, 3 waiters, 5000 ms wait, 15000 ms lease.
        let acquire = [
            0x02, 0x00, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD6, 0x03, 0x13, 0x88,
            0x3A, 0x98,
        ];
        assert_eq!(
            compute_hash(secret, &nonce, 0, &acquire),
            [0x4B, 0xC6, 0x3A, 0x2A, 0xB5, 0x50, 0x44, 0x63]
        );

        // Opcode 0x06 for company 7 / user 300: the invalidation is signed like everything else.
        let invalidate = [0x06, 0x00, 0x00, 0x07, 0x00, 0x01, 0x2C];
        assert_eq!(
            compute_hash(secret, &nonce, 0, &invalidate),
            [0xB7, 0x90, 0xDA, 0x17, 0xF1, 0x4C, 0xCD, 0x92]
        );
    }
}
