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
///
/// `:v10` gave every reply a shape in byte 0, replacing the `[correlation][status][detail]
/// [extra_len]` head whose meaning depended on which request the correlation belonged to. A client
/// on `:v9` would read a shape byte as the high half of a correlation and be wrong about every
/// frame after it, so the bump is what makes a mixed pair fail at the first one.
///
/// Public because the integration tests and the cross-language vectors sign frames with it, and a
/// second copy of this string is exactly the kind of drift the bump exists to catch.
pub const DOMAIN: &[u8] = b"fareward:v11";

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
        // Regenerated for `fareward:v11`, from the Go client's own frame builder. Both the payloads
        // and the tags moved this time: the payloads because six of the eight request shapes became
        // colbin messages behind a length header, and the tags because the domain went with them.
        //
        // These are the exact bytes the Go client puts on the wire — the same frames its
        // TestChargeFrameMatchesTheRustAuthVector, TestAccessInvalidationFrameMatchesTheRustAuthVector
        // and TestAcquireAndReleaseFramesMatchTheRustVectors assert from the other end. Each is
        // signed by one implementation and verified by the other, which is the only way a framing
        // disagreement surfaces as a failing test rather than as a connection that dies on its
        // first frame in production.
        let secret = b"test-secret";
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];

        // Opcode 0x01, a 19-byte charge: company 0x123456, user 42, route 103, cpu 300,
        // inference 25, and two filled authorization slots.
        let charge = [
            0x01, 0x00, 0x13, 0xD0, 0x0B, 0x56, 0x34, 0x12, 0x19, 0x2A, 0x28, 0x67, 0x39, 0x2C,
            0x01, 0x48, 0x19, 0x69, 0x39, 0x01, 0x78, 0x8B,
        ];
        assert_eq!(
            compute_hash(secret, &nonce, 0, &charge),
            [0x4F, 0xC0, 0xB8, 0xD1, 0xBA, 0xE0, 0x72, 0x76]
        );
        assert_eq!(
            compute_hash(secret, &nonce, 1, &charge),
            [0xD3, 0x87, 0x19, 0xB6, 0xF0, 0x84, 0x90, 0x66]
        );

        // Opcode 0x02 with action 7, identifier -42, 3 waiters, 5000 ms wait, 15000 ms lease.
        let acquire = [
            0x02, 0x00, 0x0B, 0xD0, 0x07, 0x11, 0x2A, 0x23, 0x39, 0x88, 0x13, 0x49, 0x98, 0x3A,
        ];
        assert_eq!(
            compute_hash(secret, &nonce, 0, &acquire),
            [0xCD, 0xE6, 0xD2, 0x58, 0xF9, 0xB7, 0x7A, 0x2C]
        );

        // Opcode 0x06 for company 7 / user 300: the invalidation is signed like everything else.
        let invalidate = [0x06, 0x00, 0x06, 0xD0, 0x09, 0x07, 0x1A, 0x2C, 0x01];
        assert_eq!(
            compute_hash(secret, &nonce, 0, &invalidate),
            [0x02, 0xA6, 0x4D, 0x42, 0xA1, 0x56, 0xA8, 0x01]
        );
    }

    /// The frames above are not just signed by the daemon — they are what its own decoders read.
    /// Signing bytes nobody parses would pin the tag and miss the payload entirely.
    #[test]
    fn the_go_client_vectors_are_frames_this_daemon_can_parse() {
        use crate::limiter::access::parse_access_invalidation;
        use crate::limiter::protocol::parse_charge;
        use crate::lock::protocol::parse_acquire;

        // Payload only: past the opcode and the two-byte length, and these carry no tag.
        let charge = parse_charge(&[
            0xD0, 0x0B, 0x56, 0x34, 0x12, 0x19, 0x2A, 0x28, 0x67, 0x39, 0x2C, 0x01, 0x48, 0x19,
            0x69, 0x39, 0x01, 0x78, 0x8B,
        ])
        .expect("the Go client's charge payload must parse");
        assert_eq!(charge.company_id, 0x12_34_56);
        assert_eq!(charge.user_id, 42);
        assert_eq!(charge.route_id, 103);
        assert_eq!(charge.credits.cpu, 300);
        assert_eq!(charge.credits.inference, 25);
        assert_eq!(charge.required_access, [0x0139, 0x008B, 0, 0]);

        let acquire = parse_acquire(&[0xD0, 0x07, 0x11, 0x2A, 0x23, 0x39, 0x88, 0x13, 0x49, 0x98, 0x3A])
            .expect("the Go client's acquire payload must parse");
        assert_eq!(acquire.action, 7);
        assert_eq!(acquire.identifier, -42);
        assert_eq!(acquire.max_waiters, 3);
        assert_eq!(acquire.wait_ms, 5_000);
        assert_eq!(acquire.lease_ms, 15_000);

        let invalidate = parse_access_invalidation(&[0xD0, 0x09, 0x07, 0x1A, 0x2C, 0x01])
            .expect("the Go client's invalidation payload must parse");
        assert_eq!(invalidate.company_id, 7);
        assert_eq!(invalidate.user_id, 300);
    }
}
