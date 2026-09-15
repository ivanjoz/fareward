//! Payload codecs for opcodes `0x02` (acquire) and `0x03` (release).
//!
//! Transport concerns belong to `service`: this module decodes exactly the record that describes
//! one acquire or one release. Both are colbin messages, mirrored field id for field id by
//! `lockAcquireFrame` and `lockReleaseFrame` in fareward/go/locks.go.

use std::time::Duration;

use colbin::Colbin;
use thiserror::Error;

/// Ceilings on what a client can make the daemon buffer before its tag has been verified. Five and
/// three fields respectively, each at its widest.
pub const ACQUIRE_MAX_PAYLOAD_SIZE: usize = 40;
pub const RELEASE_MAX_PAYLOAD_SIZE: usize = 24;

/// The acquire frame as colbin carries it.
///
/// `wait_ms` and `lease_ms` are `u32` rather than the `u16` the fixed layout had room for. That is
/// the ceiling in §2.7 of PROTOCOL_SHAPES.md disappearing rather than being raised: a lease is now
/// bounded by what the daemon's configuration allows and not by what two bytes can spell, and a
/// short one still costs two bytes because colbin writes the bytes a value needs.
#[derive(Colbin, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcquireRequest {
    /// Namespace chosen by the Go caller. The daemon never interprets it; two features with
    /// different actions can never collide even on the same identifier.
    #[cb(1)]
    pub action: u16,
    /// Whatever the caller decided identifies the thing being serialized: an IP, a company, a
    /// client, a packed pair. Opaque here by design.
    #[cb(2)]
    pub identifier: i64,
    /// Queue ceiling. Zero means never queue, which turns the call into a try-lock.
    #[cb(3)]
    pub max_waiters: u8,
    #[cb(4)]
    pub wait_ms: u32,
    #[cb(5)]
    pub lease_ms: u32,
}

impl AcquireRequest {
    pub fn wait(&self) -> Duration {
        Duration::from_millis(u64::from(self.wait_ms))
    }

    pub fn lease(&self) -> Duration {
        Duration::from_millis(u64::from(self.lease_ms))
    }
}

/// Which hold a release is ending.
///
/// The key alone is not enough once one connection can carry several locks and several callers:
/// a release sent by a caller that already gave up would otherwise end whichever hold replaced
/// it on the same key. The generation pins it to one specific grant.
#[derive(Colbin, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReleaseRequest {
    #[cb(1)]
    pub action: u16,
    #[cb(2)]
    pub identifier: i64,
    #[cb(3)]
    pub generation: u16,
}

/// The one-byte reply. Zero is success for every opcode on this port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LockReply {
    Ok = 0,
    /// `max_waiters` were already queued, so nothing was queued for this caller.
    Busy = 1,
    /// `wait` elapsed without reaching the front of the queue.
    WaitTimeout = 2,
    /// A process-wide ceiling was hit: too many live keys or too many waiters overall.
    Capacity = 3,
    /// Acquiring while already holding, or releasing while holding nothing.
    Misuse = 4,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LockProtocolError {
    #[error("lock payload is not a valid colbin message: {0}")]
    Malformed(#[from] colbin::Error),
    #[error("lease_ms must be positive")]
    EmptyLease,
}

pub fn parse_acquire(payload: &[u8]) -> Result<AcquireRequest, LockProtocolError> {
    let request = AcquireRequest::decode(payload)?;
    // A zero lease would expire the hold the instant it was granted; a zero wait is legitimate
    // and means "try-lock". An absent field is a zero, so this also catches an empty payload.
    if request.lease_ms == 0 {
        return Err(LockProtocolError::EmptyLease);
    }
    Ok(request)
}

pub fn parse_release(payload: &[u8]) -> Result<ReleaseRequest, LockProtocolError> {
    Ok(ReleaseRequest::decode(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_round_trips() {
        let request = parse_release(
            &ReleaseRequest {
                action: 9,
                identifier: -7,
                generation: 300,
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(request.action, 9);
        // Negative identifiers must survive the round trip: the field is opaque, so the Go side
        // is free to pack anything into it.
        assert_eq!(request.identifier, -7);
        assert_eq!(request.generation, 300);
    }

    #[test]
    fn acquire_round_trips() {
        let request = parse_acquire(
            &AcquireRequest {
                action: 7,
                identifier: -42,
                max_waiters: 3,
                wait_ms: 5_000,
                lease_ms: 15_000,
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(request.action, 7);
        assert_eq!(request.identifier, -42);
        assert_eq!(request.max_waiters, 3);
        assert_eq!(request.wait(), Duration::from_millis(5_000));
        assert_eq!(request.lease(), Duration::from_millis(15_000));
    }

    /// The point of widening the two duration fields: a lease longer than 65535 ms used to be
    /// unrepresentable, so a critical section that ran for two minutes had no honest frame.
    #[test]
    fn a_lease_past_the_old_two_byte_ceiling_survives() {
        let request = parse_acquire(
            &AcquireRequest {
                action: 1,
                identifier: 1,
                max_waiters: 0,
                wait_ms: 0,
                lease_ms: 600_000,
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(request.lease(), Duration::from_secs(600));
    }

    #[test]
    fn a_zero_lease_is_rejected() {
        assert_eq!(
            parse_acquire(&AcquireRequest::default().encode()),
            Err(LockProtocolError::EmptyLease)
        );
    }

    #[test]
    fn refuses_a_payload_that_is_not_colbin() {
        assert!(matches!(
            parse_acquire(&[0x00; 15]),
            Err(LockProtocolError::Malformed(_))
        ));
        assert!(matches!(
            parse_release(&[0x00; 12]),
            Err(LockProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn the_ceilings_cover_the_widest_frames() {
        let acquire = AcquireRequest {
            action: u16::MAX,
            identifier: i64::MIN,
            max_waiters: u8::MAX,
            wait_ms: u32::MAX,
            lease_ms: u32::MAX,
        }
        .encode();
        assert!(
            acquire.len() <= ACQUIRE_MAX_PAYLOAD_SIZE,
            "widest acquire is {} bytes",
            acquire.len()
        );
        let release = ReleaseRequest {
            action: u16::MAX,
            identifier: i64::MIN,
            generation: u16::MAX,
        }
        .encode();
        assert!(
            release.len() <= RELEASE_MAX_PAYLOAD_SIZE,
            "widest release is {} bytes",
            release.len()
        );
    }
}
