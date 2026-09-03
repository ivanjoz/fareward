//! One user's authorization grants, held in memory and answered without touching ScyllaDB.
//!
//! This is the half of the charge frame that is not about credits. The Go router used to answer it
//! itself with a `SELECT accesos_computed FROM users` behind a five-minute in-process cache, which
//! is nearly free on a VPS and expensive on Lambda: every new execution environment starts cold and
//! pays a database round trip on the authorization path before the handler runs. This daemon is the
//! one process that is always resident, so the answer lives here and the frame that was already
//! going out carries the question.
//!
//! What this module deliberately does not know: access *names*, which route maps to which access,
//! that `access_list.yml` exists at all. It answers "does this user hold any of these grants" and
//! every policy rule around that — an unmapped GET being free, `POST.user-self` needing no access,
//! user 1 bypassing the check entirely — stays in Go, where the catalogue is embedded.

use crate::limiter::storage::StoredUserAccess;

/// How many required grants one frame can carry. `access_list.yml` maps at most two accesses to any
/// one backend route today, so this is 2x headroom for eight bytes of frame. A route that needs a
/// fifth is refused Go-side at encode time, never here — a rejected frame is indistinguishable from
/// the daemon being down and would surface as a 503 instead of as the bug it is.
pub const MAX_REQUIRED_ACCESS: usize = 4;

/// Payload of opcode `0x06`: `[company:u24][user:u24]`.
pub const INVALIDATE_ACCESS_PAYLOAD_SIZE: usize = 6;

/// Which cached grants to drop. `user_id == 0` is the wildcard, since user ids start at 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessInvalidation {
    pub company_id: i32,
    /// Zero means every cached user of the company.
    pub user_id: i32,
}

/// Decodes one invalidation. Only the company is required to be real: a wildcard is the point of
/// user zero, and a stale entry for a user the backend has since deleted is still worth dropping.
pub fn parse_access_invalidation(
    payload: &[u8; INVALIDATE_ACCESS_PAYLOAD_SIZE],
) -> anyhow::Result<AccessInvalidation> {
    let company_id = read_u24(&payload[0..3]) as i32;
    let user_id = read_u24(&payload[3..6]) as i32;
    if company_id <= 0 {
        anyhow::bail!("company_id must be positive");
    }
    Ok(AccessInvalidation {
        company_id,
        user_id,
    })
}

fn read_u24(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
}

/// `users.status` value that means the user exists and may act. Anything else — 0 from a soft
/// delete, or a value some future migration invents — is refused.
const ACTIVE_USER_STATUS: i8 = 1;

/// Why a request was refused. Distinct from a credit violation: these say something about the
/// session or the user, not about how much the tenant has spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessDenial {
    /// The user holds none of the required accesses at the required level.
    NoAccess = 2,
    /// No such user in this company. The token decoded and its tag checked, so this means the
    /// user was hard-deleted, or the token names a company the user does not belong to.
    UnknownUser = 3,
    /// The row exists but `status != 1`.
    InactiveUser = 4,
}

impl AccessDenial {
    /// Rides in the reply frame's `detail` field. 0 and 1 are reserved for "not requested" and
    /// "granted", which is why these start at 2.
    pub fn detail_code(self) -> u16 {
        self as u16
    }
}

/// The verdict for one charge frame's authorization question.
///
/// It is no longer a yes/no: the Go gate asks about up to `MAX_REQUIRED_ACCESS` accesses at once
/// and needs to know *which* of them the user holds and what sub-accesses ride along, so a handler
/// can act on them. `granted_mask` and `sub_bytes` are what the reply frame carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessVerdict {
    /// Bit N set = `required_access[N]` is held at or above the level asked for.
    pub granted_mask: u8,
    /// Bit N set = slot N contributed bytes to `sub_bytes`.
    pub has_subs_mask: u8,
    /// The sub-access runs of the slots in `has_subs_mask`, ascending, copied verbatim out of the
    /// cached blob. Nothing is re-encoded: the wire format and the stored format are the same one.
    pub sub_bytes: Vec<u8>,
}

impl AccessVerdict {
    pub fn is_granted(&self) -> bool {
        self.granted_mask != 0
    }
}

/// One user's cached authorization state.
///
/// Both blobs are held **verbatim**, exactly as ScyllaDB returned them. The `Vec<u16>` this used to
/// decode into was an allocation and a sort per cache load that bought nothing: the Go ORM writes
/// `[]byte` through a `reflect.Copy` fast path, so the bytes on both sides are already identical.
///
/// Which blob an access is in is itself information — `grants` holds accesses with no sub-access at
/// a fixed 2-byte stride, `sub_grants` holds the rest with their sub bytes appended — which is what
/// lets the grant word keep all 14 of its id bits instead of spending one on a "sub bytes follow"
/// flag. See `backend/core/accesos-blob.go`, the only writer of these bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAccessState {
    /// `accesos_computed`: grant words only, ascending, `[14 bits acceso_id][2 bits nivel-1]` BE.
    grants: Box<[u8]>,
    /// `accesos_sub_computed`: the same grant word, each followed by `[1 bit MORE][7 bits flags]`
    /// sub bytes. Ascending, variable width.
    sub_grants: Box<[u8]>,
    status: i8,
    /// Whether the row exists at all. A miss is cached like a hit, or a token naming a deleted user
    /// would re-query ScyllaDB on every request it sends.
    found: bool,
    /// Unix seconds of the load. Reloaded once older than the configured TTL.
    loaded_at: i64,
}

/// Width of one grant word, in both blobs.
const GRANT_WORD_SIZE: usize = 2;
/// The low bit of a sub byte set means another follows.
const SUB_MORE_BIT: u8 = 0x80;

impl UserAccessState {
    /// Builds the cached state from the row, or from its absence.
    pub fn from_row(row: Option<StoredUserAccess>, loaded_at: i64) -> anyhow::Result<Self> {
        let Some(row) = row else {
            return Ok(Self {
                grants: Box::from([]),
                sub_grants: Box::from([]),
                status: 0,
                found: false,
                loaded_at,
            });
        };
        validate_grants(&row.grants_blob)?;
        validate_sub_grants(&row.sub_grants_blob)?;
        Ok(Self {
            grants: row.grants_blob.into_boxed_slice(),
            sub_grants: row.sub_grants_blob.into_boxed_slice(),
            status: row.status,
            found: true,
            loaded_at,
        })
    }

    pub fn is_fresh(&self, unix_seconds: i64, ttl_seconds: i64) -> bool {
        // A clock that went backwards reads as stale rather than as fresh forever.
        unix_seconds >= self.loaded_at && unix_seconds - self.loaded_at <= ttl_seconds
    }

    /// The verdict for one frame's required grants. `Ok` is granted, `Err` is the denial.
    ///
    /// Identity is checked before grants: a request from a user who no longer exists is not a
    /// permission problem and must not be reported as one, because the two produce different HTTP
    /// answers on the Go side (401 versus 403).
    pub fn verdict(
        &self,
        required: &[u16; MAX_REQUIRED_ACCESS],
    ) -> Result<AccessVerdict, AccessDenial> {
        if !self.found {
            return Err(AccessDenial::UnknownUser);
        }
        if self.status != ACTIVE_USER_STATUS {
            return Err(AccessDenial::InactiveUser);
        }

        let mut verdict = AccessVerdict::default();
        // Slots fill from index 0 and zero terminates, so this walks exactly the ones the caller
        // filled. Every slot is resolved rather than stopping at the first hit: the gate needs the
        // full picture now, and a route mapped to several accesses is still satisfied by any one.
        for (slot_index, required_grant) in required
            .iter()
            .enumerate()
            .take_while(|(_, grant)| **grant != 0)
        {
            // An access lives in exactly one blob, so a miss in the first has to try the second.
            // Missing that second lookup denies a user something they hold — it fails closed, but
            // it is the one place this split can go quietly wrong.
            if holds_in_grants(&self.grants, *required_grant) {
                verdict.granted_mask |= 1 << slot_index;
                continue;
            }
            if let Some(sub_bytes) = find_in_sub_grants(&self.sub_grants, *required_grant) {
                verdict.granted_mask |= 1 << slot_index;
                verdict.has_subs_mask |= 1 << slot_index;
                verdict.sub_bytes.extend_from_slice(sub_bytes);
            }
        }

        if verdict.is_granted() {
            Ok(verdict)
        } else {
            Err(AccessDenial::NoAccess)
        }
    }
}

/// Splits a grant word into its access id and its level. Mirrors `core.UnpackAccesoNivel`.
fn unpack_grant(grant_word: u16) -> (u16, u8) {
    (grant_word >> 2, (grant_word & 0b11) as u8 + 1)
}

/// Whether `accesos_computed` holds this access at or above the level asked for.
///
/// A binary search, which the fixed stride is what makes possible — and the reason the variable
/// half of the format was pushed into the other blob. The old bucket-ceiling trick
/// (`required | 0b11`) is gone: comparing the unpacked levels says the same thing and says it in
/// the words the rest of the system uses.
fn holds_in_grants(grants: &[u8], required_grant: u16) -> bool {
    let (required_id, required_nivel) = unpack_grant(required_grant);
    let grant_count = grants.len() / GRANT_WORD_SIZE;

    let mut low = 0;
    let mut high = grant_count;
    while low < high {
        let middle = (low + high) / 2;
        let offset = middle * GRANT_WORD_SIZE;
        let (granted_id, granted_nivel) =
            unpack_grant(u16::from_be_bytes([grants[offset], grants[offset + 1]]));
        match granted_id.cmp(&required_id) {
            std::cmp::Ordering::Less => low = middle + 1,
            std::cmp::Ordering::Greater => high = middle,
            std::cmp::Ordering::Equal => return granted_nivel >= required_nivel,
        }
    }
    false
}

/// Finds this access in `accesos_sub_computed` and returns its sub bytes, or `None` if it is not
/// there or is held below the level asked for.
///
/// Linear, because entries are variable width. That costs nothing: this blob only holds accesses a
/// profile actually granted a sub-access to, and it is scanned in ascending order so it stops early.
fn find_in_sub_grants(sub_grants: &[u8], required_grant: u16) -> Option<&[u8]> {
    let (required_id, required_nivel) = unpack_grant(required_grant);
    let mut offset = 0;

    while offset + GRANT_WORD_SIZE <= sub_grants.len() {
        let (granted_id, granted_nivel) = unpack_grant(u16::from_be_bytes([
            sub_grants[offset],
            sub_grants[offset + 1],
        ]));
        offset += GRANT_WORD_SIZE;

        let sub_start = offset;
        while offset < sub_grants.len() {
            let sub_byte = sub_grants[offset];
            offset += 1;
            if sub_byte & SUB_MORE_BIT == 0 {
                break;
            }
        }

        if granted_id == required_id {
            return (granted_nivel >= required_nivel).then_some(&sub_grants[sub_start..offset]);
        }
        // Ascending order, so nothing past this point can match.
        if granted_id > required_id {
            return None;
        }
    }
    None
}

/// Checks `accesos_computed` on load: whole grant words, strictly ascending.
///
/// The `[]uint16` column this replaced was defensively re-sorted here, so that a blob some write
/// path left out of order degraded into a wrong answer for one user rather than a broken binary
/// search. Order is load-bearing now, so it is verified instead of repaired — and the failure is
/// loud rather than silent, which is the better half of that trade.
fn validate_grants(grants: &[u8]) -> anyhow::Result<()> {
    if grants.len() % GRANT_WORD_SIZE != 0 {
        anyhow::bail!(
            "accesos_computed length {} is not a whole number of grant words",
            grants.len()
        );
    }
    let mut previous_id = 0_u16;
    for offset in (0..grants.len()).step_by(GRANT_WORD_SIZE) {
        let (granted_id, _) =
            unpack_grant(u16::from_be_bytes([grants[offset], grants[offset + 1]]));
        if granted_id <= previous_id {
            anyhow::bail!("accesos_computed is not ascending at acceso {granted_id}");
        }
        previous_id = granted_id;
    }
    Ok(())
}

/// Checks `accesos_sub_computed` on load: every grant word followed by a terminated sub run, and no
/// entry without one — an access with no sub-access belongs in the other column, so finding one
/// here means the two blobs were written by something that disagrees with the Go encoder.
fn validate_sub_grants(sub_grants: &[u8]) -> anyhow::Result<()> {
    let mut offset = 0;
    let mut previous_id = 0_u16;

    while offset < sub_grants.len() {
        if offset + GRANT_WORD_SIZE > sub_grants.len() {
            anyhow::bail!("accesos_sub_computed ends mid grant word at byte {offset}");
        }
        let (granted_id, _) = unpack_grant(u16::from_be_bytes([
            sub_grants[offset],
            sub_grants[offset + 1],
        ]));
        if granted_id <= previous_id {
            anyhow::bail!("accesos_sub_computed is not ascending at acceso {granted_id}");
        }
        previous_id = granted_id;
        offset += GRANT_WORD_SIZE;

        let mut sub_mask = 0_u16;
        let mut sub_byte_index = 0;
        loop {
            let Some(sub_byte) = sub_grants.get(offset) else {
                anyhow::bail!("accesos_sub_computed acceso {granted_id} has no sub bytes");
            };
            if sub_byte_index * 7 >= 16 {
                anyhow::bail!("accesos_sub_computed acceso {granted_id} overflows its mask");
            }
            sub_mask |= u16::from(sub_byte & !SUB_MORE_BIT) << (sub_byte_index * 7);
            offset += 1;
            sub_byte_index += 1;
            if sub_byte & SUB_MORE_BIT == 0 {
                break;
            }
        }
        if sub_mask == 0 {
            anyhow::bail!("accesos_sub_computed acceso {granted_id} carries no sub-accesses");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `core.MakeAccesoNivelPacked`.
    fn packed(acceso_id: u16, nivel: u16) -> u16 {
        (acceso_id << 2) | (nivel - 1)
    }

    /// One grant word, big-endian, as both blobs store it.
    fn grant_bytes(acceso_id: u16, nivel: u16) -> Vec<u8> {
        packed(acceso_id, nivel).to_be_bytes().to_vec()
    }

    fn required(grants: &[u16]) -> [u16; MAX_REQUIRED_ACCESS] {
        let mut slots = [0_u16; MAX_REQUIRED_ACCESS];
        slots[..grants.len()].copy_from_slice(grants);
        slots
    }

    fn active(grants: Vec<u8>, sub_grants: Vec<u8>) -> UserAccessState {
        UserAccessState::from_row(
            Some(StoredUserAccess {
                grants_blob: grants,
                sub_grants_blob: sub_grants,
                status: 1,
            }),
            1_000,
        )
        .unwrap()
    }

    /// The endianness is the one thing in this module that could be wrong without failing, so it is
    /// asserted against bytes written by hand rather than by the encoder under test.
    ///
    /// It is also the thing that changed: the `[]uint16` column this replaced was little-endian,
    /// the only such integer anywhere in this daemon. A reader still on the old convention does not
    /// error, it authorizes a different access.
    #[test]
    fn the_grant_word_is_big_endian() {
        // packed(34, 4) = 34<<2 | 3 = 139 = 0x008B.
        let state = active(vec![0x00, 0x8B], vec![]);
        assert!(state.verdict(&required(&[packed(34, 1)])).is_ok());
        // Little-endian would have read 0x8B00 = 35584 = acceso 8896, which no catalogue contains.
        assert_eq!(
            state.verdict(&required(&[packed(8896, 1)])),
            Err(AccessDenial::NoAccess)
        );
    }

    /// The bytes `backend/core/accesos-blob.go` actually emits for a realistic grant set, captured
    /// from `EncodeAccesosGrants` itself. The hand-written fixtures above prove this codec is
    /// self-consistent; this one proves it agrees with the only writer of these columns.
    ///
    /// Accesos 7, 8, 14 and 15 carry no sub-access and live in `accesos_computed`. Accesos 10 and 16
    /// do, and live in `accesos_sub_computed` — an access is never in both.
    #[test]
    fn decodes_the_blobs_the_go_encoder_writes() {
        let grants = vec![0x00, 0x1F, 0x00, 0x23, 0x00, 0x38, 0x00, 0x3C];
        let sub_grants = vec![0x00, 0x29, 0x06, 0x00, 0x43, 0x81, 0x20];
        let state = active(grants, sub_grants);

        // Accesos 7 and 8 were granted nivel 4, so they satisfy every level.
        for acceso_id in [7, 8] {
            for nivel in 1..=4 {
                assert!(
                    state.verdict(&required(&[packed(acceso_id, nivel)])).is_ok(),
                    "acceso {acceso_id} nivel {nivel} should be granted"
                );
            }
        }
        // Accesos 14 and 15 were granted nivel 1 only: reading yes, writing no.
        for acceso_id in [14, 15] {
            assert!(state.verdict(&required(&[packed(acceso_id, 1)])).is_ok());
            assert_eq!(
                state.verdict(&required(&[packed(acceso_id, 2)])),
                Err(AccessDenial::NoAccess),
                "acceso {acceso_id} was granted nivel 1, so a write must be refused"
            );
        }
        // Acceso 10, nivel 2, sub-accesos 2 and 3 — one sub byte, MORE clear.
        let verdict = state.verdict(&required(&[packed(10, 2)])).unwrap();
        assert_eq!(verdict.granted_mask, 0b1);
        assert_eq!(verdict.has_subs_mask, 0b1);
        assert_eq!(verdict.sub_bytes, vec![0x06]);
        // Acceso 16, nivel 4, sub-accesos 1 and 13 — two sub bytes, MORE set on the first.
        let verdict = state.verdict(&required(&[packed(16, 1)])).unwrap();
        assert_eq!(verdict.sub_bytes, vec![0x81, 0x20]);
        // Nothing outside the granted set leaks in.
        for acceso_id in [1, 6, 9, 11, 17, 36] {
            assert_eq!(
                state.verdict(&required(&[packed(acceso_id, 1)])),
                Err(AccessDenial::NoAccess),
                "acceso {acceso_id} was never granted"
            );
        }
    }

    /// The split is the format's "has sub-accesses" bit, so a lookup that stops at the first blob
    /// denies a user something they hold. It fails closed, which is why it needs a test rather than
    /// a bug report.
    #[test]
    fn an_access_is_found_in_either_blob() {
        let mut sub_grants = grant_bytes(20, 2);
        sub_grants.push(0x01);
        let state = active(grant_bytes(3, 1), sub_grants);

        assert!(state.verdict(&required(&[packed(3, 1)])).is_ok());
        let verdict = state.verdict(&required(&[packed(20, 2)])).unwrap();
        assert_eq!(verdict.sub_bytes, vec![0x01]);
        // And the level rule applies in the sub blob exactly as it does in the other.
        assert_eq!(
            state.verdict(&required(&[packed(20, 4)])),
            Err(AccessDenial::NoAccess)
        );
    }

    /// The gate asks about up to four accesses at once and needs to know which of them landed, so
    /// the verdict resolves every filled slot instead of stopping at the first hit.
    #[test]
    fn every_filled_slot_is_resolved_and_zero_terminates() {
        let mut sub_grants = grant_bytes(20, 2);
        sub_grants.push(0x02);
        let state = active(grant_bytes(3, 4), sub_grants);

        let verdict = state
            .verdict(&required(&[packed(9, 1), packed(3, 1), packed(20, 1)]))
            .unwrap();
        // Slot 0 (acceso 9) is not held; slots 1 and 2 are, and only slot 2 carries sub bytes.
        assert_eq!(verdict.granted_mask, 0b110);
        assert_eq!(verdict.has_subs_mask, 0b100);
        assert_eq!(verdict.sub_bytes, vec![0x02]);

        // A grant sitting past a zero slot is not read: the gate fills from index 0.
        let mut sparse = [0_u16; MAX_REQUIRED_ACCESS];
        sparse[1] = packed(3, 1);
        assert_eq!(state.verdict(&sparse), Err(AccessDenial::NoAccess));
    }

    /// The level rule: a grant satisfies every level at or below it, and never leaks into the
    /// neighbouring acceso id.
    #[test]
    fn a_higher_level_satisfies_a_lower_requirement_and_never_a_neighbour() {
        let state = active(grant_bytes(8, 4), vec![]);
        for nivel in 1..=4 {
            assert!(state.verdict(&required(&[packed(8, nivel)])).is_ok());
        }
        for acceso_id in [7, 9] {
            assert_eq!(
                state.verdict(&required(&[packed(acceso_id, 1)])),
                Err(AccessDenial::NoAccess)
            );
        }
    }

    /// An empty required list never reaches here — the caller skips the check — but if it did, no
    /// grant can satisfy it, and failing closed is the only safe reading.
    #[test]
    fn no_required_grants_is_refused_rather_than_waved_through() {
        assert_eq!(
            active(grant_bytes(1, 4), vec![]).verdict(&[0; MAX_REQUIRED_ACCESS]),
            Err(AccessDenial::NoAccess)
        );
    }

    /// Identity outranks permission: these become 401s on the Go side, not 403s.
    #[test]
    fn identity_is_judged_before_grants() {
        let missing = UserAccessState::from_row(None, 0).unwrap();
        assert_eq!(
            missing.verdict(&required(&[packed(1, 1)])),
            Err(AccessDenial::UnknownUser)
        );

        let soft_deleted = UserAccessState::from_row(
            Some(StoredUserAccess {
                grants_blob: grant_bytes(1, 4),
                sub_grants_blob: vec![],
                status: 0,
            }),
            0,
        )
        .unwrap();
        assert_eq!(
            soft_deleted.verdict(&required(&[packed(1, 1)])),
            Err(AccessDenial::InactiveUser)
        );
    }

    #[test]
    fn a_user_with_no_grants_at_all_is_a_permission_denial() {
        // Distinct from UnknownUser: the row exists and is active, it just grants nothing.
        assert_eq!(
            active(vec![], vec![]).verdict(&required(&[packed(1, 1)])),
            Err(AccessDenial::NoAccess)
        );
    }

    /// Ordering and framing are load-bearing now that entries are variable width, so both blobs are
    /// validated on load. Each of these would otherwise answer the wrong question rather than fail.
    #[test]
    fn corrupt_blobs_are_refused_on_load() {
        let corrupt = |grants: Vec<u8>, sub_grants: Vec<u8>| {
            UserAccessState::from_row(
                Some(StoredUserAccess {
                    grants_blob: grants,
                    sub_grants_blob: sub_grants,
                    status: 1,
                }),
                0,
            )
            .is_err()
        };

        assert!(corrupt(vec![0x00, 0x0C, 0x00], vec![]), "odd length");
        assert!(
            corrupt(vec![0x00, 0x43, 0x00, 0x0C], vec![]),
            "not ascending"
        );
        assert!(
            corrupt(vec![0x00, 0x0C, 0x00, 0x0C], vec![]),
            "duplicated acceso"
        );
        assert!(corrupt(vec![], vec![0x00, 0x29]), "sub entry with no bytes");
        assert!(corrupt(vec![], vec![0x00, 0x29, 0x81]), "dangling MORE");
        assert!(
            corrupt(vec![], vec![0x00, 0x29, 0x00]),
            "sub entry carrying no sub-accesses"
        );
        assert!(
            corrupt(vec![], vec![0x00, 0x43, 0x01, 0x00, 0x29, 0x01]),
            "sub blob not ascending"
        );
        // Both empty is a legitimate user with no profiles, not a corruption.
        assert!(!corrupt(vec![], vec![]));
    }

    #[test]
    fn freshness_expires_and_survives_a_backward_clock() {
        let state = active(vec![], vec![]);
        assert!(state.is_fresh(1_000, 600));
        assert!(state.is_fresh(1_600, 600));
        assert!(!state.is_fresh(1_601, 600));
        // Earlier than the load: something reset the clock, so treat the entry as unusable.
        assert!(!state.is_fresh(999, 600));
    }

    #[test]
    fn an_invalidation_decodes_its_two_ids_and_its_wildcard() {
        let invalidation =
            parse_access_invalidation(&[0x00, 0x00, 0x07, 0x00, 0x01, 0x2C]).unwrap();
        assert_eq!(invalidation.company_id, 7);
        assert_eq!(invalidation.user_id, 300);
        // User zero is the wildcard, not an error: user ids start at 1.
        assert_eq!(
            parse_access_invalidation(&[0x00, 0x00, 0x07, 0x00, 0x00, 0x00])
                .unwrap()
                .user_id,
            0
        );
        assert!(parse_access_invalidation(&[0; INVALIDATE_ACCESS_PAYLOAD_SIZE]).is_err());
    }

    #[test]
    fn detail_codes_match_the_documented_contract() {
        assert_eq!(AccessDenial::NoAccess.detail_code(), 2);
        assert_eq!(AccessDenial::UnknownUser.detail_code(), 3);
        assert_eq!(AccessDenial::InactiveUser.detail_code(), 4);
    }
}
