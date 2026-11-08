//! The grants: what the backend pushes so the limiter never reads its `users` table (plan D7).
//!
//! Only what the admission check needs, per user: the status and the two grant blobs, verbatim as
//! the backend computes them (`accesos_computed`, `accesos_sub_computed`).
//!
//! Opcode `0x0A`, answered `Ack` once the whole batch is stored and the users' cached grants are
//! dropped. Mirrored by `go/grants.go`. The payload is hand-rolled rather than colbin because it is
//! a list of blobs:
//!
//! ```text
//! [count:u16] then count × [company:i32][user:i32][flags:u8][status:i8]
//!                           [grants_len:u16][grants][sub_len:u16][sub_grants]
//! ```
//!
//! big-endian, with flag bit 0 meaning "this user no longer exists": the entry carries empty blobs
//! and the stored row is deleted, so the user is denied like any unknown one.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;

use crate::limiter::access::UserAccessState;
use crate::limiter::storage::{AccessSource, StoredUserAccess};
use crate::store::FjallStore;
use crate::store::codec::{VALUE_VERSION, put_i32};

/// Ceiling on one batch, and so on what an unauthenticated peer can make the daemon buffer. The
/// client splits a larger push into several frames.
pub const GRANTS_MAX_PAYLOAD_SIZE: usize = 8 * 1024;

const FLAG_DELETED: u8 = 0x01;

/// One user's grants as pushed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantEntry {
    pub company_id: i32,
    pub user_id: i32,
    /// `None` deletes the user.
    pub access: Option<StoredUserAccess>,
}

/// `grants`: `[company][user]`.
pub fn grants_key(company_id: i32, user_id: i32) -> Vec<u8> {
    let mut key = Vec::with_capacity(8);
    put_i32(&mut key, company_id);
    put_i32(&mut key, user_id);
    key
}

/// `[version][status:i8][grants_len:u16][grants][sub_grants…]`
pub fn encode_grants(access: &StoredUserAccess) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + access.grants_blob.len() + access.sub_grants_blob.len());
    value.push(VALUE_VERSION);
    value.push(access.status as u8);
    value.extend_from_slice(&(access.grants_blob.len() as u16).to_be_bytes());
    value.extend_from_slice(&access.grants_blob);
    value.extend_from_slice(&access.sub_grants_blob);
    value
}

pub fn decode_grants(value: &[u8]) -> Result<StoredUserAccess> {
    if value.len() < 4 || value[0] != VALUE_VERSION {
        bail!("grants value has an unknown layout");
    }
    let grants_len = usize::from(u16::from_be_bytes([value[2], value[3]]));
    let Some(grants_blob) = value.get(4..4 + grants_len) else {
        bail!("grants value is shorter than its grants");
    };
    Ok(StoredUserAccess {
        status: value[1] as i8,
        grants_blob: grants_blob.to_vec(),
        sub_grants_blob: value[4 + grants_len..].to_vec(),
    })
}

/// Decodes and validates a whole batch: one bad entry refuses the frame, so the backend never
/// half-applies a push.
pub fn parse_grants(payload: &[u8]) -> Result<Vec<GrantEntry>> {
    let mut cursor = Cursor {
        bytes: payload,
        offset: 0,
    };
    let count = cursor.u16()?;
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let company_id = cursor.i32()?;
        let user_id = cursor.i32()?;
        let flags = cursor.u8()?;
        let status = cursor.u8()? as i8;
        let grants_len = cursor.u16()?;
        let grants_blob = cursor.take(usize::from(grants_len))?.to_vec();
        let sub_len = cursor.u16()?;
        let sub_grants_blob = cursor.take(usize::from(sub_len))?.to_vec();
        if company_id <= 0 || user_id <= 0 {
            bail!("grants for company {company_id} user {user_id}: ids must be positive");
        }
        if flags & !FLAG_DELETED != 0 {
            bail!("grants for company {company_id} user {user_id}: unknown flags {flags:#x}");
        }
        let access = if flags & FLAG_DELETED != 0 {
            None
        } else {
            let access = StoredUserAccess {
                grants_blob,
                sub_grants_blob,
                status,
            };
            // The same checks a cache load runs, so a blob the limiter cannot read is refused here
            // rather than stored and turned into a 503 on that user's next request.
            UserAccessState::from_row(Some(access.clone()), 0).with_context(|| {
                format!("grants for company {company_id} user {user_id} are malformed")
            })?;
            Some(access)
        };
        entries.push(GrantEntry {
            company_id,
            user_id,
            access,
        });
    }
    if cursor.offset != payload.len() {
        bail!(
            "{} bytes after the last grant entry",
            payload.len() - cursor.offset
        );
    }
    Ok(entries)
}

/// Encodes a batch the way the Go client does; used by the tests.
pub fn encode_grant_batch(entries: &[GrantEntry]) -> Vec<u8> {
    let mut payload = (entries.len() as u16).to_be_bytes().to_vec();
    for entry in entries {
        payload.extend_from_slice(&entry.company_id.to_be_bytes());
        payload.extend_from_slice(&entry.user_id.to_be_bytes());
        let empty = StoredUserAccess::default();
        let (flags, access) = match &entry.access {
            Some(access) => (0, access),
            None => (FLAG_DELETED, &empty),
        };
        payload.push(flags);
        payload.push(access.status as u8);
        payload.extend_from_slice(&(access.grants_blob.len() as u16).to_be_bytes());
        payload.extend_from_slice(&access.grants_blob);
        payload.extend_from_slice(&(access.sub_grants_blob.len() as u16).to_be_bytes());
        payload.extend_from_slice(&access.sub_grants_blob);
    }
    payload
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let Some(field) = self.bytes.get(self.offset..self.offset + size) else {
            bail!("grants payload ends mid entry");
        };
        self.offset += size;
        Ok(field)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let field = self.take(2)?;
        Ok(u16::from_be_bytes([field[0], field[1]]))
    }
    fn i32(&mut self) -> Result<i32> {
        let field = self.take(4)?;
        Ok(i32::from_be_bytes([field[0], field[1], field[2], field[3]]))
    }
}

impl FjallStore {
    /// Stores a batch in one atomic write.
    pub fn put_grants(&self, entries: &[GrantEntry]) -> Result<()> {
        let keyspace = &self.inner.grants;
        let mut batch = self.inner.database.batch();
        for entry in entries {
            let key = grants_key(entry.company_id, entry.user_id);
            match &entry.access {
                Some(access) => batch.insert(keyspace, key, encode_grants(access)),
                None => batch.remove(keyspace, key),
            }
        }
        batch.commit()?;
        Ok(())
    }

    pub fn user_grants(&self, company_id: i32, user_id: i32) -> Result<Option<StoredUserAccess>> {
        match self.inner.grants.get(grants_key(company_id, user_id))? {
            Some(value) => decode_grants(&value).map(Some),
            None => Ok(None),
        }
    }
}

/// The limiter reads the grants from the store: what the backend last pushed.
#[async_trait]
impl AccessSource for FjallStore {
    async fn load_user_access(
        &self,
        company_id: i32,
        user_id: i32,
    ) -> Result<Option<StoredUserAccess>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.user_grants(company_id, user_id))
            .await
            .context("store task panicked")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::temporary_store;

    fn user(company_id: i32, user_id: i32, status: i8) -> GrantEntry {
        GrantEntry {
            company_id,
            user_id,
            // One grant word (access 78, nivel 2) and no sub-accesses.
            access: Some(StoredUserAccess {
                grants_blob: vec![0x01, 0x39],
                sub_grants_blob: Vec::new(),
                status,
            }),
        }
    }

    #[test]
    fn a_batch_round_trips_and_a_deletion_removes_the_row() {
        let (_directory, store) = temporary_store();
        let batch = vec![user(7, 42, 1), user(7, 43, 0), user(8, 1, 1)];
        let parsed = parse_grants(&encode_grant_batch(&batch)).unwrap();
        assert_eq!(parsed, batch);
        store.put_grants(&parsed).unwrap();
        assert_eq!(store.user_grants(7, 42).unwrap(), batch[0].access.clone());
        assert_eq!(store.user_grants(7, 43).unwrap().unwrap().status, 0);

        let deletion = GrantEntry {
            company_id: 7,
            user_id: 42,
            access: None,
        };
        store
            .put_grants(&parse_grants(&encode_grant_batch(&[deletion])).unwrap())
            .unwrap();
        assert_eq!(store.user_grants(7, 42).unwrap(), None);
        assert!(store.user_grants(8, 1).unwrap().is_some());
    }

    #[test]
    fn a_bad_batch_is_refused_whole() {
        let mut bad_blob = user(7, 42, 1);
        bad_blob.access.as_mut().unwrap().grants_blob = vec![0x01];
        assert!(parse_grants(&encode_grant_batch(&[user(7, 1, 1), bad_blob])).is_err());
        assert!(parse_grants(&encode_grant_batch(&[user(0, 1, 1)])).is_err());
        let mut trailing = encode_grant_batch(&[user(7, 1, 1)]);
        trailing.push(0);
        assert!(parse_grants(&trailing).is_err());
        assert!(parse_grants(&[0, 1, 0]).is_err());
        assert_eq!(parse_grants(&[0, 0]).unwrap(), Vec::new());
    }

    /// The bytes go/grants_test.go pins for the Go encoder.
    #[test]
    fn the_go_layout_parses() {
        let payload = [
            0, 2, //
            0, 0, 0, 7, 0, 0, 0, 42, 0, 1, 0, 2, 0x01, 0x39, 0, 3, 0x02, 0x00, 0x20, //
            0, 0, 0, 7, 0, 0, 0, 43, 1, 0, 0, 0, 0, 0,
        ];
        let entries = parse_grants(&payload).unwrap();
        assert_eq!(
            entries[0].access,
            Some(StoredUserAccess {
                grants_blob: vec![0x01, 0x39],
                sub_grants_blob: vec![0x02, 0x00, 0x20],
                status: 1,
            })
        );
        assert_eq!(entries[1].user_id, 43);
        assert_eq!(entries[1].access, None);
        assert_eq!(encode_grant_batch(&entries), payload);
    }

    #[test]
    fn the_value_layout_round_trips() {
        let access = StoredUserAccess {
            grants_blob: vec![0x01, 0x39, 0x00, 0x8B],
            sub_grants_blob: vec![0x02, 0x00, 0x81, 0x20],
            status: -1,
        };
        assert_eq!(decode_grants(&encode_grants(&access)).unwrap(), access);
        assert!(decode_grants(&[1, 0, 0, 9]).is_err());
    }
}
