//! In-memory absolute usage rows with mutation versions for lossless dirty flushing.

use std::collections::HashMap;

use anyhow::{Result, anyhow};

use crate::limiter::credits_blob::{Credits, RoutedCredits};

/// Charging a request updates the user's row and the company's total, so the in-memory map needs a
/// key for "the company itself". It is a discriminator, not a user, and it is not stored: the two
/// usage tables are separate, and `UsageKey::is_company_aggregate` is what routes a flush to the
/// right one.
pub const COMPANY_AGGREGATE_USER_ID: i32 = -1;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct UsageKey {
    pub company_id: i32,
    pub user_id: i32,
    pub time_frame: i32,
}

impl UsageKey {
    pub fn is_company_aggregate(&self) -> bool {
        self.user_id == COMPANY_AGGREGATE_USER_ID
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageSnapshot {
    pub key: UsageKey,
    pub routes: RoutedCredits,
    pub version: u64,
    /// The routes are only what was charged since the record was created, not the row's total: the
    /// flush has to read the stored row and add it before writing, or it would overwrite the total.
    pub base_pending: bool,
}

#[derive(Clone, Debug)]
pub struct UsageRecord {
    routes: RoutedCredits,
    version: u64,
    flushed_version: u64,
    base_pending: bool,
}

impl UsageRecord {
    pub fn loaded(routes: RoutedCredits) -> Self {
        // Loaded rows are already durable and must not be rewritten until they change.
        Self {
            routes,
            version: 0,
            flushed_version: 0,
            base_pending: false,
        }
    }

    /// A row created without reading what is stored for it. It accumulates charges from zero and the
    /// first flush that writes it adds the stored row in (`apply_base`), which moves the read off the
    /// admission path. Used for the per-user rows when `rate_limit.disable_user_limit` is on: nothing
    /// decides admission on them, so nothing needs their total before the flush.
    pub fn unseeded() -> Self {
        Self {
            routes: RoutedCredits::new(),
            version: 0,
            flushed_version: 0,
            base_pending: true,
        }
    }

    /// Folds the stored row into a record whose flush just wrote `base + snapshot`, turning it into
    /// an absolute record like any other. Applied once: a later call is a no-op, so a stale base can
    /// never be counted twice.
    pub fn apply_base(&mut self, base: &RoutedCredits) -> Result<()> {
        if !self.base_pending {
            return Ok(());
        }
        add_routes(&mut self.routes, base)?;
        self.base_pending = false;
        Ok(())
    }

    pub fn increment(&mut self, route_id: u16, credits: Credits) -> Result<()> {
        let current = self.routes.get(&route_id).copied().unwrap_or_default();
        let updated = current
            .checked_add(credits)
            .ok_or_else(|| anyhow!("in-memory usage credits overflowed uint64"))?;
        self.routes.insert(route_id, updated);
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow!("usage mutation version overflowed uint64"))?;
        Ok(())
    }

    pub fn snapshot(&self, key: UsageKey) -> Option<UsageSnapshot> {
        (self.version != self.flushed_version).then(|| UsageSnapshot {
            key,
            routes: self.routes.clone(),
            version: self.version,
            base_pending: self.base_pending,
        })
    }

    pub fn mark_flushed(&mut self, version: u64) {
        // A concurrent mutation stays dirty instead of being hidden by an older completed write.
        if self.version == version {
            self.flushed_version = version;
        }
    }

    pub fn is_clean(&self) -> bool {
        self.version == self.flushed_version
    }
}

/// Adds `other` into `target`, route by route.
pub fn add_routes(target: &mut RoutedCredits, other: &RoutedCredits) -> Result<()> {
    for (&route_id, &credits) in other {
        let current = target.get(&route_id).copied().unwrap_or_default();
        let updated = current
            .checked_add(credits)
            .ok_or_else(|| anyhow!("usage credits overflowed uint64"))?;
        target.insert(route_id, updated);
    }
    Ok(())
}

pub fn merge_loaded(
    records: &mut HashMap<UsageKey, UsageRecord>,
    key: UsageKey,
    routes: RoutedCredits,
) {
    // Never replace an in-memory row that may already contain newer accepted usage.
    records
        .entry(key)
        .or_insert_with(|| UsageRecord::loaded(routes));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_during_flush_remains_dirty() {
        let key = UsageKey {
            company_id: 7,
            user_id: 42,
            time_frame: 105_954_061,
        };
        let mut record = UsageRecord::loaded(RoutedCredits::new());
        record
            .increment(
                0,
                Credits {
                    cpu: 2,
                    inference: 3,
                },
            )
            .unwrap();
        let snapshot = record.snapshot(key).unwrap();
        record
            .increment(
                0,
                Credits {
                    cpu: 1,
                    inference: 1,
                },
            )
            .unwrap();
        record.mark_flushed(snapshot.version);
        assert!(record.snapshot(key).is_some());
    }

    #[test]
    fn an_unseeded_record_takes_its_base_exactly_once() {
        let key = UsageKey {
            company_id: 7,
            user_id: 42,
            time_frame: 105_954_061,
        };
        let two = Credits {
            cpu: 2,
            inference: 0,
        };
        let mut record = UsageRecord::unseeded();
        record.increment(5, two).unwrap();
        let snapshot = record.snapshot(key).unwrap();
        assert!(snapshot.base_pending);

        let base = RoutedCredits::from([(
            5,
            Credits {
                cpu: 10,
                inference: 0,
            },
        )]);
        record.apply_base(&base).unwrap();
        record.apply_base(&base).unwrap();
        record.mark_flushed(snapshot.version);

        assert!(record.is_clean());
        record.increment(5, two).unwrap();
        let snapshot = record.snapshot(key).unwrap();
        assert!(!snapshot.base_pending);
        assert_eq!(
            snapshot.routes.get(&5),
            Some(&Credits {
                cpu: 14,
                inference: 0
            })
        );
    }
}
