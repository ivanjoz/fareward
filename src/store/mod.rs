//! Fareward's own store: an embedded fjall database on local disk (plan D7). It is the source of
//! truth for usage, budgets and server metrics; the backend reads them through the report opcode
//! (`query`) instead of from its own database.
//!
//! | Keyspace | Key | Value |
//! |---|---|---|
//! | `usage_company` | company, time_frame | version, three refusal counters, credits blob |
//! | `usage_user` | company, user, time_frame | version, credits blob |
//! | `budget` | company | version, entitlement and usage counters (`BudgetRecord`) |
//! | `server_metrics` | date, slot | metrics version (2), fourteen i16 columns; v1 rows had eleven |
//! | `grants` | company, user | version, status, the two grant blobs (pushed by the backend) |
//! | `meta` | one byte | the store's own state |
//!
//! fjall is synchronous. Every call here is a short memtable or block-cache operation, except the
//! range reads, which the async adapters run on the blocking pool.

pub mod codec;
pub mod grants;
pub mod limiter;
pub mod metrics;
pub mod query;

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};

use crate::limiter::block::Rejections;
use crate::limiter::storage::{StoredBudget, StoredBudgetUsage, StoredUsage};
use crate::sysmetrics::MetricsSample;
use codec::{
    BudgetRecord, CompanyUsageValue, budget_key, company_usage_key, decode_user_usage,
    encode_metrics, encode_user_usage, metrics_key, read_key_i32, user_usage_key,
};

/// The layout version this binary writes. A store written by another layout refuses to open
/// rather than being misread.
const SCHEMA_VERSION: u16 = 1;
const META_SCHEMA_VERSION: [u8; 1] = [1];

/// Cheap to clone: every handle inside is shared.
#[derive(Clone)]
pub struct FjallStore {
    inner: Arc<Inner>,
}

struct Inner {
    database: Database,
    usage_company: Keyspace,
    usage_user: Keyspace,
    budget: Keyspace,
    server_metrics: Keyspace,
    grants: Keyspace,
    /// Held across every read-modify-write: the flush and a budget mutation write the two halves of
    /// one budget value, and the flush and the rejection counters the two halves of one company
    /// usage value. Each must keep the other's half, so neither may read a value the other is
    /// about to replace.
    write_lock: Mutex<()>,
}

impl FjallStore {
    /// Opens or creates the store at `path`. Fails on a store of another layout.
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)
            .with_context(|| format!("cannot create the store directory {}", path.display()))?;
        let database = Database::builder(path)
            .open()
            .with_context(|| format!("cannot open the fareward store at {}", path.display()))?;
        let keyspace = |name: &str| {
            database
                .keyspace(name, KeyspaceCreateOptions::default)
                .with_context(|| format!("cannot open keyspace {name}"))
        };
        let meta = keyspace("meta")?;
        match meta.get(META_SCHEMA_VERSION)? {
            None => meta.insert(META_SCHEMA_VERSION, SCHEMA_VERSION.to_be_bytes())?,
            Some(stored) if *stored == SCHEMA_VERSION.to_be_bytes() => {}
            Some(stored) => bail!(
                "the store at {} has layout {:?}, this binary writes {SCHEMA_VERSION}",
                path.display(),
                &*stored
            ),
        }
        Ok(Self {
            inner: Arc::new(Inner {
                usage_company: keyspace("usage_company")?,
                usage_user: keyspace("usage_user")?,
                budget: keyspace("budget")?,
                server_metrics: keyspace("server_metrics")?,
                grants: keyspace("grants")?,
                database,
                write_lock: Mutex::new(()),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        // A panic while holding it left no half-written value: every write below is one insert.
        self.inner
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Makes everything written so far durable on disk. Called once per flush, so a crash loses at
    /// most the flush window, as before.
    pub fn persist(&self) -> Result<()> {
        self.inner
            .database
            .persist(PersistMode::SyncData)
            .context("store fsync failed")
    }

    /// A company's rows over `[first, last]` frames.
    pub fn company_usage(
        &self,
        company_id: i32,
        first: i32,
        last: i32,
    ) -> Result<Vec<(i32, CompanyUsageValue)>> {
        let mut rows = Vec::new();
        let range = company_usage_key(company_id, first)..=company_usage_key(company_id, last);
        for item in self.inner.usage_company.range(range) {
            let (key, value) = item.into_inner()?;
            rows.push((read_key_i32(&key[4..8]), CompanyUsageValue::decode(&value)?));
        }
        Ok(rows)
    }

    /// One user's rows over `[first, last]` frames.
    pub fn user_usage(
        &self,
        company_id: i32,
        user_id: i32,
        first: i32,
        last: i32,
    ) -> Result<Vec<(i32, Vec<u8>)>> {
        let mut rows = Vec::new();
        let range =
            user_usage_key(company_id, user_id, first)..=user_usage_key(company_id, user_id, last);
        for item in self.inner.usage_user.range(range) {
            let (key, value) = item.into_inner()?;
            rows.push((read_key_i32(&key[8..12]), decode_user_usage(&value)?));
        }
        Ok(rows)
    }

    /// Every user of a company over `[first, last]` frames: `(user, frame, blob)`. One seek per
    /// user rather than a filter over all of the company's frames, which is what keeps a report of
    /// thirty days cheap next to months of five-minute rows.
    pub fn company_users_usage(
        &self,
        company_id: i32,
        first: i32,
        last: i32,
    ) -> Result<Vec<(i32, i32, Vec<u8>)>> {
        let mut rows = Vec::new();
        let mut user_id = i32::MIN;
        loop {
            // The next user at or after `user_id` that has any row in this company.
            let start = user_usage_key(company_id, user_id, i32::MIN);
            let end = user_usage_key(company_id, i32::MAX, i32::MAX);
            let Some(item) = self.inner.usage_user.range(start..=end).next() else {
                break;
            };
            let key = item.key()?;
            user_id = read_key_i32(&key[4..8]);
            for (frame, blob) in self.user_usage(company_id, user_id, first, last)? {
                rows.push((user_id, frame, blob));
            }
            if user_id == i32::MAX {
                break;
            }
            user_id += 1;
        }
        Ok(rows)
    }

    /// Every company's rows over `[first, last]` frames: `(company, frame, value)`. Skips from one
    /// company to the next the same way `company_users_usage` skips users.
    pub fn every_company_usage(
        &self,
        first: i32,
        last: i32,
    ) -> Result<Vec<(i32, i32, CompanyUsageValue)>> {
        let mut rows = Vec::new();
        let mut company_id = i32::MIN;
        loop {
            let start = company_usage_key(company_id, i32::MIN);
            let end = company_usage_key(i32::MAX, i32::MAX);
            let Some(item) = self.inner.usage_company.range(start..=end).next() else {
                break;
            };
            let key = item.key()?;
            company_id = read_key_i32(&key[..4]);
            for (frame, value) in self.company_usage(company_id, first, last)? {
                rows.push((company_id, frame, value));
            }
            if company_id == i32::MAX {
                break;
            }
            company_id += 1;
        }
        Ok(rows)
    }

    /// Replaces a usage row's credits. A company row keeps its refusal counters.
    pub fn put_usage(
        &self,
        company_id: i32,
        user_id: Option<i32>,
        time_frame: i32,
        used_credits: Vec<u8>,
    ) -> Result<()> {
        match user_id {
            Some(user_id) => self.inner.usage_user.insert(
                user_usage_key(company_id, user_id, time_frame),
                encode_user_usage(&used_credits),
            )?,
            None => {
                let key = company_usage_key(company_id, time_frame);
                let _guard = self.lock();
                let mut value = self.company_value(&key)?;
                value.used_credits = used_credits;
                self.inner.usage_company.insert(key, value.encode())?;
            }
        }
        Ok(())
    }

    /// Adds to a company row's refusal counters, creating the row when there is none.
    pub fn add_rejections(
        &self,
        company_id: i32,
        time_frame: i32,
        rejections: Rejections,
    ) -> Result<()> {
        let key = company_usage_key(company_id, time_frame);
        let _guard = self.lock();
        let mut value = self.company_value(&key)?;
        value.rejections.short = value.rejections.short.saturating_add(rejections.short);
        value.rejections.long = value.rejections.long.saturating_add(rejections.long);
        value.rejections.no_funds = value
            .rejections
            .no_funds
            .saturating_add(rejections.no_funds);
        self.inner.usage_company.insert(key, value.encode())?;
        Ok(())
    }

    fn company_value(&self, key: &[u8]) -> Result<CompanyUsageValue> {
        match self.inner.usage_company.get(key)? {
            Some(stored) => CompanyUsageValue::decode(&stored),
            None => Ok(CompanyUsageValue::default()),
        }
    }

    pub fn budget(&self, company_id: i32) -> Result<Option<BudgetRecord>> {
        match self.inner.budget.get(budget_key(company_id))? {
            Some(stored) => BudgetRecord::decode(company_id, &stored).map(Some),
            None => Ok(None),
        }
    }

    /// Every company's budget, in company order.
    pub fn budgets(&self) -> Result<Vec<BudgetRecord>> {
        let mut records = Vec::new();
        for item in self.inner.budget.iter() {
            let (key, value) = item.into_inner()?;
            records.push(BudgetRecord::decode(read_key_i32(&key), &value)?);
        }
        Ok(records)
    }

    /// Replaces the entitlement half of a budget, keeping the usage half.
    pub fn put_budget(&self, budget: StoredBudget) -> Result<()> {
        self.update_budget(budget.company_id, |record| record.budget = budget)
    }

    /// Replaces the usage half of a budget, keeping the entitlement half.
    pub fn put_budget_usage(&self, usage: StoredBudgetUsage) -> Result<()> {
        self.update_budget(usage.company_id, |record| record.usage = usage)
    }

    fn update_budget(&self, company_id: i32, change: impl FnOnce(&mut BudgetRecord)) -> Result<()> {
        let _guard = self.lock();
        let mut record = self.budget(company_id)?.unwrap_or(BudgetRecord {
            budget: StoredBudget {
                company_id,
                ..StoredBudget::default()
            },
            usage: StoredBudgetUsage {
                company_id,
                ..StoredBudgetUsage::default()
            },
        });
        change(&mut record);
        self.inner
            .budget
            .insert(budget_key(company_id), record.encode())?;
        Ok(())
    }

    pub fn put_metrics(&self, date: i16, slot: i16, sample: &MetricsSample) -> Result<()> {
        self.inner
            .server_metrics
            .insert(metrics_key(date, slot), encode_metrics(sample))?;
        Ok(())
    }

    /// Samples over `[(first_date, first_slot), (last_date, last_slot)]`, in time order.
    pub fn metrics(
        &self,
        first: (i16, i16),
        last: (i16, i16),
    ) -> Result<Vec<(i16, i16, MetricsSample)>> {
        let mut rows = Vec::new();
        let range = metrics_key(first.0, first.1)..=metrics_key(last.0, last.1);
        for item in self.inner.server_metrics.range(range) {
            let (key, value) = item.into_inner()?;
            rows.push((
                codec::read_key_i16(&key[..2]),
                codec::read_key_i16(&key[2..4]),
                codec::decode_metrics(&value)?,
            ));
        }
        Ok(rows)
    }

    /// Deletes every sample of a day before `cutoff_day`, in one atomic batch. Returns how many.
    pub fn purge_metrics_before(&self, cutoff_day: i16) -> Result<usize> {
        let keyspace = &self.inner.server_metrics;
        let end = metrics_key(cutoff_day, i16::MIN);
        let mut batch = self.inner.database.batch();
        let mut removed = 0;
        for item in keyspace.range(..end) {
            batch.remove(keyspace, item.key()?);
            removed += 1;
        }
        if removed > 0 {
            batch.commit()?;
        }
        Ok(removed)
    }

    /// The limiter's usage reads, in the shape `LimiterStore` returns.
    pub fn usage_rows(
        &self,
        company_id: i32,
        user_id: Option<i32>,
        first: i32,
        last: i32,
    ) -> Result<Vec<StoredUsage>> {
        Ok(match user_id {
            Some(user_id) => self
                .user_usage(company_id, user_id, first, last)?
                .into_iter()
                .map(|(time_frame, used_credits)| StoredUsage {
                    time_frame,
                    used_credits,
                })
                .collect(),
            None => self
                .company_usage(company_id, first, last)?
                .into_iter()
                .map(|(time_frame, value)| StoredUsage {
                    time_frame,
                    used_credits: value.used_credits,
                })
                .collect(),
        })
    }
}

#[cfg(test)]
pub(crate) fn temporary_store() -> (tempfile::TempDir, FjallStore) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let store = FjallStore::open(directory.path()).expect("a fresh store");
    (directory, store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limiter::credits_blob::Credits;

    #[test]
    fn usage_round_trips_and_a_company_row_keeps_its_counters() {
        let (_directory, store) = temporary_store();
        store
            .add_rejections(
                7,
                200_000_010,
                Rejections {
                    short: 2,
                    long: 0,
                    no_funds: 1,
                },
            )
            .unwrap();
        store
            .put_usage(7, None, 200_000_010, vec![0, 4, 1, 2])
            .unwrap();
        store
            .add_rejections(
                7,
                200_000_010,
                Rejections {
                    short: 1,
                    long: 3,
                    no_funds: 0,
                },
            )
            .unwrap();
        let rows = store.company_usage(7, 200_000_000, 200_000_100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 200_000_010);
        assert_eq!(rows[0].1.used_credits, [0, 4, 1, 2]);
        assert_eq!(
            rows[0].1.rejections,
            Rejections {
                short: 3,
                long: 3,
                no_funds: 1
            }
        );
        // Another company and a frame outside the range stay out.
        store.put_usage(8, None, 200_000_010, vec![1]).unwrap();
        store.put_usage(7, None, 200_000_200, vec![1]).unwrap();
        assert_eq!(
            store
                .company_usage(7, 200_000_000, 200_000_100)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn skip_scans_visit_every_company_and_user_once() {
        let (_directory, store) = temporary_store();
        for company in [0, 3, 9] {
            for frame in [100, 200, 300] {
                store
                    .put_usage(company, None, frame, vec![frame as u8])
                    .unwrap();
            }
        }
        for user in [1, 2, 40] {
            for frame in [100, 200, 300] {
                store
                    .put_usage(3, Some(user), frame, vec![user as u8])
                    .unwrap();
            }
        }
        store.put_usage(4, Some(1), 200, vec![9]).unwrap();

        let companies = store.every_company_usage(150, 250).unwrap();
        let visited: Vec<(i32, i32)> = companies.iter().map(|row| (row.0, row.1)).collect();
        assert_eq!(visited, [(0, 200), (3, 200), (9, 200)]);

        let users = store.company_users_usage(3, 200, 300).unwrap();
        let visited: Vec<(i32, i32)> = users.iter().map(|row| (row.0, row.1)).collect();
        assert_eq!(
            visited,
            [(1, 200), (1, 300), (2, 200), (2, 300), (40, 200), (40, 300)]
        );
    }

    #[test]
    fn the_two_halves_of_a_budget_never_overwrite_each_other() {
        let (_directory, store) = temporary_store();
        let budget = StoredBudget {
            company_id: 5,
            daily: Credits {
                cpu: 100,
                inference: 10,
            },
            budget_month_start_day: 20_390,
            ..StoredBudget::default()
        };
        store.put_budget(budget).unwrap();
        let usage = StoredBudgetUsage {
            company_id: 5,
            day_period: 20_400,
            day_used: Credits {
                cpu: 3,
                inference: 1,
            },
            ..StoredBudgetUsage::default()
        };
        store.put_budget_usage(usage).unwrap();
        store.put_budget(budget).unwrap();

        let record = store.budget(5).unwrap().unwrap();
        assert_eq!(record.budget, budget);
        assert_eq!(record.usage, usage);
        assert_eq!(store.budgets().unwrap().len(), 1);
        assert!(store.budget(6).unwrap().is_none());
    }

    #[test]
    fn the_metrics_purge_drops_whole_days_only() {
        let (_directory, store) = temporary_store();
        let sample = MetricsSample::default();
        for date in [100, 101, 102] {
            for slot in [0, 17_279] {
                store.put_metrics(date, slot, &sample).unwrap();
            }
        }
        assert_eq!(store.purge_metrics_before(102).unwrap(), 4);
        let left = store.metrics((0, 0), (200, 0)).unwrap();
        let days: Vec<(i16, i16)> = left.iter().map(|row| (row.0, row.1)).collect();
        assert_eq!(days, [(102, 0), (102, 17_279)]);
    }

    #[test]
    fn a_store_survives_a_reopen_and_refuses_another_layout() {
        let directory = tempfile::tempdir().unwrap();
        {
            let store = FjallStore::open(directory.path()).unwrap();
            store.put_usage(1, Some(2), 3, vec![4]).unwrap();
            store.persist().unwrap();
        }
        let store = FjallStore::open(directory.path()).unwrap();
        assert_eq!(store.user_usage(1, 2, 0, 10).unwrap(), [(3, vec![4])]);
        drop(store);

        {
            let database = Database::builder(directory.path()).open().unwrap();
            let meta = database
                .keyspace("meta", KeyspaceCreateOptions::default)
                .unwrap();
            meta.insert(META_SCHEMA_VERSION, 99_u16.to_be_bytes())
                .unwrap();
        }
        assert!(FjallStore::open(directory.path()).is_err());
    }
}
