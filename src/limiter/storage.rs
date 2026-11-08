//! The limiter's durable ports. Usage, budgets, the reports over them and the grants the backend
//! pushes all live in Fareward's own store (`crate::store::FjallStore`, plan D7).

use anyhow::Result;
use async_trait::async_trait;

use crate::limiter::aggregation::UsageKey;
use crate::limiter::block::Rejections;
use crate::limiter::credits_blob::Credits;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredUsage {
    pub time_frame: i32,
    pub used_credits: Vec<u8>,
}

/// One user's authorization row, exactly as `users` holds it.
///
/// Two blobs, and which one an access is in carries meaning: `grants_blob` (`accesos_computed`) is
/// fixed-stride grant words for accesses with no sub-access, and `sub_grants_blob`
/// (`accesos_sub_computed`) appends each grant's sub bytes. Both are **big-endian** — see
/// `validate_grants` in `access.rs`, and `backend/core/accesos-blob.go`, which writes them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredUserAccess {
    pub grants_blob: Vec<u8>,
    pub sub_grants_blob: Vec<u8>,
    pub status: i8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredBudget {
    pub company_id: i32,
    pub daily: Credits,
    pub budget_month_start_day: i16,
    pub monthly_ceiling: Credits,
    /// The figure the last "set current" wrote, kept so a reader can tell how much of the granted
    /// credit is gone: the ceiling folds in the usage that existed when it was set, so on its own it
    /// cannot answer that.
    pub last_set: Credits,
    pub updated: i32,
}

/// The extra-pool counters as persisted, with the periods that say which window each belongs to.
///
/// Read back at cold start for two different reasons. The daily figure is the pool itself: without
/// it a restart would hand a company a fresh allowance mid-day. The monthly figure is not a quota at
/// all — there is no monthly extra ceiling — it is the correction term that keeps `month_used`
/// honest, because that counter is recovered by summing the usage rows and those rows include
/// whatever the pool paid for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredExtraUsage {
    pub day_period: i16,
    pub day_cpu: u64,
    pub month_start_day: i16,
    pub month_cpu: u64,
}

/// The two halves of one `company_credit_budget` row. Read together because it is one row and one
/// point query; written by two separate statements because the two writes race and each must leave
/// the other's columns alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredBudgetRow {
    pub budget: StoredBudget,
    pub extra: StoredExtraUsage,
}

/// The daemon's own usage counters for one company, so a reader can subtract them from the ceilings
/// in `StoredBudget` instead of re-summing the usage rows the way the daemon does on a cold miss.
///
/// The two period fields say which window each counter belongs to: nothing rewrites a row when a day
/// or a month rolls over with no traffic, so a reader compares them against its own current window
/// and treats a mismatch as zero used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredBudgetUsage {
    pub company_id: i32,
    /// Local business UnixDay, the same day `time_frame::daily` buckets by.
    pub day_period: i16,
    pub day_used: Credits,
    pub month_start_day: i16,
    pub month_used: Credits,
    /// CPU paid out of the extra daily pool, in the two windows above. Not part of `day_used` or
    /// `month_used`: extra spending is counted apart from the quota it was granted outside of.
    pub day_extra_cpu: u64,
    pub month_extra_cpu: u64,
    pub updated: i32,
}

/// Every durable read and write the limiter needs. Named for the limiter rather than for usage
/// because it also answers the authorization question the charge frame now carries: one store
/// handle, one database pool, one test double.
#[async_trait]
pub trait LimiterStore: Send + Sync {
    async fn load_exact(&self, key: UsageKey) -> Result<Option<StoredUsage>>;
    async fn load_range(
        &self,
        company_id: i32,
        user_id: i32,
        start_time_frame: i32,
        end_time_frame: i32,
    ) -> Result<Vec<StoredUsage>>;
    async fn upsert(&self, key: UsageKey, used_credits: Vec<u8>) -> Result<()>;
    async fn load_budget(&self, company_id: i32) -> Result<Option<StoredBudgetRow>>;
    async fn upsert_budget(&self, budget: StoredBudget) -> Result<()>;
    /// Writes only the usage columns, never the entitlement ones: the two writes race (a flush and a
    /// mutation can land in either order) and each must leave the other's columns untouched.
    async fn upsert_budget_usage(&self, usage: StoredBudgetUsage) -> Result<()>;
    /// **Adds** to a company row's rejection counters; unlike every other write here it is not an
    /// absolute replacement, because the counters are not loaded at start and memory only ever
    /// holds what accumulated since the last flush. Never touches `used_credits` of an existing row.
    async fn add_rejections(
        &self,
        company_id: i32,
        time_frame: i32,
        rejections: Rejections,
    ) -> Result<()>;
    /// `None` means no such user in this company, which is a denial and not an error.
    async fn load_user_access(
        &self,
        company_id: i32,
        user_id: i32,
    ) -> Result<Option<StoredUserAccess>>;
    /// Called once a flush has written every dirty record, so a store that buffers can make the
    /// whole flush durable in one step instead of one per row.
    async fn flush_completed(&self) -> Result<()> {
        Ok(())
    }
    /// Answers a report query (opcode `0x09`) with the reply body. Only the real store keeps the
    /// rows a report reads, so a test double refuses.
    async fn report(&self, _query: crate::store::query::ReportQuery) -> Result<Vec<u8>> {
        anyhow::bail!("this store answers no reports")
    }
    /// Stores the grants the backend pushed (opcode `0x0A`).
    async fn put_grants(&self, _entries: Vec<crate::store::grants::GrantEntry>) -> Result<()> {
        anyhow::bail!("this store keeps no grants")
    }
}

/// Where the grants come from: the authorization half of the limiter's reads, apart from usage so
/// the two can live in different places.
#[async_trait]
pub trait AccessSource: Send + Sync {
    /// `None` means no such user in this company, which is a denial and not an error.
    async fn load_user_access(
        &self,
        company_id: i32,
        user_id: i32,
    ) -> Result<Option<StoredUserAccess>>;
}
