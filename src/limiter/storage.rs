//! MariaDB adapter for loading and replacing absolute compact usage rows.

use anyhow::{Context, Result};
use async_trait::async_trait;
use mysql_async::{Pool, prelude::Queryable};

use crate::limiter::aggregation::{COMPANY_AGGREGATE_USER_ID, UsageKey};
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
}

// Company totals and per-user totals live in separate tables: the company table carries the
// per-route split and is read across every tenant by the SaaS panel, while the user table stays
// narrow and is only ever read one user at a time.
const SELECT_COMPANY_RANGE: &str = "SELECT time_frame, used_credits FROM credit_usage_company \
     WHERE company_id = ? AND time_frame >= ? AND time_frame <= ?";
const SELECT_USER_RANGE: &str = "SELECT time_frame, used_credits FROM credit_usage_user \
     WHERE company_id = ? AND user_id = ? AND time_frame >= ? AND time_frame <= ?";

// Every write is an absolute replacement of the named columns, as a ScyllaDB INSERT was: ON
// DUPLICATE KEY UPDATE touches only those, so the entitlement and the usage halves of
// company_credit_budget never overwrite each other.
const UPSERT_COMPANY: &str = "INSERT INTO credit_usage_company (company_id, time_frame, used_credits) \
     VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE used_credits = VALUES(used_credits)";
const UPSERT_USER: &str = "INSERT INTO credit_usage_user (company_id, user_id, time_frame, used_credits) \
     VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE used_credits = VALUES(used_credits)";
// The one additive write. A row created here carries an empty used_credits, which decodes as "no
// usage"; an existing row keeps its credits, since the update names only the counters.
const ADD_REJECTIONS: &str = "INSERT INTO credit_usage_company \
     (company_id, time_frame, used_credits, rejected_10s, rejected_1h, rejected_no_funds) \
     VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE \
     rejected_10s = COALESCE(rejected_10s, 0) + VALUES(rejected_10s), \
     rejected_1h = COALESCE(rejected_1h, 0) + VALUES(rejected_1h), \
     rejected_no_funds = COALESCE(rejected_no_funds, 0) + VALUES(rejected_no_funds)";

const SELECT_BUDGET: &str = "SELECT daily_cpu, daily_inference, budget_month_start_day, \
     monthly_cpu_ceiling, monthly_inference_ceiling, last_set_cpu, last_set_inference, updated, \
     usage_day_period, day_extra_cpu_used, usage_month_start_day, month_extra_cpu_used \
     FROM company_credit_budget WHERE company_id = ?";
const UPSERT_BUDGET: &str = "INSERT INTO company_credit_budget \
     (company_id, daily_cpu, daily_inference, budget_month_start_day, monthly_cpu_ceiling, \
      monthly_inference_ceiling, last_set_cpu, last_set_inference, updated) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE \
     daily_cpu = VALUES(daily_cpu), daily_inference = VALUES(daily_inference), \
     budget_month_start_day = VALUES(budget_month_start_day), \
     monthly_cpu_ceiling = VALUES(monthly_cpu_ceiling), \
     monthly_inference_ceiling = VALUES(monthly_inference_ceiling), \
     last_set_cpu = VALUES(last_set_cpu), last_set_inference = VALUES(last_set_inference), \
     updated = VALUES(updated)";
const UPSERT_BUDGET_USAGE: &str = "INSERT INTO company_credit_budget \
     (company_id, usage_day_period, day_cpu_used, day_inference_used, usage_month_start_day, \
      month_cpu_used, month_inference_used, day_extra_cpu_used, month_extra_cpu_used, usage_updated) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE \
     usage_day_period = VALUES(usage_day_period), day_cpu_used = VALUES(day_cpu_used), \
     day_inference_used = VALUES(day_inference_used), \
     usage_month_start_day = VALUES(usage_month_start_day), \
     month_cpu_used = VALUES(month_cpu_used), month_inference_used = VALUES(month_inference_used), \
     day_extra_cpu_used = VALUES(day_extra_cpu_used), \
     month_extra_cpu_used = VALUES(month_extra_cpu_used), usage_updated = VALUES(usage_updated)";

// Authorization, not usage: a primary-key point read of the row the route gate needs.
const SELECT_USER_ACCESS: &str = "SELECT accesos_computed, accesos_sub_computed, status \
     FROM users WHERE company_id = ? AND id = ?";

/// The pool caches each connection's prepared statements, so the SQL above is prepared once per
/// connection rather than per call.
pub struct MariaLimiterStore {
    pool: Pool,
}

impl MariaLimiterStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LimiterStore for MariaLimiterStore {
    async fn load_exact(&self, key: UsageKey) -> Result<Option<StoredUsage>> {
        let rows = self
            .load_range(key.company_id, key.user_id, key.time_frame, key.time_frame)
            .await?;
        Ok(rows.into_iter().next())
    }

    async fn load_range(
        &self,
        company_id: i32,
        user_id: i32,
        start_time_frame: i32,
        end_time_frame: i32,
    ) -> Result<Vec<StoredUsage>> {
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        // The company table has no user_id column at all, so the aggregate read binds three values
        // and the per-user read binds four.
        let rows: Vec<(i32, Option<Vec<u8>>)> = if user_id == COMPANY_AGGREGATE_USER_ID {
            connection
                .exec(
                    SELECT_COMPANY_RANGE,
                    (company_id, start_time_frame, end_time_frame),
                )
                .await
        } else {
            connection
                .exec(
                    SELECT_USER_RANGE,
                    (company_id, user_id, start_time_frame, end_time_frame),
                )
                .await
        }
        .context("credit usage range read failed")?;
        Ok(rows
            .into_iter()
            .map(|(time_frame, used_credits)| StoredUsage {
                time_frame,
                used_credits: used_credits.unwrap_or_default(),
            })
            .collect())
    }

    async fn upsert(&self, key: UsageKey, used_credits: Vec<u8>) -> Result<()> {
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        if key.is_company_aggregate() {
            connection
                .exec_drop(
                    UPSERT_COMPANY,
                    (key.company_id, key.time_frame, used_credits),
                )
                .await
                .context("credit_usage_company absolute upsert failed")?;
        } else {
            connection
                .exec_drop(
                    UPSERT_USER,
                    (key.company_id, key.user_id, key.time_frame, used_credits),
                )
                .await
                .context("credit_usage_user absolute upsert failed")?;
        }
        Ok(())
    }

    async fn add_rejections(
        &self,
        company_id: i32,
        time_frame: i32,
        rejections: Rejections,
    ) -> Result<()> {
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        connection
            .exec_drop(
                ADD_REJECTIONS,
                (
                    company_id,
                    time_frame,
                    Vec::<u8>::new(),
                    rejections.burst,
                    rejections.hour,
                    rejections.no_funds,
                ),
            )
            .await
            .context("credit_usage_company rejection counters update failed")?;
        Ok(())
    }

    async fn load_budget(&self, company_id: i32) -> Result<Option<StoredBudgetRow>> {
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        // Every non-key ORM column is nullable: a company the daemon has never flushed for has no
        // usage cells, and one whose budget was never set has no entitlement cells.
        type BudgetRow = (
            Option<i64>,
            Option<i64>,
            Option<i16>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i32>,
            Option<i16>,
            Option<i64>,
            Option<i16>,
            Option<i64>,
        );
        let row: Option<BudgetRow> = connection
            .exec_first(SELECT_BUDGET, (company_id,))
            .await
            .context("company_credit_budget read failed")?;
        let Some((
            daily_cpu,
            daily_inference,
            month_start,
            monthly_cpu,
            monthly_inference,
            last_set_cpu,
            last_set_inference,
            updated,
            extra_day_period,
            extra_day_cpu,
            extra_month_start_day,
            extra_month_cpu,
        )) = row
        else {
            return Ok(None);
        };
        let credits = [
            daily_cpu,
            daily_inference,
            monthly_cpu,
            monthly_inference,
            last_set_cpu,
            last_set_inference,
            extra_day_cpu,
            extra_month_cpu,
        ]
        .map(|value| value.unwrap_or(0));
        if credits.iter().any(|value| *value < 0) {
            anyhow::bail!("company_credit_budget contains negative credits");
        }
        let [
            daily_cpu,
            daily_inference,
            monthly_cpu,
            monthly_inference,
            last_set_cpu,
            last_set_inference,
            extra_day_cpu,
            extra_month_cpu,
        ] = credits.map(|value| value as u64);
        let budget = StoredBudget {
            company_id,
            daily: Credits {
                cpu: daily_cpu,
                inference: daily_inference,
            },
            budget_month_start_day: month_start.unwrap_or(0),
            monthly_ceiling: Credits {
                cpu: monthly_cpu,
                inference: monthly_inference,
            },
            last_set: Credits {
                cpu: last_set_cpu,
                inference: last_set_inference,
            },
            updated: updated.unwrap_or(0),
        };
        Ok(Some(StoredBudgetRow {
            budget,
            extra: StoredExtraUsage {
                day_period: extra_day_period.unwrap_or(0),
                day_cpu: extra_day_cpu,
                month_start_day: extra_month_start_day.unwrap_or(0),
                month_cpu: extra_month_cpu,
            },
        }))
    }

    async fn upsert_budget(&self, budget: StoredBudget) -> Result<()> {
        let daily_cpu =
            i64::try_from(budget.daily.cpu).context("daily CPU budget exceeds int64")?;
        let daily_inference = i64::try_from(budget.daily.inference)
            .context("daily inference budget exceeds int64")?;
        let monthly_cpu = i64::try_from(budget.monthly_ceiling.cpu)
            .context("monthly CPU ceiling exceeds int64")?;
        let monthly_inference = i64::try_from(budget.monthly_ceiling.inference)
            .context("monthly inference ceiling exceeds int64")?;
        let last_set_cpu =
            i64::try_from(budget.last_set.cpu).context("last set CPU credits exceed int64")?;
        let last_set_inference = i64::try_from(budget.last_set.inference)
            .context("last set inference credits exceed int64")?;
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        connection
            .exec_drop(
                UPSERT_BUDGET,
                (
                    budget.company_id,
                    daily_cpu,
                    daily_inference,
                    budget.budget_month_start_day,
                    monthly_cpu,
                    monthly_inference,
                    last_set_cpu,
                    last_set_inference,
                    budget.updated,
                ),
            )
            .await
            .context("company_credit_budget upsert failed")?;
        Ok(())
    }

    async fn upsert_budget_usage(&self, usage: StoredBudgetUsage) -> Result<()> {
        let day_cpu = i64::try_from(usage.day_used.cpu).context("daily CPU usage exceeds int64")?;
        let day_inference = i64::try_from(usage.day_used.inference)
            .context("daily inference usage exceeds int64")?;
        let month_cpu =
            i64::try_from(usage.month_used.cpu).context("monthly CPU usage exceeds int64")?;
        let month_inference = i64::try_from(usage.month_used.inference)
            .context("monthly inference usage exceeds int64")?;
        let day_extra_cpu =
            i64::try_from(usage.day_extra_cpu).context("daily extra CPU usage exceeds int64")?;
        let month_extra_cpu = i64::try_from(usage.month_extra_cpu)
            .context("monthly extra CPU usage exceeds int64")?;
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        connection
            .exec_drop(
                UPSERT_BUDGET_USAGE,
                (
                    usage.company_id,
                    usage.day_period,
                    day_cpu,
                    day_inference,
                    usage.month_start_day,
                    month_cpu,
                    month_inference,
                    day_extra_cpu,
                    month_extra_cpu,
                    usage.updated,
                ),
            )
            .await
            .context("company_credit_budget usage upsert failed")?;
        Ok(())
    }

    async fn load_user_access(
        &self,
        company_id: i32,
        user_id: i32,
    ) -> Result<Option<StoredUserAccess>> {
        let mut connection = self
            .pool
            .get_conn()
            .await
            .context("no MariaDB connection")?;
        // A user saved before ever being given a profile has no accesos_computed, and status is
        // nullable like every ORM column: decoding either as non-nullable would turn a legitimately
        // empty user into a read failure, which fails closed as a 503 rather than as a denial.
        let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<i8>)> = connection
            .exec_first(SELECT_USER_ACCESS, (company_id, user_id))
            .await
            .context("users access read failed")?;
        Ok(
            row.map(|(grants_blob, sub_grants_blob, status)| StoredUserAccess {
                grants_blob: grants_blob.unwrap_or_default(),
                sub_grants_blob: sub_grants_blob.unwrap_or_default(),
                status: status.unwrap_or(0),
            }),
        )
    }
}
