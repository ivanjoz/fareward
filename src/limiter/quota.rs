//! Atomic company/user quota admission and accepted-usage aggregation.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::limiter::{
    access::{AccessDenial, AccessVerdict, UserAccessState},
    aggregation::{
        COMPANY_AGGREGATE_USER_ID, UsageKey, UsageRecord, UsageSnapshot, add_routes, merge_loaded,
    },
    block::{Block, CompanyBlocks, Until},
    budget::{BudgetMutation, BudgetMutationReply, BudgetOperation},
    credits_blob::{Credits, RoutedCredits, decode, encode, sum},
    protocol::{LimitViolation, Request, Scope, Window},
    storage::{LimiterStore, StoredBudget, StoredBudgetUsage},
    time_frame,
};

const PLATFORM_AGGREGATE_COMPANY_ID: i32 = 0;

/// The two rate-limit windows every scope is judged on, from `[rate_limit]`. Always two: a short
/// token bucket against bursts and a long fixed clock window against sustained load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    /// `short_window_seconds`: the bucket's period. `short` credits refill over this many seconds,
    /// continuously.
    pub short_seconds: u64,
    /// `long_window_minutes`: a fixed clock window, aligned to the Unix epoch (with 10, the
    /// windows start at :00, :10, :20…). A multiple of five minutes, because a restart recovers it
    /// by summing the five-minute usage rows.
    pub long_minutes: u64,
}

impl Default for Windows {
    /// Ten seconds and one hour: the windows the daemon had before they were configurable.
    fn default() -> Self {
        Self {
            short_seconds: 10,
            long_minutes: 60,
        }
    }
}

impl Windows {
    pub fn short(&self) -> Duration {
        Duration::from_secs(self.short_seconds)
    }

    pub fn long_seconds(&self) -> i64 {
        i64::try_from(self.long_minutes.saturating_mul(60)).unwrap_or(i64::MAX)
    }

    /// The window as the 429 page words it: "en los últimos 10 segundos", "… 10 minutos",
    /// "en la última hora".
    pub fn describe(&self, window: Window) -> String {
        let seconds = match window {
            Window::Short => self.short_seconds,
            Window::Long => self.long_minutes.saturating_mul(60),
            Window::Day => return "hoy".into(),
            Window::Month => return "este mes".into(),
        };
        match seconds {
            1 => "en el último segundo".into(),
            60 => "en el último minuto".into(),
            3_600 => "en la última hora".into(),
            seconds if seconds % 3_600 == 0 => format!("en las últimas {} horas", seconds / 3_600),
            seconds if seconds % 60 == 0 => format!("en los últimos {} minutos", seconds / 60),
            seconds => format!("en los últimos {seconds} segundos"),
        }
    }
}

/// What one frame was answered with.
///
/// Authorization and quota are separate refusals with separate HTTP answers on the Go side, so they
/// are separate variants rather than one status byte: a 403 is not a 429 and must not be reported as
/// one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Carries the authorization verdict when the frame asked for one, so the reply can name which
    /// required slots were granted and hand back their sub-accesses. `Default` — an all-zero
    /// verdict — is what a frame that asked nothing gets.
    Allowed(AccessVerdict),
    CreditViolation(LimitViolation),
    AccessDenied(AccessDenial),
}

/// The figures a client is shown about its own consumption (the SPOE agent's `x-fareward-usage`
/// header), read under the same shard lock as the verdict. CPU only: it is the dimension every
/// route charges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsageReport {
    /// CPU credits the user may still spend today. `None` when users are not limited apart
    /// (`disable_user_limit`), or when the verdict came from the block cache, which knows only the
    /// company.
    pub user_day_left: Option<u64>,
    /// CPU credits the company may still spend today, out of its daily entitlement.
    pub company_day_left: u64,
    /// CPU credits the company has spent in the short-window bucket: what has not refilled yet.
    pub company_short_used: u64,
    /// CPU credits the company has spent in the current long window.
    pub company_long_used: u64,
    /// Set only on a refusal answered by the block cache (plan D9): how many requests the block has
    /// refused, counting the one whose refusal created it. The other figures are then the ones the
    /// block was created on.
    pub blocked: Option<u32>,
    /// On a credit refusal: CPU credits spent in the window that refused (the burst bucket, the
    /// hour, the day or the month, of the scope that refused). Zero otherwise.
    pub window_used: u64,
    /// On a credit refusal: seconds to wait before the refusing gate can reopen, with a margin.
    pub retry_after: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct CreditLimits {
    pub short: u64,
    pub long: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ScopeLimits {
    pub cpu: CreditLimits,
    pub inference: CreditLimits,
}

#[derive(Clone, Copy, Debug)]
pub struct LimitPolicy {
    pub company: ScopeLimits,
    pub user: ScopeLimits,
    /// CPU credits a company may spend per local business day *after* its normal quota has refused,
    /// and only on a frame the router marked as a read. Zero disables the pool entirely, which is
    /// the default: a guessed free allowance is credit given away.
    ///
    /// CPU only, and one number rather than a `Credits`: inference is charged by
    /// `ChargeInferenceUsage`, which never carries the mark, so an inference dimension here could
    /// only ever be dead weight.
    pub company_extra_daily_cpu: u64,
    /// Percentage of the company's daily entitlement one user may spend, from
    /// `rate_limit.user_daily_share_pct`. At 100 a single user can spend the whole company
    /// allowance and the burst gates above are the only per-user brake left.
    ///
    /// A share and not a fixed number of credits because the daily figure is per-tenant
    /// (`company_credit_budget`, administered by the SaaS panel) while this is platform policy: a
    /// fixed ceiling here would mean something different for every tenant. Anything below 100 makes
    /// part of the purchased allowance unreachable for a single-user company, which is most of them.
    pub user_daily_share_pct: u64,
    /// `rate_limit.disable_user_limit`: rate limit by company only. Each company is one customer
    /// who creates its own users, so limiting those users apart protects nobody from anybody.
    ///
    /// When set, a user gets no `SubjectState`, no cold load from storage and no gate of its own, so
    /// `user` and `user_daily_share_pct` stop mattering and no violation carries `Scope::User`. The
    /// per-user usage rows are still written: they are accounting, not a limit, and since nothing
    /// loads them before the charge any more, the flush adds the stored row in
    /// (`UsageRecord::unseeded`).
    pub disable_user_limit: bool,
    /// How long the short and the long window last. `CreditLimits::short` and `long` are credits
    /// per window.
    pub windows: Windows,
}

impl LimitPolicy {
    /// The daily entitlement one user is judged against: the company's, cut to the configured share.
    fn user_daily(&self, company_daily: Credits) -> Credits {
        Credits {
            cpu: daily_share(company_daily.cpu, self.user_daily_share_pct),
            inference: daily_share(company_daily.inference, self.user_daily_share_pct),
        }
    }
}

/// Multiplies before dividing, in u128: a purchased daily figure near the int64 column ceiling would
/// overflow u64 halfway through, and rounding the division first would lose credits on small
/// allowances.
fn daily_share(company_daily: u64, percent: u64) -> u64 {
    u64::try_from(u128::from(company_daily) * u128::from(percent) / 100).unwrap_or(u64::MAX)
}

/// `limit` credits per `period`, refilled continuously. Tokens are kept scaled by the period in
/// nanoseconds, so a refill of `elapsed × limit` is exact integer arithmetic.
#[derive(Debug)]
struct TokenBucket {
    scaled_tokens: u128,
    last_refill: Instant,
    period: Duration,
}

impl TokenBucket {
    fn full(limit: u64, period: Duration, now: Instant) -> Self {
        let mut bucket = Self {
            scaled_tokens: 0,
            last_refill: now,
            period,
        };
        bucket.scaled_tokens = bucket.capacity(limit);
        bucket
    }

    fn capacity(&self, limit: u64) -> u128 {
        u128::from(limit) * self.period.as_nanos()
    }

    fn scaled(&self, credits: u64) -> u128 {
        u128::from(credits) * self.period.as_nanos()
    }

    fn refill(&mut self, limit: u64, now: Instant) {
        let elapsed_nanos = now.duration_since(self.last_refill).as_nanos();
        let refill = elapsed_nanos.saturating_mul(u128::from(limit));
        self.scaled_tokens = self
            .scaled_tokens
            .saturating_add(refill)
            .min(self.capacity(limit));
        self.last_refill = now;
    }

    fn can_charge(&self, credits: u64) -> bool {
        self.scaled_tokens >= self.scaled(credits)
    }

    fn charge(&mut self, credits: u64) {
        self.scaled_tokens -= self.scaled(credits);
    }

    /// Credits taken and not refilled yet, rounded up. Valid right after a refill.
    fn used(&self, limit: u64) -> u64 {
        let used = self.capacity(limit).saturating_sub(self.scaled_tokens);
        u64::try_from(used.div_ceil(self.period.as_nanos())).unwrap_or(u64::MAX)
    }

    /// How long until `credits` fit, counted from the last refill. A charge larger than the whole
    /// bucket never fits; it waits one full period and is judged again.
    fn wait_for(&self, credits: u64, limit: u64) -> Duration {
        let needed = self.scaled(credits);
        if needed <= self.scaled_tokens {
            return Duration::ZERO;
        }
        if limit == 0 || needed > self.capacity(limit) {
            return self.period;
        }
        let nanos = (needed - self.scaled_tokens).div_ceil(u128::from(limit));
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

#[derive(Debug)]
struct SubjectState {
    cpu_bucket: TokenBucket,
    inference_bucket: TokenBucket,
    /// The long window's length; `long_period` is the Unix time divided by it.
    long_seconds: i64,
    long_period: i64,
    // The local business UnixDay, not the UTC one: this counter is seeded from the daily usage row,
    // which is bucketed by `time_frame::daily`, so counting it on any other day would both reset the
    // daily cap five hours early and reseed it from a window it does not cover.
    day_period: i64,
    long_used: Credits,
    day_used: Credits,
}

#[derive(Debug)]
struct CompanyBudgetState {
    stored: StoredBudget,
    usage_month_start_day: i16,
    month_used: Credits,
    // The extra daily pool's two counters, kept here rather than on the subject because the pool is
    // an entitlement of the company and this is where entitlement lives.
    //
    // `day_extra_used` IS the pool: it is what every eligible frame is measured against. The local
    // business day it belongs to is tracked alongside it, for the same reason SubjectState tracks
    // its own — on the raw UTC division the pool would reset at 19:00 local time.
    //
    // `month_extra_used` is not a second pool; there is no monthly extra ceiling. It exists so
    // `ensure_budget` can rebuild `month_used` correctly after a restart: that counter is recovered
    // by summing the usage rows, and those rows include everything the pool paid for.
    extra_day_period: i64,
    day_extra_used: u64,
    month_extra_used: u64,
    // Mutation versions, exactly as UsageRecord carries them: the flush publishes the counters this
    // company enforces on, and a write that completes after a concurrent charge must not mark the
    // newer figure as durable.
    version: u64,
    flushed_version: u64,
}

impl CompanyBudgetState {
    fn refresh_month(&mut self, current_month_start_day: i16) {
        if self.usage_month_start_day != current_month_start_day {
            self.usage_month_start_day = current_month_start_day;
            self.month_used = Credits::default();
            self.month_extra_used = 0;
        }
    }

    /// Rolls the extra pool over. Driven by the same local business day the company's SubjectState
    /// is refreshed with in the same pass, so the two counters the flushed row carries can never be
    /// labelled with different days.
    fn refresh_day(&mut self, current_day_period: i64) {
        if self.extra_day_period != current_day_period {
            self.extra_day_period = current_day_period;
            self.day_extra_used = 0;
        }
    }

    /// What this frame may still take from the pool, or `None` when the pool cannot pay for it.
    ///
    /// Inference is refused outright rather than partially relaxed: the pool is a single CPU figure,
    /// so there is nothing here that could authorize an inference credit.
    fn extra_grant(&self, requested: Credits, pool: u64) -> Option<u64> {
        if pool == 0 || requested.inference > 0 || requested.cpu == 0 {
            return None;
        }
        let total = self.day_extra_used.checked_add(requested.cpu)?;
        (total <= pool).then_some(requested.cpu)
    }

    fn add_extra_used(&mut self, cpu: u64) -> Result<()> {
        self.day_extra_used = self
            .day_extra_used
            .checked_add(cpu)
            .ok_or_else(|| anyhow!("daily extra usage overflowed uint64"))?;
        self.month_extra_used = self
            .month_extra_used
            .checked_add(cpu)
            .ok_or_else(|| anyhow!("monthly extra usage overflowed uint64"))?;
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow!("budget usage mutation version overflowed uint64"))?;
        Ok(())
    }

    fn add_month_used(&mut self, credits: Credits) -> Result<()> {
        self.month_used = self
            .month_used
            .checked_add(credits)
            .ok_or_else(|| anyhow!("monthly usage overflowed uint64"))?;
        // A rollover needs no version bump of its own: the flushed row names the month and the day it
        // belongs to, so a reader already reads a window the daemon has not touched as unused.
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow!("budget usage mutation version overflowed uint64"))?;
        Ok(())
    }

    /// The row to flush, or `None` when nothing was charged since the last successful write. The
    /// daily counter lives on the company aggregate subject, so it is read in the same shard pass.
    fn usage_snapshot(
        &self,
        company_id: i32,
        day_used: Credits,
        day_period: i64,
        unix_seconds: i64,
    ) -> Result<Option<(StoredBudgetUsage, u64)>> {
        if self.version == self.flushed_version {
            return Ok(None);
        }
        let snapshot = StoredBudgetUsage {
            company_id,
            day_period: i16::try_from(day_period)
                .context("local business day does not fit int16")?,
            day_used,
            month_start_day: self.usage_month_start_day,
            month_used: self.month_used,
            day_extra_cpu: self.day_extra_used,
            month_extra_cpu: self.month_extra_used,
            updated: sunix_time(unix_seconds)?,
        };
        Ok(Some((snapshot, self.version)))
    }

    fn mark_usage_flushed(&mut self, version: u64) {
        if self.version == version {
            self.flushed_version = version;
        }
    }

    fn monthly_violation(&self, requested: Credits) -> Option<LimitViolation> {
        let active = self.stored.budget_month_start_day == self.usage_month_start_day;
        let cpu = requested.cpu > 0
            && (!active
                || exceeds(
                    self.month_used.cpu,
                    requested.cpu,
                    self.stored.monthly_ceiling.cpu,
                ));
        let inference = requested.inference > 0
            && (!active
                || exceeds(
                    self.month_used.inference,
                    requested.inference,
                    self.stored.monthly_ceiling.inference,
                ));
        (cpu || inference).then_some(LimitViolation {
            scope: Scope::Company,
            window: Window::Month,
            cpu,
            inference,
        })
    }
}

impl SubjectState {
    fn recovered(
        limits: ScopeLimits,
        windows: Windows,
        unix_seconds: i64,
        day_period: i64,
        now: Instant,
        long_used: Credits,
        day_used: Credits,
    ) -> Self {
        let long_seconds = windows.long_seconds();
        Self {
            cpu_bucket: TokenBucket::full(limits.cpu.short, windows.short(), now),
            inference_bucket: TokenBucket::full(limits.inference.short, windows.short(), now),
            long_seconds,
            long_period: unix_seconds / long_seconds,
            day_period,
            long_used,
            day_used,
        }
    }

    /// How long until both buckets hold `requested`. Valid right after `refresh_periods`, which is
    /// when the refills were last brought up to `now`.
    fn burst_wait(&self, limits: ScopeLimits, requested: Credits) -> Duration {
        self.cpu_bucket
            .wait_for(requested.cpu, limits.cpu.short)
            .max(
                self.inference_bucket
                    .wait_for(requested.inference, limits.inference.short),
            )
    }

    fn refresh_periods(
        &mut self,
        limits: ScopeLimits,
        unix_seconds: i64,
        day_period: i64,
        now: Instant,
    ) {
        self.cpu_bucket.refill(limits.cpu.short, now);
        self.inference_bucket.refill(limits.inference.short, now);
        let long_period = unix_seconds / self.long_seconds;
        if self.long_period != long_period {
            self.long_period = long_period;
            self.long_used = Credits::default();
        }
        if self.day_period != day_period {
            self.day_period = day_period;
            self.day_used = Credits::default();
        }
    }

    fn violation(
        &self,
        scope: Scope,
        window: Window,
        limits: ScopeLimits,
        requested: Credits,
    ) -> Option<LimitViolation> {
        let (cpu, inference) = match window {
            Window::Short => (
                !self.cpu_bucket.can_charge(requested.cpu),
                !self.inference_bucket.can_charge(requested.inference),
            ),
            Window::Long => (
                exceeds(self.long_used.cpu, requested.cpu, limits.cpu.long),
                exceeds(
                    self.long_used.inference,
                    requested.inference,
                    limits.inference.long,
                ),
            ),
            // Daily/monthly entitlement belongs to the company budget, not static policy.
            Window::Day | Window::Month => (false, false),
        };
        (cpu || inference).then_some(LimitViolation {
            scope,
            window,
            cpu,
            inference,
        })
    }

    /// `count_daily` is false only for a charge paid out of the extra daily pool.
    ///
    /// The buckets and the long-window counter are charged either way, and that is not an oversight: they
    /// are rate limits protecting the machine, so a tenant spending its extra allowance must still
    /// queue behind them. Skipping them would give a company in read-only mode unlimited burst.
    /// `day_used` is different — it is the meter the entitlement gates judge, and extra spending is
    /// counted apart from it precisely so `daily - day_used` keeps meaning what it means for a write.
    fn charge(&mut self, requested: Credits, count_daily: bool) -> Result<()> {
        self.cpu_bucket.charge(requested.cpu);
        self.inference_bucket.charge(requested.inference);
        self.long_used = self
            .long_used
            .checked_add(requested)
            .ok_or_else(|| anyhow!("hour usage overflowed uint64"))?;
        if count_daily {
            self.day_used = self
                .day_used
                .checked_add(requested)
                .ok_or_else(|| anyhow!("daily usage overflowed uint64"))?;
        }
        Ok(())
    }
}

fn exceeds(current: u64, requested: u64, limit: u64) -> bool {
    current
        .checked_add(requested)
        .is_none_or(|total| total > limit)
}

fn fixed_limit_violation(
    scope: Scope,
    window: Window,
    current: Credits,
    requested: Credits,
    limit: Credits,
) -> Option<LimitViolation> {
    let cpu = exceeds(current.cpu, requested.cpu, limit.cpu);
    let inference = exceeds(current.inference, requested.inference, limit.inference);
    (cpu || inference).then_some(LimitViolation {
        scope,
        window,
        cpu,
        inference,
    })
}

#[derive(Default)]
struct ShardState {
    subjects: HashMap<(i32, i32), SubjectState>,
    budgets: HashMap<i32, CompanyBudgetState>,
    usage: HashMap<UsageKey, UsageRecord>,
    // Authorization grants, on the same key and behind the same mutex as the quota state so a
    // request that both authorizes and charges still takes one lock. A separate map rather than a
    // field on SubjectState: the lifetimes differ (a TTL and an invalidation channel, versus state
    // that lives as long as the process), the company aggregate has no accesses, and because
    // denial precedes charging an unauthorized caller must not get a SubjectState allocated for it.
    access: HashMap<(i32, i32), UserAccessState>,
}

pub struct RateLimiter {
    shards: Vec<Mutex<ShardState>>,
    access_cache_seconds: i64,
    // Platform usage has one reserved key shared by every company. Keeping it outside the
    // company-sharded maps prevents competing absolute snapshots from overwriting one another.
    platform_usage: Mutex<HashMap<UsageKey, UsageRecord>>,
    policy: LimitPolicy,
    store: Arc<dyn LimiterStore>,
    // One flush at a time. An unseeded row's flush reads the stored row and adds it in; two flushes
    // of the same row at once would both add it, so this is a correctness requirement and not only
    // the habit of the caller (main.rs already flushes sequentially).
    flush_lock: Mutex<()>,
    // Companies a gate refused, answered without the shard lock until the gate can reopen, and the
    // refusal counters the flush persists (plan D9).
    blocks: CompanyBlocks,
}

impl RateLimiter {
    pub fn new(
        shard_count: usize,
        policy: LimitPolicy,
        store: Arc<dyn LimiterStore>,
        access_cache_seconds: i64,
    ) -> Self {
        let shards = (0..shard_count.max(1))
            .map(|_| Mutex::new(ShardState::default()))
            .collect();
        Self {
            shards,
            access_cache_seconds,
            platform_usage: Mutex::new(HashMap::new()),
            policy,
            store,
            flush_lock: Mutex::new(()),
            blocks: CompanyBlocks::new(shard_count),
        }
    }

    /// How long the short and the long window last, for whoever words a refusal.
    pub fn windows(&self) -> Windows {
        self.policy.windows
    }

    pub async fn admit(&self, request: Request) -> Result<Decision> {
        let unix_seconds = current_unix_seconds()?;
        self.admit_at(request, unix_seconds, Instant::now()).await
    }

    /// `admit`, plus the figures the SPOE agent shows the client. The report is `None` when the
    /// verdict came before any quota state was read: an authorization refusal.
    pub async fn admit_reported(
        &self,
        request: Request,
    ) -> Result<(Decision, Option<UsageReport>)> {
        let unix_seconds = current_unix_seconds()?;
        self.judge(request, unix_seconds, Instant::now(), false)
            .await
    }

    /// The verdict `admit` would give, without acting on it: nothing is charged, no row is dirtied,
    /// no company is blocked and no refusal is counted. For the SPOE agent's shadow mode (plan
    /// phase 7), where the backend still charges every request over TCP against this same limiter,
    /// so an evaluation that charged or blocked would bill or refuse the request twice.
    ///
    /// It may still load state a cold company or user needs, as `admit` would: that is a cache
    /// fill, not an effect.
    pub async fn evaluate(&self, request: Request) -> Result<Decision> {
        let unix_seconds = current_unix_seconds()?;
        self.admit_mode_at(request, unix_seconds, Instant::now(), true)
            .await
    }

    async fn admit_at(
        &self,
        request: Request,
        unix_seconds: i64,
        now: Instant,
    ) -> Result<Decision> {
        self.admit_mode_at(request, unix_seconds, now, false).await
    }

    async fn admit_mode_at(
        &self,
        request: Request,
        unix_seconds: i64,
        now: Instant,
        dry_run: bool,
    ) -> Result<Decision> {
        Ok(self.judge(request, unix_seconds, now, dry_run).await?.0)
    }

    async fn judge(
        &self,
        request: Request,
        unix_seconds: i64,
        now: Instant,
        dry_run: bool,
    ) -> Result<(Decision, Option<UsageReport>)> {
        let blocked = if dry_run {
            self.blocks.peek(&request, unix_seconds, now)
        } else {
            self.blocks.check(&request, unix_seconds, now)
        };
        if let Some((violation, report)) = blocked {
            return Ok((Decision::CreditViolation(violation), Some(report)));
        }
        let shard_index = request.company_id as usize % self.shards.len();
        let mut shard = self.shards[shard_index].lock().await;

        // Authorization first, and on refusal nothing is charged: no usage row, no SubjectState, no
        // budget load. A 403 costs the tenant nothing, which is the deliberate trade — the work
        // being given away is one binary search over a cached list.
        let mut access_verdict = AccessVerdict::default();
        if request.requests_authorization() {
            self.ensure_access(
                &mut shard,
                request.company_id,
                request.user_id,
                unix_seconds,
            )
            .await?;
            match shard
                .access
                .get(&(request.company_id, request.user_id))
                .expect("user access initialized")
                .verdict(&request.required_access)
            {
                Ok(verdict) => access_verdict = verdict,
                Err(denial) => {
                    debug!(
                        company_id = request.company_id,
                        user_id = request.user_id,
                        route_id = request.route_id,
                        ?denial,
                        "authorization refused"
                    );
                    return Ok((Decision::AccessDenied(denial), None));
                }
            }
        }

        // The budget is loaded before the subjects, and not after the company one as it used to be,
        // because seeding a subject needs its extra-pool counter: the usage rows a cold subject is
        // recovered from include what the pool paid for.
        self.ensure_budget(&mut shard, request.company_id, unix_seconds)
            .await?;
        let day_extra_used = shard
            .budgets
            .get(&request.company_id)
            .expect("company budget initialized")
            .day_extra_used;
        self.ensure_subject(
            &mut shard,
            request.company_id,
            COMPANY_AGGREGATE_USER_ID,
            self.policy.company,
            unix_seconds,
            now,
            day_extra_used,
        )
        .await?;
        let user_limited = !self.policy.disable_user_limit;
        if user_limited {
            self.ensure_subject(
                &mut shard,
                request.company_id,
                request.user_id,
                self.policy.user,
                unix_seconds,
                now,
                day_extra_used,
            )
            .await?;
        }

        let company_key = (request.company_id, COMPANY_AGGREGATE_USER_ID);
        let user_key = (request.company_id, request.user_id);
        let current_day_period = time_frame::local_unix_day(unix_seconds)?;
        shard
            .subjects
            .get_mut(&company_key)
            .expect("company state initialized")
            .refresh_periods(self.policy.company, unix_seconds, current_day_period, now);
        if user_limited {
            shard
                .subjects
                .get_mut(&user_key)
                .expect("user state initialized")
                .refresh_periods(self.policy.user, unix_seconds, current_day_period, now);
        }
        let current_month_start_day = time_frame::month_start_day(unix_seconds)?;
        let budget = shard
            .budgets
            .get_mut(&request.company_id)
            .expect("company budget initialized");
        budget.refresh_month(current_month_start_day);
        budget.refresh_day(current_day_period);

        // Shortest window and company scope win, matching the documented response priority.
        for window in [Window::Short, Window::Long] {
            let company = shard
                .subjects
                .get(&company_key)
                .expect("company state initialized");
            if let Some(violation) =
                company.violation(Scope::Company, window, self.policy.company, request.credits)
            {
                let report = self.refused_report(&shard, &request, violation, unix_seconds, now);
                if !dry_run {
                    self.block_company(
                        &request,
                        violation,
                        company,
                        report,
                        true,
                        unix_seconds,
                        now,
                    );
                }
                return Ok((Decision::CreditViolation(violation), Some(report)));
            }
            if user_limited {
                let user = shard
                    .subjects
                    .get(&user_key)
                    .expect("user state initialized");
                if let Some(violation) =
                    user.violation(Scope::User, window, self.policy.user, request.credits)
                {
                    let report =
                        self.refused_report(&shard, &request, violation, unix_seconds, now);
                    return Ok((Decision::CreditViolation(violation), Some(report)));
                }
            }
        }

        let company = shard
            .subjects
            .get(&company_key)
            .expect("company state initialized");
        let user = user_limited.then(|| {
            shard
                .subjects
                .get(&user_key)
                .expect("user state initialized")
        });
        let budget = shard
            .budgets
            .get(&request.company_id)
            .expect("company budget initialized");
        // The three entitlement gates, evaluated together instead of returning one by one, because
        // any of them refusing leads to the same second question: can the extra pool pay for this?
        let quota_violation = fixed_limit_violation(
            Scope::Company,
            Window::Day,
            company.day_used,
            request.credits,
            budget.stored.daily,
        )
        .or_else(|| {
            fixed_limit_violation(
                Scope::User,
                Window::Day,
                user?.day_used,
                request.credits,
                self.policy.user_daily(budget.stored.daily),
            )
        })
        .or_else(|| budget.monthly_violation(request.credits));

        // The pool is consulted only after normal quota has refused, never before: a read that fits
        // in the entitlement the tenant paid for is charged against it, as it should be. There is no
        // per-user share of the pool — it is a company allowance, and cutting it the way the daily
        // gate is cut would leave a single-user company, which is most of them, unable to reach it
        // at all. The burst gates above already bound the rate.
        let mut extra_cpu = 0;
        if let Some(violation) = quota_violation {
            let grant = request
                .extra_credits_allowed
                .then(|| budget.extra_grant(request.credits, self.policy.company_extra_daily_cpu))
                .flatten();
            let Some(grant) = grant else {
                // Marked reads stay unblocked while the pool still has credit: a smaller one may fit.
                let pool = self.policy.company_extra_daily_cpu;
                let pool_spent = pool == 0 || budget.day_extra_used >= pool;
                let report = self.refused_report(&shard, &request, violation, unix_seconds, now);
                if !dry_run {
                    self.block_company(
                        &request,
                        violation,
                        company,
                        report,
                        pool_spent,
                        unix_seconds,
                        now,
                    );
                }
                return Ok((Decision::CreditViolation(violation), Some(report)));
            };
            extra_cpu = grant;
        }
        let paid_from_extra = extra_cpu > 0;
        // Every gate has answered; what follows only acts on the verdict.
        if dry_run {
            let report = self.usage_report(&shard, request.company_id, request.user_id);
            return Ok((Decision::Allowed(access_verdict), Some(report)));
        }

        // Load the reserved absolute row before mutating accepted usage. A storage failure then
        // fails admission cleanly instead of charging company/user state without the platform row.
        let mut platform_usage = self.platform_usage.lock().await;
        self.ensure_platform_usage(&mut platform_usage, unix_seconds)
            .await?;

        shard
            .subjects
            .get_mut(&company_key)
            .expect("company state initialized")
            .charge(request.credits, !paid_from_extra)?;
        if user_limited {
            shard
                .subjects
                .get_mut(&user_key)
                .expect("user state initialized")
                .charge(request.credits, !paid_from_extra)?;
        }
        let budget = shard
            .budgets
            .get_mut(&request.company_id)
            .expect("company budget initialized");
        if paid_from_extra {
            // Deliberately not `add_month_used`: this credit was granted outside the entitlement, so
            // charging it against the monthly ceiling would spend money the tenant did not agree to.
            budget.add_extra_used(extra_cpu)?;
            // Logged at info because it is the only outward sign that a tenant is in read-only mode:
            // the reply frame does not change shape and the client cannot tell.
            info!(
                company_id = request.company_id,
                user_id = request.user_id,
                route_id = request.route_id,
                cpu = extra_cpu,
                day_extra_used = budget.day_extra_used,
                pool = self.policy.company_extra_daily_cpu,
                "request served from the extra daily pool"
            );
        } else {
            budget.add_month_used(request.credits)?;
        }
        // The usage rows are written either way. They are the record of what the platform actually
        // served — the per-route cards and the platform aggregate both read them — and a request
        // paid for out of the pool was served like any other.
        increment_usage(&mut shard.usage, request, unix_seconds, !user_limited)?;
        increment_platform_usage(&mut platform_usage, request, unix_seconds)?;
        // After the charge, so the client sees what is left once this request is paid for.
        let report = self.usage_report(&shard, request.company_id, request.user_id);
        Ok((Decision::Allowed(access_verdict), Some(report)))
    }

    /// The client's figures, read from the state the verdict was just reached on. Valid only after
    /// `refresh_periods` and the budget's own refreshes, which bring the buckets and the counters up
    /// to now.
    fn usage_report(&self, shard: &ShardState, company_id: i32, user_id: i32) -> UsageReport {
        let company = shard
            .subjects
            .get(&(company_id, COMPANY_AGGREGATE_USER_ID))
            .expect("company state initialized");
        let daily = shard
            .budgets
            .get(&company_id)
            .expect("company budget initialized")
            .stored
            .daily;
        let user_day_left = if self.policy.disable_user_limit {
            None
        } else {
            shard.subjects.get(&(company_id, user_id)).map(|user| {
                self.policy
                    .user_daily(daily)
                    .cpu
                    .saturating_sub(user.day_used.cpu)
            })
        };
        UsageReport {
            user_day_left,
            company_day_left: daily.cpu.saturating_sub(company.day_used.cpu),
            company_short_used: company.cpu_bucket.used(self.policy.company.cpu.short),
            company_long_used: company.long_used.cpu,
            blocked: None,
            window_used: 0,
            retry_after: None,
        }
    }

    /// `usage_report` for a credit refusal: the same figures plus what the refusing window had
    /// spent and how long until its gate reopens, so the client is told why and when to retry.
    fn refused_report(
        &self,
        shard: &ShardState,
        request: &Request,
        violation: LimitViolation,
        unix_seconds: i64,
        now: Instant,
    ) -> UsageReport {
        let (subject_id, limits) = match violation.scope {
            Scope::Company => (COMPANY_AGGREGATE_USER_ID, self.policy.company),
            Scope::User => (request.user_id, self.policy.user),
        };
        let subject = shard
            .subjects
            .get(&(request.company_id, subject_id))
            .expect("refusing subject initialized");
        let window_used = match violation.window {
            Window::Short => subject.cpu_bucket.used(limits.cpu.short),
            Window::Long => subject.long_used.cpu,
            Window::Day => subject.day_used.cpu,
            Window::Month => {
                shard
                    .budgets
                    .get(&request.company_id)
                    .expect("company budget initialized")
                    .month_used
                    .cpu
            }
        };
        let until = self.reopens(
            violation.window,
            subject,
            limits,
            request,
            unix_seconds,
            now,
        );
        UsageReport {
            window_used,
            retry_after: Some(until.retry_after(unix_seconds, now)),
            ..self.usage_report(shard, request.company_id, request.user_id)
        }
    }

    /// When the gate of `window` can admit `request` again, on the clock that gate runs on.
    fn reopens(
        &self,
        window: Window,
        subject: &SubjectState,
        limits: ScopeLimits,
        request: &Request,
        unix_seconds: i64,
        now: Instant,
    ) -> Until {
        match window {
            Window::Short => Until::Monotonic(now + subject.burst_wait(limits, request.credits)),
            // The long counter is a fixed clock window (`refresh_periods`), not a rolling one.
            Window::Long => {
                let length = subject.long_seconds;
                Until::UnixSeconds((unix_seconds / length + 1) * length)
            }
            // The month is re-judged every business day too: a block shorter than the verdict is
            // only ever conservative, and a budget mutation lifts it at once anyway.
            Window::Day | Window::Month => {
                // An unreadable day blocks nothing (the until is already reached); it still counts.
                let next_day_start = time_frame::local_unix_day(unix_seconds)
                    .map(|day| {
                        (day + 1) * time_frame::DAY_SECONDS - time_frame::DAY_ZONE_OFFSET_SECONDS
                    })
                    .unwrap_or(unix_seconds);
                Until::UnixSeconds(next_day_start)
            }
        }
    }

    /// Blocks the company until the gate that refused can reopen, and counts the refusal. A user
    /// refusal blocks nothing and counts nothing: the block and the counters describe the company.
    ///
    /// `marked_reads_too` only matters for a day or month refusal: while the extra pool still has
    /// credit, marked reads must keep reaching it. Short- and long-window refusals block them as well,
    /// because the pool never relaxes a burst gate.
    fn block_company(
        &self,
        request: &Request,
        violation: LimitViolation,
        company: &SubjectState,
        report: UsageReport,
        marked_reads_too: bool,
        unix_seconds: i64,
        now: Instant,
    ) {
        if violation.scope != Scope::Company {
            return;
        }
        let until = self.reopens(
            violation.window,
            company,
            self.policy.company,
            request,
            unix_seconds,
            now,
        );
        // Short- and long-window refusals block marked reads as well, because the pool never relaxes
        // them; a day or month block lets them through while the pool can still pay.
        let marked_reads_too = match violation.window {
            Window::Short | Window::Long => true,
            Window::Day | Window::Month => marked_reads_too,
        };
        self.blocks.record(
            request.company_id,
            Block {
                violation,
                until,
                applies_to_marked_reads: marked_reads_too,
                // The block answers every user of the company, so it keeps only the company's
                // figures: the user's belong to whoever happened to trigger it.
                report: UsageReport {
                    user_day_left: None,
                    ..report
                },
            },
            unix_seconds,
        );
    }

    pub async fn mutate_budget(&self, mutation: BudgetMutation) -> Result<BudgetMutationReply> {
        let unix_seconds = current_unix_seconds()?;
        self.mutate_budget_at(mutation, unix_seconds).await
    }

    async fn mutate_budget_at(
        &self,
        mutation: BudgetMutation,
        unix_seconds: i64,
    ) -> Result<BudgetMutationReply> {
        let shard_index = mutation.company_id as usize % self.shards.len();
        let mut shard = self.shards[shard_index].lock().await;
        self.ensure_budget(&mut shard, mutation.company_id, unix_seconds)
            .await?;
        let current_month_start_day = time_frame::month_start_day(unix_seconds)?;
        let budget_state = shard
            .budgets
            .get_mut(&mutation.company_id)
            .expect("company budget initialized");
        budget_state.refresh_month(current_month_start_day);
        let mut stored = budget_state.stored;

        // last_set tracks the granted figure, not the ceiling: SetCurrent restates it, IncreaseCurrent
        // moves it by the same amount it moves the ceiling so "consumed since the grant" stays
        // continuous across a top-up, and SetDaily leaves it alone because a rate limit grants nothing.
        match mutation.operation {
            BudgetOperation::SetDaily => stored.daily = mutation.credits,
            BudgetOperation::SetCurrent => {
                let Some(monthly_cpu_ceiling) = budget_state
                    .month_used
                    .cpu
                    .checked_add(mutation.credits.cpu)
                else {
                    return Ok(BudgetMutationReply::Overflow);
                };
                let Some(monthly_inference_ceiling) = budget_state
                    .month_used
                    .inference
                    .checked_add(mutation.credits.inference)
                else {
                    return Ok(BudgetMutationReply::Overflow);
                };
                if monthly_cpu_ceiling > i64::MAX as u64
                    || monthly_inference_ceiling > i64::MAX as u64
                {
                    return Ok(BudgetMutationReply::Overflow);
                }
                stored.budget_month_start_day = current_month_start_day;
                stored.monthly_ceiling = Credits {
                    cpu: monthly_cpu_ceiling,
                    inference: monthly_inference_ceiling,
                };
                stored.last_set = mutation.credits;
            }
            BudgetOperation::IncreaseCurrent => {
                if stored.budget_month_start_day != current_month_start_day {
                    return Ok(BudgetMutationReply::CurrentMonthNotConfigured);
                }
                let Some(monthly_ceiling) = stored.monthly_ceiling.checked_add(mutation.credits)
                else {
                    return Ok(BudgetMutationReply::Overflow);
                };
                let Some(last_set) = stored.last_set.checked_add(mutation.credits) else {
                    return Ok(BudgetMutationReply::Overflow);
                };
                if monthly_ceiling.cpu > i64::MAX as u64
                    || monthly_ceiling.inference > i64::MAX as u64
                    || last_set.cpu > i64::MAX as u64
                    || last_set.inference > i64::MAX as u64
                {
                    return Ok(BudgetMutationReply::Overflow);
                }
                stored.monthly_ceiling = monthly_ceiling;
                stored.last_set = last_set;
            }
        }

        stored.updated = sunix_time(unix_seconds)?;
        self.store
            .upsert_budget(stored)
            .await
            .context("failed to persist company credit budget")?;
        budget_state.stored = stored;
        // The figures a day or month block was decided on just changed: judge the next request again.
        self.blocks.clear_funds(mutation.company_id);
        info!(
            company_id = mutation.company_id,
            operation = ?mutation.operation,
            cpu = mutation.credits.cpu,
            inference = mutation.credits.inference,
            "company credit budget mutated"
        );
        Ok(BudgetMutationReply::Ok)
    }

    async fn ensure_budget(
        &self,
        shard: &mut ShardState,
        company_id: i32,
        unix_seconds: i64,
    ) -> Result<()> {
        if shard.budgets.contains_key(&company_id) {
            return Ok(());
        }
        let current_month_start_day = time_frame::month_start_day(unix_seconds)?;
        let current_day_period = time_frame::local_unix_day(unix_seconds)?;
        let row = self
            .store
            .load_budget(company_id)
            .await
            .context("failed to initialize company credit budget")?
            .unwrap_or_default();
        let stored = StoredBudget {
            company_id,
            ..row.budget
        };
        // A counter whose stored period is not the current one describes a window this process has
        // not touched, which is the same as unused — the row is only rewritten when something is
        // charged, so a quiet day or month leaves yesterday's figure sitting there.
        let day_extra_used = (i64::from(row.extra.day_period) == current_day_period)
            .then_some(row.extra.day_cpu)
            .unwrap_or(0);
        let month_extra_used = (row.extra.month_start_day == current_month_start_day)
            .then_some(row.extra.month_cpu)
            .unwrap_or(0);
        let first_daily_time_frame =
            i32::try_from(time_frame::DAILY_PREFIX + i64::from(current_month_start_day))
                .context("monthly daily time frame does not fit int32")?;
        let current_daily_time_frame = time_frame::daily(unix_seconds)?;
        let monthly_rows = self
            .store
            .load_range(
                company_id,
                COMPANY_AGGREGATE_USER_ID,
                first_daily_time_frame,
                current_daily_time_frame,
            )
            .await
            .context("failed to initialize monthly company usage")?;
        let mut month_used = Credits::default();
        for row in monthly_rows {
            let routes = decode(&row.used_credits)
                .with_context(|| format!("corrupt usage blob in time frame {}", row.time_frame))?;
            month_used = month_used
                .checked_add(sum(&routes)?)
                .ok_or_else(|| anyhow!("recovered monthly usage overflowed uint64"))?;
        }
        // The usage rows just summed include whatever the extra pool paid for, because a request
        // served from the pool is still a request the platform served and still lands in them. The
        // live counter excludes it, so without this the entitlement would shrink by that much on
        // every restart. Saturating rather than checked: the two figures come from different writes
        // and a lost usage-row flush must not turn into a hard error on the next charge.
        month_used.cpu = month_used.cpu.saturating_sub(month_extra_used);
        shard.budgets.insert(
            company_id,
            CompanyBudgetState {
                stored,
                usage_month_start_day: current_month_start_day,
                month_used,
                extra_day_period: current_day_period,
                day_extra_used,
                month_extra_used,
                // Recovered counters are already durable: they were summed from flushed usage rows,
                // so they must not be rewritten until something is charged against them.
                version: 0,
                flushed_version: 0,
            },
        );
        debug!(
            company_id,
            month_start_day = current_month_start_day,
            month_cpu = month_used.cpu,
            month_inference = month_used.inference,
            day_extra_used,
            month_extra_used,
            "initialized company credit budget"
        );
        Ok(())
    }

    async fn ensure_platform_usage(
        &self,
        platform_usage: &mut HashMap<UsageKey, UsageRecord>,
        unix_seconds: i64,
    ) -> Result<()> {
        let key = platform_usage_key(unix_seconds)?;
        if platform_usage.contains_key(&key) {
            return Ok(());
        }

        let stored_row = self
            .store
            .load_exact(key)
            .await
            .context("failed to initialize platform usage")?;
        let routes = decode_optional(
            stored_row
                .as_ref()
                .map(|stored_usage| stored_usage.used_credits.as_slice()),
        )?;
        merge_loaded(platform_usage, key, routes);
        debug!(time_frame = key.time_frame, "initialized platform usage");
        Ok(())
    }

    /// Loads a user's grants into the shard on a miss or past the TTL.
    ///
    /// The store read happens while holding the shard mutex, which is head-of-line blocking for
    /// other callers in the same shard. That is worth saying out loud, but it is exactly what
    /// `ensure_subject` already does for the daily and long-window usage rows: this adds a third awaited
    /// read to a path that already had two. `server.rs` spawns each charge onto its own task
    /// specifically so none of them block the frame reader.
    async fn ensure_access(
        &self,
        shard: &mut ShardState,
        company_id: i32,
        user_id: i32,
        unix_seconds: i64,
    ) -> Result<()> {
        if let Some(cached) = shard.access.get(&(company_id, user_id))
            && cached.is_fresh(unix_seconds, self.access_cache_seconds)
        {
            return Ok(());
        }
        let row = self
            .store
            .load_user_access(company_id, user_id)
            .await
            .context("failed to load user access grants")?;
        // A miss is cached like a hit, or a token naming a deleted user would re-read the store on
        // every request it sends.
        let state = UserAccessState::from_row(row, unix_seconds)?;
        shard.access.insert((company_id, user_id), state);
        Ok(())
    }

    /// Drops one user's cached grants so the next request re-reads them.
    ///
    /// This is what makes the TTL a backstop rather than the mechanism: a grants push calls it for
    /// every user it stores, so a revoked access stops working immediately instead of at the end of
    /// the window.
    async fn drop_cached_access(&self, company_id: i32, user_id: i32) {
        let shard_index = company_id as usize % self.shards.len();
        let mut shard = self.shards[shard_index].lock().await;
        shard.access.remove(&(company_id, user_id));
    }

    async fn ensure_subject(
        &self,
        shard: &mut ShardState,
        company_id: i32,
        user_id: i32,
        limits: ScopeLimits,
        unix_seconds: i64,
        now: Instant,
        day_extra_cpu_from_pool: u64,
    ) -> Result<()> {
        if shard.subjects.contains_key(&(company_id, user_id)) {
            return Ok(());
        }

        let daily_time_frame = time_frame::daily(unix_seconds)?;
        let daily_key = UsageKey {
            company_id,
            user_id,
            time_frame: daily_time_frame,
        };
        let daily_row = self
            .store
            .load_exact(daily_key)
            .await
            .context("failed to initialize daily usage")?;
        let daily_routes =
            decode_optional(daily_row.as_ref().map(|row| row.used_credits.as_slice()))?;
        merge_loaded(&mut shard.usage, daily_key, daily_routes.clone());

        let (long_start, long_end) =
            time_frame::window_five_minute_range(unix_seconds, self.policy.windows.long_seconds())?;
        let long_rows = self
            .store
            .load_range(company_id, user_id, long_start, long_end)
            .await
            .context("failed to initialize long-window usage")?;
        let mut long_used = Credits::default();
        for row in long_rows {
            let routes = decode(&row.used_credits)
                .with_context(|| format!("corrupt usage blob in time frame {}", row.time_frame))?;
            long_used = long_used
                .checked_add(sum(&routes)?)
                .ok_or_else(|| anyhow!("recovered long-window usage overflowed uint64"))?;
            merge_loaded(
                &mut shard.usage,
                UsageKey {
                    company_id,
                    user_id,
                    time_frame: row.time_frame,
                },
                routes,
            );
        }

        let mut day_used = sum(&daily_routes)?;
        // The daily row counts every request the platform served, including the ones the extra pool
        // paid for, while the live counter excludes them on purpose — a pool-paid charge is granted
        // outside the entitlement. Without this correction the company loses that much of its daily
        // allowance on every restart. It is the same subtraction `ensure_budget` applies to the
        // monthly figure, and saturating for the same reason: the two numbers come from different
        // writes, and a lost flush must not turn into a hard error on the next charge.
        //
        // The pool is a company allowance with no per-user split, so a multi-user company credits
        // the whole correction to each of its users. That errs toward the tenant, which is the right
        // side to err on for credit the platform gave away for free.
        day_used.cpu = day_used.cpu.saturating_sub(day_extra_cpu_from_pool);
        shard.subjects.insert(
            (company_id, user_id),
            SubjectState::recovered(
                limits,
                self.policy.windows,
                unix_seconds,
                time_frame::local_unix_day(unix_seconds)?,
                now,
                long_used,
                day_used,
            ),
        );
        debug!(
            company_id,
            user_id,
            long_cpu = long_used.cpu,
            long_inference = long_used.inference,
            day_cpu = day_used.cpu,
            day_inference = day_used.inference,
            "initialized quota state"
        );
        Ok(())
    }

    pub async fn flush_dirty(&self) -> usize {
        let _flushing = self.flush_lock.lock().await;
        let mut snapshots = Vec::new();
        for shard in &self.shards {
            let shard = shard.lock().await;
            snapshots.extend(
                shard
                    .usage
                    .iter()
                    .filter_map(|(&key, record)| record.snapshot(key)),
            );
        }
        {
            let platform_usage = self.platform_usage.lock().await;
            snapshots.extend(
                platform_usage
                    .iter()
                    .filter_map(|(&key, record)| record.snapshot(key)),
            );
        }
        // No early return when nothing is dirty: a company that is only being refused still has
        // refusal counters to write, and the budget counters roll with the day.
        if snapshots.is_empty() {
            debug!("no usage record is dirty");
        } else {
            info!(dirty_records = snapshots.len(), "starting usage flush");
        }
        let mut written = 0;
        for snapshot in snapshots {
            match self.flush_snapshot(&snapshot).await {
                Ok(base) => {
                    self.mark_flushed(&snapshot, base.as_ref()).await;
                    written += 1;
                }
                Err(flush_error) => {
                    error!(
                        company_id = snapshot.key.company_id,
                        user_id = snapshot.key.user_id,
                        time_frame = snapshot.key.time_frame,
                        error = %flush_error,
                        "usage snapshot remains dirty after failed flush"
                    );
                }
            }
        }
        if let Err(cleanup_error) = self.prune_clean_usage().await {
            error!(error = %cleanup_error, "failed to prune clean historical usage from memory");
        }
        written += self.flush_dirty_budget_usage().await;
        written += self.flush_rejections().await;
        if written > 0 {
            // One durable step for the whole flush rather than one per row.
            if let Err(persist_error) = self.store.flush_completed().await {
                error!(error = %persist_error, "usage flush written but not made durable");
            }
            info!(written, "usage flush completed");
        }
        written
    }

    /// Stores pushed grants, then drops those users' cached ones, so the next charge reads what was
    /// just stored. Stored first: a cache dropped before the write could reload the old grants.
    pub async fn put_grants(&self, entries: Vec<crate::store::grants::GrantEntry>) -> Result<()> {
        let users: Vec<(i32, i32)> = entries
            .iter()
            .map(|entry| (entry.company_id, entry.user_id))
            .collect();
        self.store.put_grants(entries).await?;
        for (company_id, user_id) in users {
            self.drop_cached_access(company_id, user_id).await;
        }
        Ok(())
    }

    /// Answers a report query (opcode `0x09`) from the store. Reports read what was flushed, so
    /// they lag the limiter by at most one flush interval.
    pub async fn report(&self, query: crate::store::query::ReportQuery) -> Result<Vec<u8>> {
        self.store.report(query).await
    }

    /// Adds the refusals counted since the last flush to the company rows. A failed write puts its
    /// counts back for the next flush; only a write that succeeded but whose reply was lost can count
    /// twice, an acceptable error for a counter.
    async fn flush_rejections(&self) -> usize {
        let unix_seconds = match current_unix_seconds() {
            Ok(unix_seconds) => unix_seconds,
            Err(clock_error) => {
                error!(error = %clock_error, "rejection flush skipped: unreadable clock");
                return 0;
            }
        };
        let pending = self.blocks.take_pending(unix_seconds, Instant::now());
        let mut written = 0;
        for (company_id, time_frame, rejections) in pending {
            match self
                .store
                .add_rejections(company_id, time_frame, rejections)
                .await
            {
                Ok(()) => written += 1,
                Err(flush_error) => {
                    error!(
                        company_id,
                        time_frame,
                        error = %flush_error,
                        "rejection counters remain pending after failed flush"
                    );
                    self.blocks.restore(company_id, time_frame, rejections);
                }
            }
        }
        written
    }

    /// Publishes the counters admission is decided on — the company's daily and month-to-date usage —
    /// next to the entitlement they are compared against, so a reader gets the limiter's own figures
    /// instead of re-summing the usage rows the way `ensure_budget` has to on a cold miss.
    async fn flush_dirty_budget_usage(&self) -> usize {
        let unix_seconds = match current_unix_seconds() {
            Ok(unix_seconds) => unix_seconds,
            Err(clock_error) => {
                error!(error = %clock_error, "budget usage flush skipped: unreadable clock");
                return 0;
            }
        };
        let day_period = match time_frame::local_unix_day(unix_seconds) {
            Ok(day_period) => day_period,
            Err(day_error) => {
                error!(error = %day_error, "budget usage flush skipped: unresolved business day");
                return 0;
            }
        };

        let mut snapshots = Vec::new();
        for shard in &self.shards {
            let shard = shard.lock().await;
            for (&company_id, budget) in &shard.budgets {
                // The day the snapshot carries is the subject's own, not the wall clock's: a subject
                // whose day rolled over keeps reporting the previous day's counter until its next
                // charge resets it, and labelling that figure with today would overstate today.
                let (day_used, day_period) = shard
                    .subjects
                    .get(&(company_id, COMPANY_AGGREGATE_USER_ID))
                    .map(|subject| (subject.day_used, subject.day_period))
                    .unwrap_or((Credits::default(), day_period));
                match budget.usage_snapshot(company_id, day_used, day_period, unix_seconds) {
                    Ok(Some(snapshot)) => snapshots.push(snapshot),
                    Ok(None) => {}
                    Err(snapshot_error) => error!(
                        company_id,
                        error = %snapshot_error,
                        "company budget usage snapshot could not be built"
                    ),
                }
            }
        }
        if snapshots.is_empty() {
            debug!("budget usage flush skipped because no company was charged");
            return 0;
        }

        let mut written = 0;
        for (snapshot, version) in snapshots {
            if let Err(flush_error) = self.store.upsert_budget_usage(snapshot).await {
                error!(
                    company_id = snapshot.company_id,
                    error = %flush_error,
                    "company budget usage remains dirty after failed flush"
                );
                continue;
            }
            let shard_index = snapshot.company_id as usize % self.shards.len();
            let mut shard = self.shards[shard_index].lock().await;
            if let Some(budget) = shard.budgets.get_mut(&snapshot.company_id) {
                budget.mark_usage_flushed(version);
            }
            written += 1;
            debug!(
                company_id = snapshot.company_id,
                day_period = snapshot.day_period,
                day_cpu = snapshot.day_used.cpu,
                month_start_day = snapshot.month_start_day,
                month_cpu = snapshot.month_used.cpu,
                "company budget usage flushed"
            );
        }
        written
    }

    /// Writes one row. For an unseeded row the snapshot holds only what was charged since it was
    /// created, so the stored row is read and added first, and returned so `mark_flushed` can fold it
    /// into the in-memory record.
    async fn flush_snapshot(&self, snapshot: &UsageSnapshot) -> Result<Option<RoutedCredits>> {
        if !snapshot.base_pending {
            let encoded = encode(&snapshot.routes).context("failed to encode usage snapshot")?;
            self.store.upsert(snapshot.key, encoded).await?;
            return Ok(None);
        }
        let stored = self
            .store
            .load_exact(snapshot.key)
            .await
            .context("failed to read the stored row of an unseeded usage record")?;
        let base = decode_optional(stored.as_ref().map(|row| row.used_credits.as_slice()))?;
        let mut total = snapshot.routes.clone();
        add_routes(&mut total, &base)?;
        let encoded = encode(&total).context("failed to encode usage snapshot")?;
        self.store.upsert(snapshot.key, encoded).await?;
        Ok(Some(base))
    }

    async fn mark_flushed(&self, snapshot: &UsageSnapshot, base: Option<&RoutedCredits>) {
        if snapshot.key.company_id == PLATFORM_AGGREGATE_COMPANY_ID {
            let mut platform_usage = self.platform_usage.lock().await;
            if let Some(record) = platform_usage.get_mut(&snapshot.key) {
                record.mark_flushed(snapshot.version);
            }
            return;
        }

        let shard_index = snapshot.key.company_id as usize % self.shards.len();
        let mut shard = self.shards[shard_index].lock().await;
        if let Some(record) = shard.usage.get_mut(&snapshot.key) {
            // The base goes in even when a charge landed during the write and the record stays
            // dirty: the store now holds base + snapshot, so the record must hold base + everything.
            if let Some(base) = base
                && let Err(base_error) = record.apply_base(base)
            {
                error!(
                    company_id = snapshot.key.company_id,
                    user_id = snapshot.key.user_id,
                    time_frame = snapshot.key.time_frame,
                    error = %base_error,
                    "stored usage could not be folded into memory"
                );
                return;
            }
            record.mark_flushed(snapshot.version);
        }
    }

    async fn prune_clean_usage(&self) -> Result<()> {
        let unix_seconds = current_unix_seconds()?;
        let current_five_minute = time_frame::five_minute(unix_seconds)?;
        let current_day = time_frame::daily(unix_seconds)?;
        for shard in &self.shards {
            let mut shard = shard.lock().await;
            shard.usage.retain(|key, record| {
                !record.is_clean()
                    || key.time_frame == current_five_minute
                    || key.time_frame == current_day
            });
        }
        let mut platform_usage = self.platform_usage.lock().await;
        platform_usage
            .retain(|key, record| !record.is_clean() || key.time_frame == current_five_minute);
        Ok(())
    }
}

fn decode_optional(encoded: Option<&[u8]>) -> Result<RoutedCredits> {
    encoded
        .map(decode)
        .transpose()
        .map(|value| value.unwrap_or_default())
        .map_err(Into::into)
}

/// `user_rows_unseeded`: the user's rows were not loaded before this charge (the user limit is off),
/// so a missing one is created unseeded and the flush adds the stored row in. Otherwise a missing row
/// really is a new one, because `ensure_subject` already loaded whatever was stored.
fn increment_usage(
    records: &mut HashMap<UsageKey, UsageRecord>,
    request: Request,
    unix_seconds: i64,
    user_rows_unseeded: bool,
) -> Result<()> {
    let five_minute = time_frame::five_minute(unix_seconds)?;
    let daily = time_frame::daily(unix_seconds)?;
    for user_id in [request.user_id, COMPANY_AGGREGATE_USER_ID] {
        let unseeded = user_rows_unseeded && user_id != COMPANY_AGGREGATE_USER_ID;
        for time_frame in [five_minute, daily] {
            let key = UsageKey {
                company_id: request.company_id,
                user_id,
                time_frame,
            };
            records
                .entry(key)
                .or_insert_with(|| {
                    if unseeded {
                        UsageRecord::unseeded()
                    } else {
                        UsageRecord::loaded(RoutedCredits::new())
                    }
                })
                .increment(request.route_id, request.credits)?;
        }
    }
    Ok(())
}

fn platform_usage_key(unix_seconds: i64) -> Result<UsageKey> {
    Ok(UsageKey {
        company_id: PLATFORM_AGGREGATE_COMPANY_ID,
        user_id: COMPANY_AGGREGATE_USER_ID,
        time_frame: time_frame::five_minute(unix_seconds)?,
    })
}

fn increment_platform_usage(
    records: &mut HashMap<UsageKey, UsageRecord>,
    request: Request,
    unix_seconds: i64,
) -> Result<()> {
    let key = platform_usage_key(unix_seconds)?;
    records
        .get_mut(&key)
        .expect("platform usage initialized")
        .increment(request.route_id, request.credits)
}

fn current_unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("Unix time does not fit in int64")
}

fn sunix_time(unix_seconds: i64) -> Result<i32> {
    i32::try_from((unix_seconds - 1_000_000_000) / 2)
        .context("SUnix timestamp does not fit in int32")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::limiter::access::{AccessVerdict, MAX_REQUIRED_ACCESS};
    use crate::limiter::block::Rejections;
    use crate::limiter::storage::{
        StoredBudget, StoredBudgetRow, StoredBudgetUsage, StoredExtraUsage, StoredUsage,
        StoredUserAccess,
    };

    /// Most tests in this module drive the credit path, and a credit frame asks for no
    /// authorization — so an allowed decision carries the empty verdict. Named rather than spelled
    /// out at each of two dozen call sites.
    fn allowed() -> Decision {
        Decision::Allowed(AccessVerdict::default())
    }

    /// An allowed decision for a frame that *did* ask, naming which required slots were granted.
    /// None of these fixtures grant a sub-access, so the tail is always empty.
    fn allowed_slots(granted_mask: u8) -> Decision {
        Decision::Allowed(AccessVerdict {
            granted_mask,
            has_subs_mask: 0,
            sub_bytes: Vec::new(),
        })
    }

    impl Decision {
        /// The credit violation this decision carries, or a panic naming what it carried instead.
        fn violation(self) -> LimitViolation {
            match self {
                Decision::CreditViolation(violation) => violation,
                other => panic!("expected a credit violation, got {other:?}"),
            }
        }
    }

    #[derive(Default)]
    struct MemoryStore {
        rows: StdMutex<HashMap<UsageKey, Vec<u8>>>,
        budgets: StdMutex<HashMap<i32, StoredBudget>>,
        /// Extra-pool counters as if a previous process had already flushed them, so a test can
        /// exercise the cold-start path without going through a charge first.
        stored_extra: StdMutex<HashMap<i32, StoredExtraUsage>>,
        /// What the flush published per company, plus how many times it published it: a flush that
        /// writes an unchanged row is as wrong as one that skips a changed one.
        budget_usages: StdMutex<HashMap<i32, (StoredBudgetUsage, u32)>>,
        users: StdMutex<HashMap<(i32, i32), StoredUserAccess>>,
        /// Counts the point reads, so a test can prove the cache is actually a cache.
        user_reads: AtomicU64,
        /// The rejection counters as added up by every flush, per (company, time frame).
        rejections: StdMutex<HashMap<(i32, i32), Rejections>>,
    }

    impl MemoryStore {
        fn put_budget(&self, budget: StoredBudget) {
            self.budgets
                .lock()
                .unwrap()
                .insert(budget.company_id, budget);
        }

        fn put_stored_extra(&self, company_id: i32, extra: StoredExtraUsage) {
            self.stored_extra.lock().unwrap().insert(company_id, extra);
        }

        fn budget_usage(&self, company_id: i32) -> Option<(StoredBudgetUsage, u32)> {
            self.budget_usages.lock().unwrap().get(&company_id).copied()
        }

        fn put_user(&self, company_id: i32, user_id: i32, grants: &[u16], status: i8) {
            self.users.lock().unwrap().insert(
                (company_id, user_id),
                StoredUserAccess {
                    // Big-endian, matching backend/core/accesos-blob.go. These fixtures grant no
                    // sub-accesses, so every one of them belongs in the plain column.
                    grants_blob: grants.iter().flat_map(|g| g.to_be_bytes()).collect(),
                    sub_grants_blob: Vec::new(),
                    status,
                },
            );
        }
    }

    #[async_trait]
    impl LimiterStore for MemoryStore {
        async fn load_exact(&self, key: UsageKey) -> Result<Option<StoredUsage>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .map(|used_credits| StoredUsage {
                    time_frame: key.time_frame,
                    used_credits,
                }))
        }

        async fn load_range(
            &self,
            company_id: i32,
            user_id: i32,
            start_time_frame: i32,
            end_time_frame: i32,
        ) -> Result<Vec<StoredUsage>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    key.company_id == company_id
                        && key.user_id == user_id
                        && (start_time_frame..=end_time_frame).contains(&key.time_frame)
                })
                .map(|(key, blob)| StoredUsage {
                    time_frame: key.time_frame,
                    used_credits: blob.clone(),
                })
                .collect())
        }

        async fn upsert(&self, key: UsageKey, used_credits: Vec<u8>) -> Result<()> {
            self.rows.lock().unwrap().insert(key, used_credits);
            Ok(())
        }

        async fn load_budget(&self, company_id: i32) -> Result<Option<StoredBudgetRow>> {
            let extra = self
                .stored_extra
                .lock()
                .unwrap()
                .get(&company_id)
                .copied()
                .unwrap_or_default();
            if let Some(budget) = self.budgets.lock().unwrap().get(&company_id).copied() {
                return Ok(Some(StoredBudgetRow { budget, extra }));
            }
            // Legacy limiter tests all use this fixed instant and need a non-binding entitlement.
            let budget = StoredBudget {
                company_id,
                daily: Credits {
                    cpu: i64::MAX as u64,
                    inference: i64::MAX as u64,
                },
                budget_month_start_day: time_frame::month_start_day(1_800_000_000)?,
                monthly_ceiling: Credits {
                    cpu: i64::MAX as u64,
                    inference: i64::MAX as u64,
                },
                last_set: Credits {
                    cpu: i64::MAX as u64,
                    inference: i64::MAX as u64,
                },
                updated: 0,
            };
            Ok(Some(StoredBudgetRow { budget, extra }))
        }

        async fn upsert_budget(&self, budget: StoredBudget) -> Result<()> {
            self.budgets
                .lock()
                .unwrap()
                .insert(budget.company_id, budget);
            Ok(())
        }

        async fn upsert_budget_usage(&self, usage: StoredBudgetUsage) -> Result<()> {
            let mut usages = self.budget_usages.lock().unwrap();
            let writes = usages.get(&usage.company_id).map_or(0, |(_, w)| *w);
            usages.insert(usage.company_id, (usage, writes + 1));
            Ok(())
        }

        async fn add_rejections(
            &self,
            company_id: i32,
            time_frame: i32,
            rejections: Rejections,
        ) -> Result<()> {
            self.rejections
                .lock()
                .unwrap()
                .entry((company_id, time_frame))
                .or_default()
                .add(rejections);
            Ok(())
        }

        async fn load_user_access(
            &self,
            company_id: i32,
            user_id: i32,
        ) -> Result<Option<StoredUserAccess>> {
            self.user_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .users
                .lock()
                .unwrap()
                .get(&(company_id, user_id))
                .cloned())
        }
    }

    fn test_policy(limit: u64) -> LimitPolicy {
        let limits = ScopeLimits {
            cpu: CreditLimits {
                short: limit,
                long: limit,
            },
            inference: CreditLimits {
                short: limit,
                long: limit,
            },
        };
        LimitPolicy {
            company: limits,
            user: limits,
            company_extra_daily_cpu: 0,
            // Half, stated here rather than inherited from config: the fixtures below are built on a
            // user reaching its daily gate before the company reaches its own, and that only happens
            // below 100.
            user_daily_share_pct: 50,
            disable_user_limit: false,
            windows: Windows::default(),
        }
    }

    /// The same policy with the extra daily pool switched on. Separate helper rather than a
    /// parameter on `test_policy` so every existing test keeps stating "no pool" by construction.
    fn test_policy_with_extra(limit: u64, extra: u64) -> LimitPolicy {
        LimitPolicy {
            company_extra_daily_cpu: extra,
            ..test_policy(limit)
        }
    }

    fn stored_budget(company_id: i32, unix_seconds: i64, daily: u64, monthly: u64) -> StoredBudget {
        StoredBudget {
            company_id,
            daily: Credits {
                cpu: daily,
                inference: daily,
            },
            budget_month_start_day: time_frame::month_start_day(unix_seconds).unwrap(),
            monthly_ceiling: Credits {
                cpu: monthly,
                inference: monthly,
            },
            // The fixtures grant the ceiling from a zero-usage month, so both figures coincide.
            last_set: Credits {
                cpu: monthly,
                inference: monthly,
            },
            updated: 0,
        }
    }

    const EXTRA_CLOCK: i64 = 1_800_000_000;

    /// An entitlement of four credits a day, which is what makes a single two-credit read fit
    /// exactly once: the user daily gate is half the company's, so the second read is refused by
    /// `Scope::User` before the company has spent its own allowance.
    ///
    /// That is the case worth building the fixtures on rather than an artefact of them — it is the
    /// single-user company, which is most of them, and the reason the pool has no per-user share.
    const EXTRA_DAILY: u64 = 4;

    fn read_request(cpu: u64, extra_credits_allowed: bool) -> Request {
        Request {
            company_id: 7,
            user_id: 42,
            route_id: 34,
            credits: Credits { cpu, inference: 0 },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed,
        }
    }

    async fn limiter_with_extra_pool(pool: u64, daily: u64) -> (Arc<MemoryStore>, RateLimiter) {
        let store = Arc::new(MemoryStore::default());
        store.put_budget(stored_budget(7, EXTRA_CLOCK, daily, 1_000_000));
        let limiter = RateLimiter::new(1, test_policy_with_extra(1_000, pool), store.clone(), 600);
        (store, limiter)
    }

    /// The whole feature in one assertion: the entitlement refuses, the mark is present, the read is
    /// served anyway. And the same frame without the mark is refused, which is what makes this a
    /// property of the request rather than of the company.
    #[tokio::test]
    async fn a_marked_read_is_served_from_the_extra_pool_once_the_daily_gate_refuses() {
        let (_store, limiter) = limiter_with_extra_pool(50, EXTRA_DAILY).await;
        // Spends what the user gate allows, exactly.
        assert_eq!(
            limiter
                .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
                .await
                .unwrap(),
            allowed()
        );

        let refused = limiter
            .admit_at(read_request(2, false), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        assert!(
            matches!(refused, Decision::CreditViolation(_)),
            "an unmarked frame reached the pool: {refused:?}"
        );
        assert_eq!(
            limiter
                .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
    }

    /// The pool is a ceiling, not a bypass. Once it is gone the original refusal comes back
    /// unchanged, so the client sees the same 429 it would have seen without the feature.
    #[tokio::test]
    async fn an_exhausted_pool_refuses_again() {
        let (_store, limiter) = limiter_with_extra_pool(4, EXTRA_DAILY).await;
        for _ in 0..3 {
            assert_eq!(
                limiter
                    .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
                    .await
                    .unwrap(),
                allowed()
            );
        }
        // Two of entitlement plus four of pool are spent; the pool cannot cover a fourth read.
        let refused = limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        assert!(
            matches!(refused, Decision::CreditViolation(_)),
            "the pool paid past its ceiling: {refused:?}"
        );
    }

    /// A pool of zero — the default — has to leave the daemon behaving exactly as it did before the
    /// feature existed, mark or no mark.
    #[tokio::test]
    async fn a_pool_of_zero_disables_the_feature() {
        let (_store, limiter) = limiter_with_extra_pool(0, EXTRA_DAILY).await;
        limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        let refused = limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        assert!(matches!(refused, Decision::CreditViolation(_)));
    }

    /// The burst gates protect the machine, and a flood of reads is exactly what they protect it
    /// from. A tenant in read-only mode still queues behind them.
    #[tokio::test]
    async fn the_extra_pool_never_relaxes_a_burst_gate() {
        let store = Arc::new(MemoryStore::default());
        store.put_budget(stored_budget(7, EXTRA_CLOCK, 1_000_000, 1_000_000));
        // Ten credits per ten seconds, and a pool far larger than that.
        let limiter = RateLimiter::new(1, test_policy_with_extra(10, 10_000), store.clone(), 600);
        let now = Instant::now();
        assert_eq!(
            limiter
                .admit_at(read_request(10, true), EXTRA_CLOCK, now)
                .await
                .unwrap(),
            allowed()
        );
        let refused = limiter
            .admit_at(read_request(10, true), EXTRA_CLOCK, now)
            .await
            .unwrap();
        match refused {
            Decision::CreditViolation(violation) => {
                assert_eq!(violation.window, Window::Short);
            }
            other => panic!("a burst gate was relaxed by the extra pool: {other:?}"),
        }
    }

    /// Extra spending must also consume burst tokens, or a company in read-only mode would have
    /// unlimited burst — the counters it stops touching are the entitlement ones, not the rate ones.
    #[tokio::test]
    async fn extra_spending_still_consumes_burst_and_hourly_credits() {
        let (_store, limiter) = limiter_with_extra_pool(1_000, EXTRA_DAILY).await;
        let now = Instant::now();
        limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, now)
            .await
            .unwrap();
        limiter
            .admit_at(read_request(900, true), EXTRA_CLOCK, now)
            .await
            .unwrap();
        // 902 of the 1000 hourly credits are gone, 2 from entitlement and 900 from the pool.
        let refused = limiter
            .admit_at(read_request(200, true), EXTRA_CLOCK, now)
            .await
            .unwrap();
        assert!(
            matches!(refused, Decision::CreditViolation(_)),
            "the hourly ceiling did not count extra spending: {refused:?}"
        );
    }

    /// The accounting rule, asserted on the flushed row: extra spending is counted apart, so the
    /// daily and monthly figures a write is judged against do not move.
    #[tokio::test]
    async fn extra_spending_is_counted_apart_from_the_quota_it_bypassed() {
        let (store, limiter) = limiter_with_extra_pool(50, EXTRA_DAILY).await;
        limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        limiter
            .admit_at(read_request(30, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        limiter.flush_dirty().await;

        let (usage, _) = store.budget_usage(7).expect("budget usage was flushed");
        assert_eq!(usage.day_used.cpu, 2, "the pool moved the daily meter");
        assert_eq!(
            usage.month_used.cpu, 2,
            "the pool spent the monthly ceiling"
        );
        assert_eq!(usage.day_extra_cpu, 30);
        assert_eq!(usage.month_extra_cpu, 30);
    }

    /// The pool is CPU. An inference credit has nothing here that could authorize it, so a marked
    /// frame asking for one is refused rather than partially relaxed.
    #[tokio::test]
    async fn a_marked_frame_asking_for_inference_is_not_relaxed() {
        let (_store, limiter) = limiter_with_extra_pool(1_000, 2).await;
        let mut request = read_request(1, true);
        request.credits.inference = 1;
        limiter
            .admit_at(request, EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        let refused = limiter
            .admit_at(request, EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        assert!(
            matches!(refused, Decision::CreditViolation(_)),
            "an inference credit was paid from the CPU pool: {refused:?}"
        );
    }

    /// A read that fits inside the entitlement must be charged against it. If the pool were
    /// consulted first it would be spent on tenants who never needed it.
    #[tokio::test]
    async fn a_read_that_fits_the_entitlement_does_not_touch_the_pool() {
        let (store, limiter) = limiter_with_extra_pool(50, 1_000).await;
        limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        limiter.flush_dirty().await;
        let (usage, _) = store.budget_usage(7).unwrap();
        assert_eq!(usage.day_extra_cpu, 0);
        assert_eq!(usage.day_used.cpu, 2);
    }

    /// The pool is bounded by the local business day, like every other daily figure here. On the
    /// raw UTC division it would reset at 19:00 local time.
    #[tokio::test]
    async fn the_pool_resets_on_the_local_business_day() {
        let (_store, limiter) = limiter_with_extra_pool(2, 0).await;
        assert_eq!(
            limiter
                .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        let refused = limiter
            .admit_at(read_request(2, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        assert!(matches!(refused, Decision::CreditViolation(_)));

        let next_day = EXTRA_CLOCK + 86_400;
        assert_ne!(
            time_frame::local_unix_day(EXTRA_CLOCK).unwrap(),
            time_frame::local_unix_day(next_day).unwrap()
        );
        assert_eq!(
            limiter
                .admit_at(read_request(2, true), next_day, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
    }

    /// Cold start. The pool must survive a restart inside the same day, or a restart would hand out
    /// a fresh allowance; and `month_used`, which is rebuilt by summing usage rows that include what
    /// the pool paid for, must come back without that spending folded into the entitlement.
    #[tokio::test]
    async fn a_restart_recovers_the_pool_and_does_not_lose_entitlement_to_it() {
        let store = Arc::new(MemoryStore::default());
        store.put_budget(stored_budget(7, EXTRA_CLOCK, 100, 1_000));
        let day_period = time_frame::local_unix_day(EXTRA_CLOCK).unwrap();
        store.put_stored_extra(
            7,
            StoredExtraUsage {
                day_period: i16::try_from(day_period).unwrap(),
                day_cpu: 40,
                month_start_day: time_frame::month_start_day(EXTRA_CLOCK).unwrap(),
                month_cpu: 40,
            },
        );
        // The usage rows a previous process flushed: 60 of ordinary usage plus the 40 the pool paid
        // for, because the pool's requests were served and land in these rows like any other.
        let mut routes = RoutedCredits::new();
        routes.insert(
            34,
            Credits {
                cpu: 100,
                inference: 0,
            },
        );
        store.rows.lock().unwrap().insert(
            UsageKey {
                company_id: 7,
                user_id: COMPANY_AGGREGATE_USER_ID,
                time_frame: time_frame::daily(EXTRA_CLOCK).unwrap(),
            },
            encode(&routes).unwrap(),
        );

        let limiter = RateLimiter::new(1, test_policy_with_extra(1_000, 50), store.clone(), 600);
        // Forty credits of the hundred-credit day are still unspent — the row says a hundred, but
        // forty of those were the pool's. This has to be served from the entitlement, so the pool
        // must not move.
        assert_eq!(
            limiter
                .admit_at(read_request(40, true), EXTRA_CLOCK, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        limiter.flush_dirty().await;
        let (usage, _) = store.budget_usage(7).unwrap();
        assert_eq!(
            usage.day_extra_cpu, 40,
            "the recovered day charged the pool for credit the company had bought"
        );

        // Only now is the day spent, and ten of the fifty-credit pool are left: this fits and a
        // second one does not.
        assert_eq!(
            limiter
                .admit_at(read_request(10, true), EXTRA_CLOCK, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        let refused = limiter
            .admit_at(read_request(1, true), EXTRA_CLOCK, Instant::now())
            .await
            .unwrap();
        assert!(
            matches!(refused, Decision::CreditViolation(_)),
            "the restart handed out a fresh pool: {refused:?}"
        );

        limiter.flush_dirty().await;
        let (usage, _) = store.budget_usage(7).unwrap();
        // 100 summed from the rows minus the 40 the pool paid for, plus the 40 charged above. Without
        // the correction the company would have lost 40 credits of what it bought to a free
        // allowance, in the month and in the day alike.
        assert_eq!(usage.month_used.cpu, 100);
        assert_eq!(usage.day_extra_cpu, 50);
    }

    #[tokio::test]
    async fn accepted_request_dirties_company_user_and_platform_rows() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, test_policy(100), store.clone(), 600);
        let request = Request {
            company_id: 7,
            user_id: 42,
            route_id: 34,
            credits: Credits {
                cpu: 4,
                inference: 5,
            },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed: false,
        };
        assert_eq!(
            limiter
                .admit_at(request, 1_800_000_000, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        // Five usage rows plus the company's budget usage counters, which the same flush publishes.
        assert_eq!(limiter.flush_dirty().await, 6);
        assert_eq!(store.rows.lock().unwrap().len(), 5);
        let platform_key = platform_usage_key(1_800_000_000).unwrap();
        let platform_routes = decode(
            store
                .rows
                .lock()
                .unwrap()
                .get(&platform_key)
                .expect("platform row persisted"),
        )
        .unwrap();
        assert_eq!(platform_routes.get(&34), Some(&request.credits));
        assert_eq!(limiter.flush_dirty().await, 0);
    }

    #[tokio::test]
    async fn platform_aggregate_is_shared_across_company_shards() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(4, test_policy(100), store.clone(), 600);
        let unix_seconds = 1_800_000_000;

        for company_id in [1, 2] {
            let result = limiter
                .admit_at(
                    Request {
                        company_id,
                        user_id: company_id * 10,
                        route_id: 34,
                        credits: Credits {
                            cpu: 4,
                            inference: 5,
                        },
                        required_access: [0; MAX_REQUIRED_ACCESS],
                        extra_credits_allowed: false,
                    },
                    unix_seconds,
                    Instant::now(),
                )
                .await
                .unwrap();
            assert_eq!(result, allowed());
        }

        limiter.flush_dirty().await;
        let platform_key = platform_usage_key(unix_seconds).unwrap();
        let platform_routes = decode(
            store
                .rows
                .lock()
                .unwrap()
                .get(&platform_key)
                .expect("one shared platform row persisted"),
        )
        .unwrap();
        assert_eq!(
            platform_routes.get(&34),
            Some(&Credits {
                cpu: 8,
                inference: 10
            })
        );
    }

    #[tokio::test]
    async fn platform_aggregate_extends_the_absolute_row_after_restart() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        let platform_key = platform_usage_key(unix_seconds).unwrap();
        store.rows.lock().unwrap().insert(
            platform_key,
            encode(&RoutedCredits::from([(
                34,
                Credits {
                    cpu: 7,
                    inference: 8,
                },
            )]))
            .unwrap(),
        );
        let limiter = RateLimiter::new(1, test_policy(100), store.clone(), 600);

        limiter
            .admit_at(
                Request {
                    company_id: 7,
                    user_id: 42,
                    route_id: 34,
                    credits: Credits {
                        cpu: 4,
                        inference: 5,
                    },
                    required_access: [0; MAX_REQUIRED_ACCESS],
                    extra_credits_allowed: false,
                },
                unix_seconds,
                Instant::now(),
            )
            .await
            .unwrap();
        limiter.flush_dirty().await;

        let platform_routes = decode(
            store
                .rows
                .lock()
                .unwrap()
                .get(&platform_key)
                .expect("platform row persisted"),
        )
        .unwrap();
        assert_eq!(
            platform_routes.get(&34),
            Some(&Credits {
                cpu: 11,
                inference: 13
            })
        );
    }

    #[tokio::test]
    async fn exact_limit_is_allowed_and_next_credit_is_rejected() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, test_policy(10), store.clone(), 600);
        let now = Instant::now();
        let request = Request {
            company_id: 7,
            user_id: 42,
            route_id: 0,
            credits: Credits {
                cpu: 10,
                inference: 0,
            },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed: false,
        };
        assert_eq!(
            limiter.admit_at(request, 1_800_000_000, now).await.unwrap(),
            allowed()
        );
        let violation = limiter
            .admit_at(
                Request {
                    credits: Credits {
                        cpu: 1,
                        inference: 0,
                    },
                    ..request
                },
                1_800_000_000,
                now,
            )
            .await
            .unwrap()
            .violation();
        assert_eq!(violation.scope, Scope::Company);
        assert_eq!(violation.window, Window::Short);
        assert!(violation.cpu);
        // The rejected second request must not create another dirty usage mutation. What it does
        // write is its refusal, counted in the five-minute frame and in the day: 6 + 2.
        assert_eq!(limiter.flush_dirty().await, 8);
        assert_eq!(limiter.flush_dirty().await, 0);
        let counted = Rejections {
            short: 1,
            long: 0,
            no_funds: 0,
        };
        let rejections = store.rejections.lock().unwrap();
        for time_frame in [
            time_frame::five_minute(1_800_000_000).unwrap(),
            time_frame::daily(1_800_000_000).unwrap(),
        ] {
            assert_eq!(rejections.get(&(7, time_frame)), Some(&counted));
        }
    }

    #[tokio::test]
    async fn flush_publishes_the_counters_admission_is_decided_on() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, unix_seconds, 1_000, 5_000));
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        let request = Request {
            company_id: 7,
            user_id: 42,
            route_id: 1,
            credits: Credits {
                cpu: 30,
                inference: 4,
            },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed: false,
        };
        assert_eq!(
            limiter
                .admit_at(request, unix_seconds, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        limiter.flush_dirty().await;

        let (usage, writes) = store.budget_usage(7).expect("budget usage was flushed");
        assert_eq!(writes, 1);
        assert_eq!(
            usage.day_used,
            Credits {
                cpu: 30,
                inference: 4
            }
        );
        assert_eq!(
            usage.month_used,
            Credits {
                cpu: 30,
                inference: 4
            }
        );
        assert_eq!(
            usage.day_period,
            time_frame::local_unix_day(unix_seconds).unwrap() as i16
        );
        assert_eq!(
            usage.month_start_day,
            time_frame::month_start_day(unix_seconds).unwrap()
        );

        // Nothing charged since, so the row must not be rewritten: a re-write would republish the
        // same figures with a newer stamp and make a stale reader look fresh.
        limiter.flush_dirty().await;
        assert_eq!(store.budget_usage(7).unwrap().1, 1);

        assert_eq!(
            limiter
                .admit_at(request, unix_seconds, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        limiter.flush_dirty().await;
        let (usage, writes) = store.budget_usage(7).unwrap();
        assert_eq!(writes, 2);
        assert_eq!(
            usage.month_used,
            Credits {
                cpu: 60,
                inference: 8
            }
        );
    }

    #[tokio::test]
    async fn daily_usage_resets_on_the_local_day_boundary() {
        let store = Arc::new(MemoryStore::default());
        // 2027-01-15 18:00 local (UTC-5), and two hours later — the same business day, but already
        // the next UTC day. On the raw UTC division the counter reset at 19:00 local and the caller
        // could spend its daily cap twice in one business day.
        let evening = 1_800_054_000;
        let after_utc_midnight = evening + 2 * 3_600;
        let next_business_day = evening + 7 * 3_600;
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, evening, 10, 5_000));
        let limiter = RateLimiter::new(1, test_policy(1_000), store, 600);
        // Five credits is the user's whole daily half, so the second charge must be refused for the
        // day no matter which side of UTC midnight it lands on.
        let request = Request {
            company_id: 7,
            user_id: 42,
            route_id: 1,
            credits: Credits {
                cpu: 5,
                inference: 0,
            },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed: false,
        };
        assert_eq!(
            limiter
                .admit_at(request, evening, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        let violation = limiter
            .admit_at(request, after_utc_midnight, Instant::now())
            .await
            .unwrap()
            .violation();
        assert_eq!(violation.scope, Scope::User);
        assert_eq!(violation.window, Window::Day);
        // The business day rolls over five hours after UTC midnight, and only then is the cap fresh.
        assert_eq!(
            limiter
                .admit_at(request, next_business_day, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
    }

    /// The configured share, and not the historical hard-coded half: at 80% of a ten-credit day a
    /// user reaches eight, so a fifth charge of two is refused by `Scope::User` while the company
    /// still has two credits of its own left.
    #[tokio::test]
    async fn the_user_daily_gate_follows_the_configured_share() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, unix_seconds, 10, 100));
        let policy = LimitPolicy {
            user_daily_share_pct: 80,
            ..test_policy(1_000)
        };
        let limiter = RateLimiter::new(1, policy, store, 600);
        for _ in 0..4 {
            assert_eq!(
                limiter
                    .admit_at(read_request(2, false), unix_seconds, Instant::now())
                    .await
                    .unwrap(),
                allowed()
            );
        }
        let violation = limiter
            .admit_at(read_request(2, false), unix_seconds, Instant::now())
            .await
            .unwrap()
            .violation();
        assert_eq!(violation.scope, Scope::User);
        assert_eq!(violation.window, Window::Day);
    }

    /// The usage header's figures: what each subject may still spend today once this request is paid
    /// for, and what the company spent in the short and the long window. A refusal reports the state
    /// it was judged on; the user's daily share (50 %) is what the user figure is measured against.
    #[tokio::test]
    async fn the_report_shows_what_is_left_after_the_charge() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store.put_budget(stored_budget(7, unix_seconds, 10, 100));
        let limiter = RateLimiter::new(1, test_policy(1_000), store, 600);
        let now = Instant::now();

        let (decision, report) = limiter
            .judge(read_request(2, false), unix_seconds, now, false)
            .await
            .unwrap();
        assert_eq!(decision, allowed());
        assert_eq!(
            report,
            Some(UsageReport {
                user_day_left: Some(3),
                company_day_left: 8,
                company_short_used: 2,
                company_long_used: 2,
                blocked: None,
                window_used: 0,
                retry_after: None,
            })
        );

        limiter
            .judge(read_request(2, false), unix_seconds, now, false)
            .await
            .unwrap();
        let (decision, report) = limiter
            .judge(read_request(2, false), unix_seconds, now, false)
            .await
            .unwrap();
        assert_eq!(decision.violation().scope, Scope::User);
        let report = report.unwrap();
        assert_eq!(report.user_day_left, Some(1));
        assert_eq!(report.company_day_left, 6);
        assert_eq!(report.company_long_used, 4);
        // The refusal names the window that refused (the user's day: four credits spent) and the
        // wait until the next business day, which is never zero.
        assert_eq!(report.window_used, 4);
        assert!(report.retry_after.unwrap() > 1);

        // With users not limited apart there is no user state, so no user figure.
        let company_only = RateLimiter::new(
            1,
            company_only_policy(1_000),
            Arc::new(MemoryStore::default()),
            600,
        );
        let (_, report) = company_only
            .judge(read_request(2, false), unix_seconds, now, false)
            .await
            .unwrap();
        assert_eq!(report.unwrap().user_day_left, None);
    }

    fn windowed_limiter(short: u64, long: u64, windows: Windows) -> RateLimiter {
        let store = Arc::new(MemoryStore::default());
        store.put_budget(stored_budget(7, 1_800_000_000, 1_000_000, 1_000_000));
        let limits = ScopeLimits {
            cpu: CreditLimits { short, long },
            inference: CreditLimits { short, long },
        };
        let policy = LimitPolicy {
            company: limits,
            user: limits,
            windows,
            ..test_policy(1_000)
        };
        RateLimiter::new(1, policy, store, 600)
    }

    /// A ten-minute long window: four credits fit, the fifth waits for the next ten-minute boundary,
    /// and the boundary resets the counter.
    #[tokio::test]
    async fn a_ten_minute_long_window_reopens_on_its_boundary() {
        let windows = Windows {
            short_seconds: 10,
            long_minutes: 10,
        };
        let limiter = windowed_limiter(1_000, 4, windows);
        // On a ten-minute boundary, so the whole window lies ahead.
        let start = 1_800_000_000;
        assert_eq!(start % 600, 0);
        let now = Instant::now();
        for _ in 0..2 {
            let (decision, _) = limiter
                .judge(read_request(2, false), start, now, false)
                .await
                .unwrap();
            assert_eq!(decision, allowed());
        }
        let (decision, report) = limiter
            .judge(read_request(2, false), start + 30, now, false)
            .await
            .unwrap();
        assert_eq!(decision.violation().window, Window::Long);
        let report = report.unwrap();
        assert_eq!(report.window_used, 4);
        assert_eq!(report.retry_after, Some(600 - 30 + 1));

        // Still inside the window, the block answers; one second past it, the counter is fresh.
        assert!(matches!(
            limiter
                .judge(read_request(2, false), start + 599, now, false)
                .await
                .unwrap()
                .0,
            Decision::CreditViolation(_)
        ));
        let (decision, report) = limiter
            .judge(read_request(2, false), start + 600, now, false)
            .await
            .unwrap();
        assert_eq!(decision, allowed());
        assert_eq!(report.unwrap().company_long_used, 2);
    }

    /// A thirty-second short window: three credits refill over thirty seconds, one every ten.
    #[tokio::test]
    async fn the_short_window_refills_over_its_configured_period() {
        let windows = Windows {
            short_seconds: 30,
            long_minutes: 60,
        };
        let limiter = windowed_limiter(3, 1_000, windows);
        let unix_seconds = 1_800_000_000;
        let now = Instant::now();
        let (decision, _) = limiter
            .judge(read_request(3, false), unix_seconds, now, false)
            .await
            .unwrap();
        assert_eq!(decision, allowed());
        let (decision, report) = limiter
            .judge(read_request(1, false), unix_seconds, now, false)
            .await
            .unwrap();
        assert_eq!(decision.violation().window, Window::Short);
        // One credit takes ten seconds to come back, plus the margin.
        assert_eq!(report.unwrap().retry_after, Some(11));

        let later = now + Duration::from_secs(10);
        let (decision, _) = limiter
            .judge(read_request(1, false), unix_seconds + 10, later, false)
            .await
            .unwrap();
        assert_eq!(decision, allowed());
    }

    #[test]
    fn windows_are_worded_for_the_refusal_page() {
        let windows = |short_seconds, long_minutes| Windows {
            short_seconds,
            long_minutes,
        };
        assert_eq!(
            windows(10, 10).describe(Window::Short),
            "en los últimos 10 segundos"
        );
        assert_eq!(
            windows(10, 10).describe(Window::Long),
            "en los últimos 10 minutos"
        );
        assert_eq!(
            windows(60, 60).describe(Window::Short),
            "en el último minuto"
        );
        assert_eq!(windows(10, 60).describe(Window::Long), "en la última hora");
        assert_eq!(
            windows(10, 120).describe(Window::Long),
            "en las últimas 2 horas"
        );
        assert_eq!(windows(10, 60).describe(Window::Day), "hoy");
    }

    fn company_only_policy(limit: u64) -> LimitPolicy {
        LimitPolicy {
            disable_user_limit: true,
            windows: Windows::default(),
            ..test_policy(limit)
        }
    }

    /// The same ten-credit day as above, at the test policy's 50% share: with the user limit on, the
    /// user stops at five credits. With it off, the user spends the whole company day and the refusal
    /// is the company's.
    #[tokio::test]
    async fn without_the_user_limit_only_the_company_is_judged() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store.put_budget(stored_budget(7, unix_seconds, 10, 100));
        let limiter = RateLimiter::new(1, company_only_policy(1_000), store, 600);
        for _ in 0..5 {
            assert_eq!(
                limiter
                    .admit_at(read_request(2, false), unix_seconds, Instant::now())
                    .await
                    .unwrap(),
                allowed()
            );
        }
        let violation = limiter
            .admit_at(read_request(2, false), unix_seconds, Instant::now())
            .await
            .unwrap()
            .violation();
        assert_eq!(violation.scope, Scope::Company);
        assert_eq!(violation.window, Window::Day);
    }

    /// A user burst that the user gate would refuse is admitted: the bucket is the company's.
    #[tokio::test]
    async fn without_the_user_limit_no_user_subject_is_kept() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, company_only_policy(1_000), store, 600);
        limiter
            .admit_at(read_request(2, false), 1_800_000_000, Instant::now())
            .await
            .unwrap();
        let shard = limiter.shards[0].lock().await;
        assert!(shard.subjects.contains_key(&(7, COMPANY_AGGREGATE_USER_ID)));
        assert!(!shard.subjects.contains_key(&(7, 42)));
    }

    /// The user's rows are not loaded before the charge any more, so the flush must add what is
    /// stored instead of overwriting it, and add it once: the second flush extends the total.
    #[tokio::test]
    async fn without_the_user_limit_the_flush_adds_the_stored_user_row() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        let user_daily = UsageKey {
            company_id: 7,
            user_id: 42,
            time_frame: time_frame::daily(unix_seconds).unwrap(),
        };
        let route_credits = |cpu| RoutedCredits::from([(34, Credits { cpu, inference: 0 })]);
        store
            .rows
            .lock()
            .unwrap()
            .insert(user_daily, encode(&route_credits(10)).unwrap());
        let limiter = RateLimiter::new(1, company_only_policy(1_000), store.clone(), 600);
        let stored_user_daily =
            || decode(store.rows.lock().unwrap().get(&user_daily).unwrap()).unwrap();

        limiter
            .admit_at(read_request(4, false), unix_seconds, Instant::now())
            .await
            .unwrap();
        limiter.flush_dirty().await;
        assert_eq!(stored_user_daily(), route_credits(14));

        limiter
            .admit_at(read_request(4, false), unix_seconds, Instant::now())
            .await
            .unwrap();
        limiter.flush_dirty().await;
        assert_eq!(stored_user_daily(), route_credits(18));
        assert_eq!(limiter.flush_dirty().await, 0);
    }

    /// Shadow mode's requirement: the same verdict as `admit`, with no effect at all. Two dry runs of
    /// the whole burst both pass, a dry refusal neither blocks nor counts, and the flush finds only
    /// what the real charge wrote.
    #[tokio::test]
    async fn a_dry_run_gives_the_verdict_and_changes_nothing() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, test_policy(10), store.clone(), 600);
        let now = Instant::now();
        let unix_seconds = 1_800_000_000;
        let dry = |cpu| limiter.admit_mode_at(read_request(cpu, false), unix_seconds, now, true);

        assert_eq!(dry(10).await.unwrap(), allowed());
        assert_eq!(dry(10).await.unwrap(), allowed());
        assert_eq!(limiter.flush_dirty().await, 0);

        assert_eq!(
            limiter
                .admit_at(read_request(10, false), unix_seconds, now)
                .await
                .unwrap(),
            allowed()
        );
        let refused = dry(1).await.unwrap().violation();
        assert_eq!(refused.window, Window::Short);
        assert_eq!(
            limiter
                .blocks
                .peek(&read_request(1, false), unix_seconds, now),
            None
        );
        // The real charge's rows and budget counters, and no refusal: the dry one was not counted.
        assert_eq!(limiter.flush_dirty().await, 6);
        assert!(store.rejections.lock().unwrap().is_empty());
    }

    /// The point of the block cache: once a company is refused, its next requests are answered while
    /// its shard lock is held by someone else, so an abuser cannot slow the other companies there.
    #[tokio::test]
    async fn a_blocked_company_is_answered_without_its_shard_lock() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, test_policy(10), store, 600);
        let now = Instant::now();
        let unix_seconds = 1_800_000_000;
        limiter
            .admit_at(read_request(10, false), unix_seconds, now)
            .await
            .unwrap();
        let first = limiter
            .admit_at(read_request(1, false), unix_seconds, now)
            .await
            .unwrap()
            .violation();

        let _held = limiter.shards[0].lock().await;
        let blocked = tokio::time::timeout(
            Duration::from_millis(200),
            limiter.admit_at(read_request(1, false), unix_seconds, now),
        )
        .await
        .expect("a blocked company must not wait for the shard lock")
        .unwrap()
        .violation();
        assert_eq!(blocked, first);
        assert_eq!(blocked.window, Window::Short);
    }

    /// A day block lasts until the next business day, unless the budget changes: the figures it was
    /// decided on are gone, so the next request is judged again.
    #[tokio::test]
    async fn a_budget_mutation_lifts_a_funds_block() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store.put_budget(stored_budget(7, unix_seconds, 4, 100));
        let limiter = RateLimiter::new(1, company_only_policy(1_000), store, 600);
        let admit = || limiter.admit_at(read_request(2, false), unix_seconds, Instant::now());
        assert_eq!(admit().await.unwrap(), allowed());
        assert_eq!(admit().await.unwrap(), allowed());
        assert_eq!(admit().await.unwrap().violation().window, Window::Day);
        assert_eq!(admit().await.unwrap().violation().window, Window::Day);

        limiter
            .mutate_budget_at(
                BudgetMutation {
                    company_id: 7,
                    operation: BudgetOperation::SetDaily,
                    credits: Credits {
                        cpu: 10,
                        inference: 10,
                    },
                },
                unix_seconds,
            )
            .await
            .unwrap();
        assert_eq!(admit().await.unwrap(), allowed());
    }

    #[tokio::test]
    async fn user_daily_budget_is_half_the_company_budget() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, unix_seconds, 10, 100));
        let limiter = RateLimiter::new(1, test_policy(1_000), store, 600);
        let request = Request {
            company_id: 7,
            user_id: 42,
            route_id: 1,
            credits: Credits {
                cpu: 5,
                inference: 0,
            },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed: false,
        };
        assert_eq!(
            limiter
                .admit_at(request, unix_seconds, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        let violation = limiter
            .admit_at(
                Request {
                    credits: Credits {
                        cpu: 1,
                        inference: 0,
                    },
                    ..request
                },
                unix_seconds,
                Instant::now(),
            )
            .await
            .unwrap()
            .violation();
        assert_eq!(violation.scope, Scope::User);
        assert_eq!(violation.window, Window::Day);
    }

    #[tokio::test]
    async fn monthly_budget_is_shared_by_every_company_user() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, unix_seconds, 100, 8));
        let limiter = RateLimiter::new(1, test_policy(1_000), store, 600);
        for user_id in [41, 42] {
            assert_eq!(
                limiter
                    .admit_at(
                        Request {
                            company_id: 7,
                            user_id,
                            route_id: 1,
                            credits: Credits {
                                cpu: 4,
                                inference: 0,
                            },
                            required_access: [0; MAX_REQUIRED_ACCESS],
                            extra_credits_allowed: false,
                        },
                        unix_seconds,
                        Instant::now(),
                    )
                    .await
                    .unwrap(),
                allowed()
            );
        }
        let violation = limiter
            .admit_at(
                Request {
                    company_id: 7,
                    user_id: 43,
                    route_id: 1,
                    credits: Credits {
                        cpu: 1,
                        inference: 0,
                    },
                    required_access: [0; MAX_REQUIRED_ACCESS],
                    extra_credits_allowed: false,
                },
                unix_seconds,
                Instant::now(),
            )
            .await
            .unwrap()
            .violation();
        assert_eq!(violation.scope, Scope::Company);
        assert_eq!(violation.window, Window::Month);
    }

    #[tokio::test]
    async fn set_current_anchors_to_usage_and_increase_adds_to_the_ceiling() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store.rows.lock().unwrap().insert(
            UsageKey {
                company_id: 7,
                user_id: COMPANY_AGGREGATE_USER_ID,
                time_frame: time_frame::daily(unix_seconds).unwrap(),
            },
            encode(&RoutedCredits::from([(
                1,
                Credits {
                    cpu: 30,
                    inference: 3,
                },
            )]))
            .unwrap(),
        );
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, unix_seconds, 100, 40));
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);

        assert_eq!(
            limiter
                .mutate_budget_at(
                    BudgetMutation {
                        company_id: 7,
                        operation: BudgetOperation::SetCurrent,
                        credits: Credits {
                            cpu: 70,
                            inference: 7,
                        },
                    },
                    unix_seconds,
                )
                .await
                .unwrap(),
            BudgetMutationReply::Ok
        );
        let anchored = store.budgets.lock().unwrap()[&7];
        assert_eq!(anchored.monthly_ceiling.cpu, 100);
        assert_eq!(anchored.monthly_ceiling.inference, 10);

        assert_eq!(
            limiter
                .mutate_budget_at(
                    BudgetMutation {
                        company_id: 7,
                        operation: BudgetOperation::IncreaseCurrent,
                        credits: Credits {
                            cpu: 25,
                            inference: 2,
                        },
                    },
                    unix_seconds,
                )
                .await
                .unwrap(),
            BudgetMutationReply::Ok
        );
        let increased = store.budgets.lock().unwrap()[&7];
        assert_eq!(increased.monthly_ceiling.cpu, 125);
        assert_eq!(increased.monthly_ceiling.inference, 12);
    }

    /// last_set is what lets a reader say "300 of the granted 1000 are gone": the ceiling cannot,
    /// because it folds in the usage that already existed when the grant was made.
    #[tokio::test]
    async fn last_set_records_the_granted_figure_and_survives_a_top_up() {
        let store = Arc::new(MemoryStore::default());
        let unix_seconds = 1_800_000_000;
        store.rows.lock().unwrap().insert(
            UsageKey {
                company_id: 7,
                user_id: COMPANY_AGGREGATE_USER_ID,
                time_frame: time_frame::daily(unix_seconds).unwrap(),
            },
            encode(&RoutedCredits::from([(
                1,
                Credits {
                    cpu: 30,
                    inference: 3,
                },
            )]))
            .unwrap(),
        );
        store
            .budgets
            .lock()
            .unwrap()
            .insert(7, stored_budget(7, unix_seconds, 100, 40));
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        let limiter_ref = &limiter;
        let mutate = |operation, cpu, inference| async move {
            limiter_ref
                .mutate_budget_at(
                    BudgetMutation {
                        company_id: 7,
                        operation,
                        credits: Credits { cpu, inference },
                    },
                    unix_seconds,
                )
                .await
                .unwrap()
        };

        assert_eq!(
            mutate(BudgetOperation::SetCurrent, 70, 7).await,
            BudgetMutationReply::Ok
        );
        let granted = store.budgets.lock().unwrap()[&7];
        // The grant is stored verbatim, while the ceiling carries the 30/3 already spent.
        assert_eq!(granted.last_set.cpu, 70);
        assert_eq!(granted.last_set.inference, 7);
        assert_eq!(granted.monthly_ceiling.cpu, 100);
        // Nothing is consumed yet against this grant: granted minus what remains is zero.
        assert_eq!(granted.last_set.cpu - (granted.monthly_ceiling.cpu - 30), 0);

        // A daily rate limit grants no credit, so it must leave the reference untouched.
        assert_eq!(
            mutate(BudgetOperation::SetDaily, 5, 5).await,
            BudgetMutationReply::Ok
        );
        assert_eq!(store.budgets.lock().unwrap()[&7].last_set.cpu, 70);

        // A top-up moves the reference by the same amount as the ceiling, so "consumed since the
        // grant" stays continuous instead of jumping when credits are added.
        assert_eq!(
            mutate(BudgetOperation::IncreaseCurrent, 25, 2).await,
            BudgetMutationReply::Ok
        );
        let topped_up = store.budgets.lock().unwrap()[&7];
        assert_eq!(topped_up.last_set.cpu, 95);
        assert_eq!(topped_up.last_set.inference, 9);
        assert_eq!(topped_up.monthly_ceiling.cpu, 125);
        assert_eq!(
            topped_up.last_set.cpu - (topped_up.monthly_ceiling.cpu - 30),
            0
        );
    }

    /// Mirrors `core.makeAccesoNivelUint16`: the packed form both processes agree on.
    fn packed(acceso_id: u16, nivel: u16) -> u16 {
        (acceso_id << 2) | (nivel - 1)
    }

    fn authorized_request(required: &[u16]) -> Request {
        let mut required_access = [0_u16; MAX_REQUIRED_ACCESS];
        required_access[..required.len()].copy_from_slice(required);
        Request {
            company_id: 7,
            user_id: 42,
            route_id: 1,
            credits: Credits {
                cpu: 5,
                inference: 0,
            },
            required_access,
            extra_credits_allowed: false,
        }
    }

    #[tokio::test]
    async fn a_held_access_is_admitted_and_charged() {
        let store = Arc::new(MemoryStore::default());
        store.put_user(7, 42, &[packed(3, 2), packed(20, 4)], 1);
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        assert_eq!(
            limiter
                .admit_at(
                    authorized_request(&[packed(20, 2)]),
                    1_800_000_000,
                    Instant::now()
                )
                .await
                .unwrap(),
            allowed_slots(0b1)
        );
        // Admitted means charged: the usage rows exist.
        assert!(limiter.flush_dirty().await > 0);
    }

    /// The load-bearing assertion for "deny first, no charge": a refusal must leave every usage map
    /// untouched, so nothing to flush and no subject allocated for the caller.
    #[tokio::test]
    async fn a_refusal_charges_nothing_at_all() {
        let store = Arc::new(MemoryStore::default());
        store.put_user(7, 42, &[packed(3, 1)], 1);
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        assert_eq!(
            limiter
                .admit_at(
                    authorized_request(&[packed(3, 2)]),
                    1_800_000_000,
                    Instant::now()
                )
                .await
                .unwrap(),
            Decision::AccessDenied(AccessDenial::NoAccess)
        );
        assert_eq!(limiter.flush_dirty().await, 0);
        assert!(store.rows.lock().unwrap().is_empty());
        {
            let shard = limiter.shards[0].lock().await;
            assert!(
                shard.subjects.is_empty(),
                "no quota state for a refused user"
            );
            assert!(shard.usage.is_empty());
            assert!(shard.budgets.is_empty(), "the budget was never even loaded");
        }
        assert!(limiter.platform_usage.lock().await.is_empty());
    }

    #[tokio::test]
    async fn identity_failures_are_distinct_from_permission_failures() {
        let store = Arc::new(MemoryStore::default());
        store.put_user(7, 43, &[packed(3, 4)], 0);
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);

        // No row at all: the token names a user this company does not have.
        assert_eq!(
            limiter
                .admit_at(
                    authorized_request(&[packed(3, 1)]),
                    1_800_000_000,
                    Instant::now()
                )
                .await
                .unwrap(),
            Decision::AccessDenied(AccessDenial::UnknownUser)
        );

        // Soft-deleted, and holding the access it is asking for. Status still wins.
        let mut inactive = authorized_request(&[packed(3, 1)]);
        inactive.user_id = 43;
        assert_eq!(
            limiter
                .admit_at(inactive, 1_800_000_000, Instant::now())
                .await
                .unwrap(),
            Decision::AccessDenied(AccessDenial::InactiveUser)
        );
    }

    /// A frame with empty slots must never reach the access map: that is the unmapped-GET,
    /// self-service and user-1 path, and it has to stay free of a store read.
    #[tokio::test]
    async fn a_frame_with_no_required_access_never_reads_the_user_row() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        let mut request = authorized_request(&[]);
        request.route_id = 34;
        assert_eq!(
            limiter
                .admit_at(request, 1_800_000_000, Instant::now())
                .await
                .unwrap(),
            allowed()
        );
        assert_eq!(store.user_reads.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn grants_are_read_once_and_reread_past_the_ttl() {
        let store = Arc::new(MemoryStore::default());
        store.put_user(7, 42, &[packed(3, 4)], 1);
        let limiter = RateLimiter::new(1, test_policy(100_000), store.clone(), 600);
        let request = authorized_request(&[packed(3, 1)]);

        for _ in 0..5 {
            limiter
                .admit_at(request, 1_800_000_000, Instant::now())
                .await
                .unwrap();
        }
        assert_eq!(
            store.user_reads.load(Ordering::Relaxed),
            1,
            "cached, not re-read"
        );

        // Inside the window, still one read. Past it, exactly one more.
        limiter
            .admit_at(request, 1_800_000_600, Instant::now())
            .await
            .unwrap();
        assert_eq!(store.user_reads.load(Ordering::Relaxed), 1);
        limiter
            .admit_at(request, 1_800_000_601, Instant::now())
            .await
            .unwrap();
        assert_eq!(store.user_reads.load(Ordering::Relaxed), 2);
    }

    /// A token naming a user that does not exist must not turn into a database read per request.
    #[tokio::test]
    async fn a_missing_user_is_cached_too() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        let request = authorized_request(&[packed(3, 1)]);
        for _ in 0..4 {
            assert_eq!(
                limiter
                    .admit_at(request, 1_800_000_000, Instant::now())
                    .await
                    .unwrap(),
                Decision::AccessDenied(AccessDenial::UnknownUser)
            );
        }
        assert_eq!(store.user_reads.load(Ordering::Relaxed), 1);
    }

    /// What makes the TTL a backstop rather than the mechanism.
    #[tokio::test]
    async fn dropping_cached_access_forces_a_reread_for_that_user_only() {
        let store = Arc::new(MemoryStore::default());
        store.put_user(7, 42, &[packed(3, 1)], 1);
        store.put_user(7, 43, &[packed(3, 1)], 1);
        let limiter = RateLimiter::new(1, test_policy(100_000), store.clone(), 600);
        let request = authorized_request(&[packed(3, 2)]);
        let mut other_user = request;
        other_user.user_id = 43;

        // Both denied at nivel 2, and both now cached.
        for probe in [request, other_user] {
            assert_eq!(
                limiter
                    .admit_at(probe, 1_800_000_000, Instant::now())
                    .await
                    .unwrap(),
                Decision::AccessDenied(AccessDenial::NoAccess)
            );
        }
        assert_eq!(store.user_reads.load(Ordering::Relaxed), 2);

        // A profile edit raises user 42 to nivel 4 and pushes it. Without dropping the cached
        // grants this would stay denied for the rest of the TTL.
        store.put_user(7, 42, &[packed(3, 4)], 1);
        store.put_user(7, 43, &[packed(3, 4)], 1);
        limiter.drop_cached_access(7, 42).await;
        assert_eq!(
            limiter
                .admit_at(request, 1_800_000_000, Instant::now())
                .await
                .unwrap(),
            allowed_slots(0b1)
        );
        // User 43 was not named, so it is still holding the stale answer.
        assert_eq!(
            limiter
                .admit_at(other_user, 1_800_000_000, Instant::now())
                .await
                .unwrap(),
            Decision::AccessDenied(AccessDenial::NoAccess)
        );
    }

    /// An authorize-only frame: `creditControlRoutes` sends these so an exempt-but-mapped route is
    /// still gated. It carries no credits and must still be authorized rather than refused.
    #[tokio::test]
    async fn an_authorize_only_frame_is_gated_and_admitted() {
        let store = Arc::new(MemoryStore::default());
        store.put_user(7, 42, &[packed(3, 4)], 1);
        let limiter = RateLimiter::new(1, test_policy(1_000), store.clone(), 600);
        let mut request = authorized_request(&[packed(3, 1)]);
        request.credits = Credits::default();
        assert_eq!(
            limiter
                .admit_at(request, 1_800_000_000, Instant::now())
                .await
                .unwrap(),
            allowed_slots(0b1)
        );
        // Zero credits still walk the quota path, so state exists — it just carries nothing.
        let shard = limiter.shards[0].lock().await;
        assert!(shard.subjects.contains_key(&(7, 42)));
        assert_eq!(shard.subjects[&(7, 42)].day_used, Credits::default());
    }
}
