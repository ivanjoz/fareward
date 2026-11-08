//! The company block cache and its rejection counters (plan D9).
//!
//! Once a company gate refuses, every further request from that company would be refused the same
//! way until the gate reopens. Each of those refusals used to take the company's shard lock, slowing
//! every other company on the shard, and left no trace at all. This cache remembers the verdict until
//! the moment it can change, so a blocked request is answered without the shard lock, and it counts
//! every refusal so the flush can persist how much a company was refused and why.
//!
//! The block is by company, never by user or by IP: each company is one customer who creates its own
//! users, and an IP can be shared by many customers.
//!
//! The block is only a cache of a verdict the limiter already reached. It never refuses anything the
//! limiter would admit at the same instant, with one deliberate exception: it runs before
//! authorization, so a blocked company gets its 429 even on a request that would have been a 403.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Instant,
};

use crate::limiter::{
    protocol::{LimitViolation, Request, Window},
    time_frame,
};

/// Refusals of one company in one time frame, by cause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rejections {
    /// The 10-second burst gate: a sign of abuse.
    pub burst: u32,
    /// The one-hour gate: a sign of abuse.
    pub hour: u32,
    /// The daily entitlement, the monthly ceiling, and a marked read the extra pool could not pay:
    /// a lack of credits rather than abuse, kept apart so it never inflates the abuse figures.
    pub no_funds: u32,
}

impl Rejections {
    fn count(&mut self, window: Window) {
        let counter = match window {
            Window::TenSeconds => &mut self.burst,
            Window::Hour => &mut self.hour,
            Window::Day | Window::Month => &mut self.no_funds,
        };
        *counter = counter.saturating_add(1);
    }

    pub fn add(&mut self, other: Rejections) {
        self.burst = self.burst.saturating_add(other.burst);
        self.hour = self.hour.saturating_add(other.hour);
        self.no_funds = self.no_funds.saturating_add(other.no_funds);
    }
}

/// When a block lifts, on the clock its gate runs on.
#[derive(Clone, Copy, Debug)]
pub enum Until {
    /// The burst bucket refills on the monotonic clock.
    Monotonic(Instant),
    /// The hour, the day and the month are calendar windows: they turn over with the wall clock,
    /// including when it is stepped, so their blocks must too.
    UnixSeconds(i64),
}

impl Until {
    fn reached(self, unix_seconds: i64, now: Instant) -> bool {
        match self {
            Until::Monotonic(until) => now >= until,
            Until::UnixSeconds(until) => unix_seconds >= until,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Block {
    /// What the limiter answered, returned as is so a blocked client sees no difference.
    pub violation: LimitViolation,
    pub until: Until,
    /// False for a day or month block while the extra pool may still pay a marked read: those reads
    /// go through the limiter, which consults the pool.
    pub applies_to_marked_reads: bool,
}

impl Block {
    fn applies(&self, request: &Request, unix_seconds: i64, now: Instant) -> bool {
        // Only the dimension that ran out: an exhausted inference allowance does not block CPU work.
        let asks_for_blocked = (self.violation.cpu && request.credits.cpu > 0)
            || (self.violation.inference && request.credits.inference > 0);
        !self.until.reached(unix_seconds, now)
            && asks_for_blocked
            && (self.applies_to_marked_reads || !request.extra_credits_allowed)
    }
}

#[derive(Default)]
struct CompanyGate {
    /// One slot per window, in `Window` order, so the shortest window answers first, as it does in
    /// the limiter.
    blocks: [Option<Block>; 4],
    /// Refusals not yet flushed, by time frame: each one is counted in its five-minute frame and in
    /// its day, like the credits.
    pending: BTreeMap<i32, Rejections>,
}

impl CompanyGate {
    fn count(&mut self, window: Window, unix_seconds: i64) {
        for time_frame in [
            time_frame::five_minute(unix_seconds),
            time_frame::daily(unix_seconds),
        ]
        .into_iter()
        .flatten()
        {
            self.pending.entry(time_frame).or_default().count(window);
        }
    }

    fn is_idle(&self, unix_seconds: i64, now: Instant) -> bool {
        self.pending.is_empty()
            && self
                .blocks
                .iter()
                .flatten()
                .all(|block| block.until.reached(unix_seconds, now))
    }
}

type GateMap = HashMap<i32, Arc<Mutex<CompanyGate>>>;

/// Sharded by company like the limiter, but behind its own locks: a lookup takes a shard read lock
/// and then the company's own mutex, so the only requests that contend on a blocked company are that
/// company's own.
pub struct CompanyBlocks {
    shards: Vec<RwLock<GateMap>>,
}

impl CompanyBlocks {
    pub fn new(shard_count: usize) -> Self {
        Self {
            shards: (0..shard_count.max(1))
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
        }
    }

    fn shard(&self, company_id: i32) -> &RwLock<GateMap> {
        &self.shards[company_id as usize % self.shards.len()]
    }

    fn gate(&self, company_id: i32) -> Option<Arc<Mutex<CompanyGate>>> {
        self.shard(company_id)
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&company_id)
            .cloned()
    }

    fn gate_or_insert(&self, company_id: i32) -> Arc<Mutex<CompanyGate>> {
        if let Some(gate) = self.gate(company_id) {
            return gate;
        }
        self.shard(company_id)
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(company_id)
            .or_default()
            .clone()
    }

    /// The violation a blocked company gets, counted, or `None` when the request must go through the
    /// limiter. A request that charges nothing is never blocked: the credit panel's own reads are
    /// free precisely so a company out of credit can still see why.
    pub fn check(
        &self,
        request: &Request,
        unix_seconds: i64,
        now: Instant,
    ) -> Option<LimitViolation> {
        if request.credits.cpu == 0 && request.credits.inference == 0 {
            return None;
        }
        let gate = self.gate(request.company_id)?;
        let mut gate = gate.lock().unwrap_or_else(PoisonError::into_inner);
        let violation = gate
            .blocks
            .iter()
            .flatten()
            .find(|block| block.applies(request, unix_seconds, now))?
            .violation;
        gate.count(violation.window, unix_seconds);
        Some(violation)
    }

    /// `check` without counting: the verdict a dry run must see, with no effect.
    pub fn peek(
        &self,
        request: &Request,
        unix_seconds: i64,
        now: Instant,
    ) -> Option<LimitViolation> {
        if request.credits.cpu == 0 && request.credits.inference == 0 {
            return None;
        }
        let gate = self.gate(request.company_id)?;
        let gate = gate.lock().unwrap_or_else(PoisonError::into_inner);
        gate.blocks
            .iter()
            .flatten()
            .find(|block| block.applies(request, unix_seconds, now))
            .map(|block| block.violation)
    }

    /// Records a refusal the limiter just made, and blocks the company until `block.until`.
    pub fn record(&self, company_id: i32, block: Block, unix_seconds: i64) {
        let gate = self.gate_or_insert(company_id);
        let mut gate = gate.lock().unwrap_or_else(PoisonError::into_inner);
        gate.blocks[block.violation.window as usize] = Some(block);
        gate.count(block.violation.window, unix_seconds);
    }

    /// Lifts the day and month blocks: a budget mutation changes the figures they were decided on.
    pub fn clear_funds(&self, company_id: i32) {
        if let Some(gate) = self.gate(company_id) {
            let mut gate = gate.lock().unwrap_or_else(PoisonError::into_inner);
            gate.blocks[Window::Day as usize] = None;
            gate.blocks[Window::Month as usize] = None;
        }
    }

    /// Drains every pending counter as `(company_id, time_frame, rejections)`, and drops the companies
    /// left with nothing to block and nothing to flush.
    pub fn take_pending(&self, unix_seconds: i64, now: Instant) -> Vec<(i32, i32, Rejections)> {
        let mut drained = Vec::new();
        for shard in &self.shards {
            let mut shard = shard.write().unwrap_or_else(PoisonError::into_inner);
            shard.retain(|&company_id, gate| {
                let mut state = gate.lock().unwrap_or_else(PoisonError::into_inner);
                drained.extend(
                    std::mem::take(&mut state.pending)
                        .into_iter()
                        .map(|(time_frame, rejections)| (company_id, time_frame, rejections)),
                );
                // The write lock stops new holders; a count of one means no request still holds this
                // gate, so removing it cannot lose an increment made through an older handle.
                !(state.is_idle(unix_seconds, now) && Arc::strong_count(gate) == 1)
            });
        }
        drained
    }

    /// Puts back counters whose write failed, so the next flush retries them.
    pub fn restore(&self, company_id: i32, time_frame: i32, rejections: Rejections) {
        let gate = self.gate_or_insert(company_id);
        let mut gate = gate.lock().unwrap_or_else(PoisonError::into_inner);
        gate.pending.entry(time_frame).or_default().add(rejections);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::limiter::{access::MAX_REQUIRED_ACCESS, credits_blob::Credits, protocol::Scope};

    const CLOCK: i64 = 1_800_000_000;

    fn request(cpu: u64, inference: u64, marked: bool) -> Request {
        Request {
            company_id: 7,
            user_id: 42,
            route_id: 34,
            credits: Credits { cpu, inference },
            required_access: [0; MAX_REQUIRED_ACCESS],
            extra_credits_allowed: marked,
        }
    }

    fn block(window: Window, until: Instant, marked_too: bool) -> Block {
        Block {
            violation: LimitViolation {
                scope: Scope::Company,
                window,
                cpu: true,
                inference: false,
            },
            until: Until::Monotonic(until),
            applies_to_marked_reads: marked_too,
        }
    }

    #[test]
    fn a_blocked_company_is_refused_until_the_block_expires() {
        let blocks = CompanyBlocks::new(4);
        let now = Instant::now();
        assert_eq!(blocks.check(&request(2, 0, false), CLOCK, now), None);

        let until = now + Duration::from_secs(3);
        blocks.record(7, block(Window::TenSeconds, until, true), CLOCK);
        let refused = blocks.check(&request(2, 0, false), CLOCK, now).unwrap();
        assert_eq!(refused.window, Window::TenSeconds);
        assert_eq!(blocks.check(&request(2, 0, false), CLOCK, until), None);
    }

    /// A calendar block follows the wall clock: it lifts when the day turns, whatever the monotonic
    /// clock says.
    #[test]
    fn a_calendar_block_lifts_on_the_wall_clock() {
        let blocks = CompanyBlocks::new(1);
        let now = Instant::now();
        let next_day = CLOCK + 3_600;
        blocks.record(
            7,
            Block {
                until: Until::UnixSeconds(next_day),
                ..block(Window::Day, now, true)
            },
            CLOCK,
        );
        assert!(blocks.check(&request(2, 0, false), CLOCK, now).is_some());
        assert!(blocks.check(&request(2, 0, false), next_day, now).is_none());
    }

    #[test]
    fn the_block_covers_the_whole_company_and_only_it() {
        let blocks = CompanyBlocks::new(4);
        let now = Instant::now();
        blocks.record(
            7,
            block(Window::Hour, now + Duration::from_secs(60), true),
            CLOCK,
        );
        let other_user = Request {
            user_id: 99,
            ..request(2, 0, false)
        };
        let other_company = Request {
            company_id: 8,
            ..request(2, 0, false)
        };
        assert!(blocks.check(&other_user, CLOCK, now).is_some());
        assert!(blocks.check(&other_company, CLOCK, now).is_none());
    }

    #[test]
    fn a_free_request_and_an_unblocked_dimension_go_through() {
        let blocks = CompanyBlocks::new(1);
        let now = Instant::now();
        blocks.record(
            7,
            block(Window::Day, now + Duration::from_secs(60), true),
            CLOCK,
        );
        assert!(blocks.check(&request(0, 0, false), CLOCK, now).is_none());
        assert!(blocks.check(&request(0, 3, false), CLOCK, now).is_none());
        assert!(blocks.check(&request(1, 0, false), CLOCK, now).is_some());
    }

    #[test]
    fn a_funds_block_lets_marked_reads_reach_the_pool() {
        let blocks = CompanyBlocks::new(1);
        let now = Instant::now();
        blocks.record(
            7,
            block(Window::Day, now + Duration::from_secs(60), false),
            CLOCK,
        );
        assert!(blocks.check(&request(2, 0, true), CLOCK, now).is_none());
        assert!(blocks.check(&request(2, 0, false), CLOCK, now).is_some());

        blocks.clear_funds(7);
        assert!(blocks.check(&request(2, 0, false), CLOCK, now).is_none());
    }

    #[test]
    fn refusals_are_counted_by_cause_in_the_five_minute_frame_and_the_day() {
        let blocks = CompanyBlocks::new(1);
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        blocks.record(7, block(Window::TenSeconds, later, true), CLOCK);
        blocks.check(&request(2, 0, false), CLOCK, now);
        blocks.record(7, block(Window::Month, later, true), CLOCK);

        let mut pending = blocks.take_pending(CLOCK, now);
        pending.sort_by_key(|(_, time_frame, _)| *time_frame);
        let expected = Rejections {
            burst: 2,
            hour: 0,
            no_funds: 1,
        };
        assert_eq!(
            pending,
            vec![
                (7, time_frame::five_minute(CLOCK).unwrap(), expected),
                (7, time_frame::daily(CLOCK).unwrap(), expected),
            ]
        );
        assert!(blocks.take_pending(CLOCK, now).is_empty());
    }

    #[test]
    fn an_idle_company_is_dropped_and_a_failed_write_is_retried() {
        let blocks = CompanyBlocks::new(1);
        let now = Instant::now();
        blocks.record(7, block(Window::TenSeconds, now, true), CLOCK);
        assert_eq!(blocks.take_pending(CLOCK, now).len(), 2);
        assert!(blocks.shards[0].read().unwrap().is_empty());

        let failed = Rejections {
            burst: 3,
            hour: 0,
            no_funds: 0,
        };
        blocks.restore(7, 100, failed);
        assert_eq!(blocks.take_pending(CLOCK, now), vec![(7, 100, failed)]);
    }
}
