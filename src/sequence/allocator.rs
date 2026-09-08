//! Hi-lo block allocation over the durable `sequences` counters.
//!
//! The ORM's own allocator reads a counter and then increments it, with nothing in between, so two
//! callers that read the same value both believe they own it. Moving the reservation here fixes
//! that by making one process the only writer of the row: the daemon bumps the durable counter by a
//! whole block, reads back where that landed, and owns the range it just created. Everything inside
//! that range is then handed out from memory with no I/O at all.
//!
//! Two properties follow from bumping *before* handing anything out. The durable value is always at
//! or above the highest value ever issued, so a crash loses the unused tail of a block — a gap,
//! never a reuse. And because the range is re-derived from the durable value on every block rather
//! than from a value cached at startup, a counter nudged underneath the daemon is picked up on the
//! next block instead of needing a restart.
//!
//! That second property is not enough for a counter that moves *downwards*, which is why `set`
//! exists: a live block derived from the old value would keep issuing ids past a counter that no
//! longer covers them, and the next block would repeat them. `set` moves the row and drops the
//! block under the same lock.
//!
//! The soundness of the read-back is what makes this exclusive: it is only correct while nothing
//! else writes these rows. A backend still using the ORM's direct path would collide with a range
//! this daemon believes it owns.

use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use tokio::sync::Mutex;
use tracing::warn;

use crate::sequence::store::SequenceStore;

/// Process-wide knobs. `block_size` trades restart burn against round trips: a bigger block means
/// fewer Scylla writes and more values lost when the daemon stops mid-block.
#[derive(Clone, Copy, Debug)]
pub struct SequenceLimits {
    pub block_size: u32,
    pub max_tracked_names: usize,
}

/// The half-open range this daemon currently owns for one counter.
#[derive(Clone, Copy, Debug)]
struct SequenceState {
    /// Next value to hand out.
    next: i64,
    /// Last value this daemon owns. `next > end` means the block is spent.
    end: i64,
}

impl SequenceState {
    /// A name that has never been served. `next > end`, so the first request always misses and
    /// loads a block rather than handing out a value nobody reserved.
    fn empty() -> Self {
        Self { next: 1, end: 0 }
    }

    fn is_spent(&self) -> bool {
        self.next > self.end
    }

    /// Takes `increment` consecutive values, or `None` when the live block cannot cover them.
    fn take(&mut self, increment: i64) -> Option<i64> {
        let start = self.next;
        let last = start.checked_add(increment - 1)?;
        if last > self.end {
            return None;
        }
        self.next = last + 1;
        Some(start)
    }
}

pub struct SequenceAllocator {
    store: Arc<dyn SequenceStore>,
    /// Sharded so unrelated counters never queue behind each other for the map itself. The inner
    /// mutex is what actually serializes one counter's reservations.
    shards: Vec<StdMutex<HashMap<String, Arc<Mutex<SequenceState>>>>>,
    tracked_names: AtomicUsize,
    limits: SequenceLimits,
}

impl SequenceAllocator {
    pub fn new(store: Arc<dyn SequenceStore>, shard_count: usize, limits: SequenceLimits) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            store,
            shards: (0..shard_count)
                .map(|_| StdMutex::new(HashMap::new()))
                .collect(),
            tracked_names: AtomicUsize::new(0),
            limits,
        }
    }

    /// Reserves `increment` consecutive values and returns the first of them, which is exactly what
    /// the ORM's `GetCounter` returns.
    pub async fn reserve(&self, name: &str, increment: u32) -> Result<i64> {
        let increment = i64::from(increment);
        let entry = self.entry_for(name)?;
        // Held across both Scylla calls on purpose: this is the serialization the whole feature
        // exists for. Only requests for this same counter wait behind it.
        let mut state = entry.lock().await;

        if let Some(start) = state.take(increment) {
            return Ok(start);
        }

        // A request wider than the configured block still gets served in one go, or a large insert
        // batch could never be satisfied.
        let block = increment.max(i64::from(self.limits.block_size));
        self.store.bump(name, block).await?;
        let reached = self.store.read(name).await?;

        let (first_owned, last_owned) = self.claim_block(name, reached, block).await?;
        *state = SequenceState {
            next: first_owned,
            end: last_owned,
        };

        state
            .take(increment)
            .context("a freshly claimed block must cover the request that loaded it")
    }

    /// Moves a counter to an absolute value and returns what it held before.
    ///
    /// This is the repair path — a restored backup, a counter realigned with the rows that actually
    /// exist — and it has to come through here rather than being written straight to the row. The
    /// reason is the block: this daemon may be holding a range it derived from the old value, and
    /// values it has already handed out from that range would otherwise be handed out a second time
    /// once the counter moved below them. Dropping the block under the same lock as the write is
    /// what makes the two atomic with respect to each other.
    ///
    /// The read is safe for the same reason the reserve path's read-back is: nothing else writes
    /// this row, so nothing can change it between the read and the correcting bump.
    pub async fn set(&self, name: &str, value: i64) -> Result<i64> {
        let entry = self.entry_for(name)?;
        let mut state = entry.lock().await;

        let previous = self.store.read(name).await?;
        // Counter columns are increment-only, so an absolute assignment is expressed as the delta
        // that reaches it — the same arithmetic genix-orm's ResetCounter used when it owned this.
        let delta = value.checked_sub(previous).with_context(|| {
            format!("sequences counter {name} cannot move from {previous} to {value}")
        })?;
        if delta != 0 {
            self.store.bump(name, delta).await?;
        }

        // Whatever this daemon still owned was derived from a value that no longer exists. Marking
        // the block spent costs the unused tail and forces the next reservation to re-derive.
        *state = SequenceState::empty();
        Ok(previous)
    }

    /// Works out which range the bump just created, repairing a counter that was driven
    /// non-positive.
    ///
    /// Mirrors `nextCounterRange` in genix-orm's scylla/main.go: a repair or a reset can leave the
    /// stored value negative, and the ids handed out have to stay positive because they become
    /// primary keys. The ORM folds the correction into the same update; here the bump has already
    /// happened, so the correction is a second one that lands the counter exactly on `block`.
    async fn claim_block(&self, name: &str, reached: i64, block: i64) -> Result<(i64, i64)> {
        let first_owned = reached
            .checked_sub(block)
            .and_then(|previous| previous.checked_add(1))
            .with_context(|| format!("sequences counter {name} overflowed at {reached}"))?;

        if first_owned > 0 {
            return Ok((first_owned, reached));
        }

        let correction = block.checked_sub(reached).with_context(|| {
            format!("sequences counter {name} cannot be repaired from {reached}")
        })?;
        warn!(
            counter = name,
            reached, block, correction, "recovered a non-positive sequence counter"
        );
        self.store.bump(name, correction).await?;
        Ok((1, block))
    }

    fn entry_for(&self, name: &str) -> Result<Arc<Mutex<SequenceState>>> {
        let mut shard = self.shard(name);
        if let Some(entry) = shard.get(name) {
            return Ok(entry.clone());
        }

        if self.tracked_names.load(Ordering::Relaxed) >= self.limits.max_tracked_names {
            self.prune_spent(&mut shard);
            if self.tracked_names.load(Ordering::Relaxed) >= self.limits.max_tracked_names {
                bail!(
                    "sequence allocator is tracking {} counter names, its configured ceiling",
                    self.limits.max_tracked_names
                );
            }
        }

        let entry = Arc::new(Mutex::new(SequenceState::empty()));
        shard.insert(name.to_owned(), entry.clone());
        self.tracked_names.fetch_add(1, Ordering::Relaxed);
        Ok(entry)
    }

    /// Drops entries whose block is already spent. Only those: evicting a live block would burn its
    /// unused tail, so the cheap half of the work is done and the rest is left to the ceiling.
    fn prune_spent(&self, shard: &mut HashMap<String, Arc<Mutex<SequenceState>>>) {
        let mut removed = 0;
        shard.retain(|_, entry| {
            // More than one handle means a reservation is in flight on it.
            if Arc::strong_count(entry) > 1 {
                return true;
            }
            let spent = entry
                .try_lock()
                .map(|state| state.is_spent())
                .unwrap_or(false);
            if spent {
                removed += 1;
            }
            !spent
        });
        self.tracked_names.fetch_sub(removed, Ordering::Relaxed);
    }

    fn shard(
        &self,
        name: &str,
    ) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Mutex<SequenceState>>>> {
        // A std mutex, not a tokio one: it is never held across an await, and the critical section
        // is a single hash lookup.
        self.shards[self.shard_index(name)]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn shard_index(&self, name: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        (hasher.finish() >> 32) as usize % self.shards.len()
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.tracked_names.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use async_trait::async_trait;

    use super::*;

    #[derive(Default)]
    struct FakeStore {
        counters: StdMutex<HashMap<String, i64>>,
        bumps: AtomicUsize,
        reads: AtomicUsize,
        fail: bool,
    }

    impl FakeStore {
        fn with_value(name: &str, value: i64) -> Self {
            let store = Self::default();
            store
                .counters
                .lock()
                .unwrap()
                .insert(name.to_owned(), value);
            store
        }

        fn value(&self, name: &str) -> i64 {
            *self.counters.lock().unwrap().get(name).unwrap_or(&0)
        }
    }

    #[async_trait]
    impl SequenceStore for FakeStore {
        async fn bump(&self, name: &str, by: i64) -> Result<()> {
            if self.fail {
                bail!("storage is down");
            }
            self.bumps.fetch_add(1, Ordering::Relaxed);
            // An interleaving point, so the concurrency test can actually interleave.
            tokio::task::yield_now().await;
            *self
                .counters
                .lock()
                .unwrap()
                .entry(name.to_owned())
                .or_insert(0) += by;
            Ok(())
        }

        async fn read(&self, name: &str) -> Result<i64> {
            if self.fail {
                bail!("storage is down");
            }
            self.reads.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
            Ok(self.value(name))
        }
    }

    fn allocator(store: Arc<FakeStore>, block_size: u32) -> SequenceAllocator {
        SequenceAllocator::new(
            store,
            4,
            SequenceLimits {
                block_size,
                max_tracked_names: 8,
            },
        )
    }

    #[tokio::test]
    async fn a_fresh_counter_starts_at_one() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 10);
        assert_eq!(allocator.reserve("x1_ventas_0", 1).await.unwrap(), 1);
        // The whole block is durable before the first value is handed out.
        assert_eq!(store.value("x1_ventas_0"), 10);
    }

    #[tokio::test]
    async fn values_come_from_memory_until_the_block_is_spent() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 10);

        for expected in 1..=10_i64 {
            assert_eq!(allocator.reserve("counter", 1).await.unwrap(), expected);
        }
        assert_eq!(
            store.bumps.load(Ordering::Relaxed),
            1,
            "one block, one bump"
        );

        // The eleventh exhausts the block and takes another.
        assert_eq!(allocator.reserve("counter", 1).await.unwrap(), 11);
        assert_eq!(store.bumps.load(Ordering::Relaxed), 2);
        assert_eq!(store.value("counter"), 20);
    }

    #[tokio::test]
    async fn a_request_wider_than_the_block_is_still_served_in_one_go() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 4);

        assert_eq!(allocator.reserve("bulk", 100).await.unwrap(), 1);
        assert_eq!(store.value("bulk"), 100);
        // Nothing is left over, so the next call takes a fresh block.
        assert_eq!(allocator.reserve("bulk", 1).await.unwrap(), 101);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reservations_never_overlap() {
        let store = Arc::new(FakeStore::default());
        let allocator = Arc::new(allocator(store.clone(), 8));

        let mut tasks = Vec::new();
        for _ in 0..64 {
            let allocator = allocator.clone();
            tasks.push(tokio::spawn(async move {
                allocator.reserve("contended", 3).await.unwrap()
            }));
        }

        let mut issued = HashSet::new();
        for task in tasks {
            let start = task.await.unwrap();
            // Every value in the reserved run must be new to anybody else's run.
            for value in start..start + 3 {
                assert!(issued.insert(value), "value {value} was handed out twice");
            }
        }
        assert_eq!(issued.len(), 64 * 3);
        // Nothing may be issued that the durable counter has not already accounted for.
        assert!(
            issued
                .iter()
                .all(|value| *value <= store.value("contended"))
        );
    }

    #[tokio::test]
    async fn a_damaged_counter_restarts_at_one() {
        // A reset can drive a counter below zero; the ids it hands out still have to be positive.
        let store = Arc::new(FakeStore::with_value("repaired", -500));
        let allocator = allocator(store.clone(), 10);

        assert_eq!(allocator.reserve("repaired", 1).await.unwrap(), 1);
        // The correction lands the counter exactly on the block it just handed out.
        assert_eq!(store.value("repaired"), 10);
        assert_eq!(allocator.reserve("repaired", 1).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn an_existing_counter_continues_where_it_left_off() {
        let store = Arc::new(FakeStore::with_value("resumed", 41));
        let allocator = allocator(store.clone(), 10);
        assert_eq!(allocator.reserve("resumed", 1).await.unwrap(), 42);
    }

    #[tokio::test]
    async fn different_names_do_not_share_a_block() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 10);
        assert_eq!(allocator.reserve("first", 1).await.unwrap(), 1);
        assert_eq!(allocator.reserve("second", 1).await.unwrap(), 1);
        assert_eq!(store.value("first"), 10);
        assert_eq!(store.value("second"), 10);
    }

    #[tokio::test]
    async fn a_storage_failure_hands_out_nothing() {
        let store = Arc::new(FakeStore {
            fail: true,
            ..FakeStore::default()
        });
        let allocator = allocator(store.clone(), 10);
        assert!(allocator.reserve("broken", 1).await.is_err());
        assert_eq!(store.value("broken"), 0);
    }

    #[tokio::test]
    async fn spent_entries_are_pruned_before_the_ceiling_refuses() {
        let store = Arc::new(FakeStore::default());
        // block_size 1 leaves every entry spent the moment it is served.
        let allocator = allocator(store.clone(), 1);

        for index in 0..8 {
            allocator
                .reserve(&format!("name_{index}"), 1)
                .await
                .unwrap();
        }
        assert_eq!(allocator.tracked(), 8, "the ceiling is exactly full");

        // The ninth name would exceed it, so the spent entries are dropped to make room.
        assert_eq!(allocator.reserve("name_8", 1).await.unwrap(), 1);
        assert!(allocator.tracked() <= 8);
    }

    /// The whole reason `set` exists. Writing the row directly would leave this daemon serving a
    /// block derived from the old value, and once the counter moved below what that block had
    /// already issued, the next block would hand those same values out again.
    #[tokio::test]
    async fn a_set_drops_the_live_block_so_nothing_is_issued_twice() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 100);

        let mut issued = HashSet::new();
        for _ in 0..5 {
            issued.insert(allocator.reserve("restored", 1).await.unwrap());
        }
        // A block of 100 is live and only five of it is spent.
        assert_eq!(store.value("restored"), 100);

        // A restore finds the partition actually holds rows up to id 3.
        let previous = allocator.set("restored", 3).await.unwrap();
        assert_eq!(previous, 100, "set reports what the counter held before");
        assert_eq!(store.value("restored"), 3);

        // The next reservation re-derives from 3 rather than continuing the abandoned block.
        assert_eq!(allocator.reserve("restored", 1).await.unwrap(), 4);
    }

    #[tokio::test]
    async fn a_set_upwards_is_honoured_too() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 10);

        allocator.reserve("moved", 1).await.unwrap();
        assert_eq!(allocator.set("moved", 5_000).await.unwrap(), 10);
        assert_eq!(allocator.reserve("moved", 1).await.unwrap(), 5_001);
    }

    /// Zero is what a partition with no rows left resets to, and the next id must be 1.
    #[tokio::test]
    async fn a_set_to_zero_restarts_the_counter() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 10);

        allocator.reserve("emptied", 4).await.unwrap();
        assert_eq!(allocator.set("emptied", 0).await.unwrap(), 10);
        assert_eq!(store.value("emptied"), 0);
        assert_eq!(allocator.reserve("emptied", 1).await.unwrap(), 1);
    }

    /// A set that changes nothing must not write, but must still drop the block: the caller only
    /// knows the value it wants, not whether this daemon is mid-block.
    #[tokio::test]
    async fn a_set_to_the_current_value_writes_nothing_and_still_drops_the_block() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 10);

        allocator.reserve("steady", 1).await.unwrap();
        let bumps_before = store.bumps.load(Ordering::Relaxed);
        assert_eq!(allocator.set("steady", 10).await.unwrap(), 10);
        assert_eq!(store.bumps.load(Ordering::Relaxed), bumps_before);
        // Re-derived from 10, not continued from the abandoned block's second value.
        assert_eq!(allocator.reserve("steady", 1).await.unwrap(), 11);
    }

    #[tokio::test]
    async fn a_storage_failure_during_a_set_leaves_the_counter_alone() {
        let store = Arc::new(FakeStore {
            fail: true,
            ..FakeStore::default()
        });
        let allocator = allocator(store.clone(), 10);
        assert!(allocator.set("broken", 5).await.is_err());
        assert_eq!(store.value("broken"), 0);
    }

    #[tokio::test]
    async fn a_ceiling_of_live_blocks_refuses_rather_than_overrunning() {
        let store = Arc::new(FakeStore::default());
        let allocator = allocator(store.clone(), 100);

        // Every block stays live, so nothing is prunable.
        for index in 0..8 {
            allocator
                .reserve(&format!("live_{index}"), 1)
                .await
                .unwrap();
        }
        assert!(allocator.reserve("one_too_many", 1).await.is_err());
    }
}
