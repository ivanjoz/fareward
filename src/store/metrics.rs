//! Where the server metrics writer puts its rows.

use anyhow::Result;

use crate::store::FjallStore;
use crate::sysmetrics::MetricsSample;

/// The metrics writer's only dependency: write one window, drop old days.
pub trait MetricsSink: Send + Sync {
    fn write(&self, date: i16, slot: i16, sample: &MetricsSample) -> Result<()>;
    /// Deletes every day before `cutoff_day`. Returns how many samples went.
    fn purge_before(&self, cutoff_day: i16) -> Result<usize>;
}

impl MetricsSink for FjallStore {
    fn write(&self, date: i16, slot: i16, sample: &MetricsSample) -> Result<()> {
        self.put_metrics(date, slot, sample)
    }

    fn purge_before(&self, cutoff_day: i16) -> Result<usize> {
        self.purge_metrics_before(cutoff_day)
    }
}
