//! Turns sub-samples into `server_metrics` rows, written to Fareward's own store.
//!
//! The loop ticks once a second and writes on the tick that crosses a five-second boundary of the
//! wall clock, never on every fifth tick of a counter. That distinction is the whole reason a
//! restart lands back on the same grid instead of drifting, and it is why a skipped tick leaves an
//! honest hole in the series rather than shifting every later slot by one.
//!
//! Fails open throughout: a write that does not land is a warning and a counter.

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, sleep},
};
use tracing::{info, warn};

use crate::{
    config::ServerMetricsConfig,
    store::metrics::MetricsSink,
    sysmetrics::{
        WindowPeaks,
        collector::{ServiceUnits, SystemMetricsCollector},
        database::{DatabaseProbe, DatabaseReadings},
    },
};

const SECONDS_PER_DAY: i64 = 86_400;

/// How often days past the retention are deleted. The key is a day, so hourly is plenty.
const PURGE_INTERVAL: Duration = Duration::from_secs(3_600);

pub struct ServerMetricsWriter {
    sink: Arc<dyn MetricsSink>,
    retention_days: i16,
    last_purge: Option<Instant>,
}

impl ServerMetricsWriter {
    pub fn new(sink: Arc<dyn MetricsSink>, config: &ServerMetricsConfig) -> Self {
        Self {
            sink,
            retention_days: config.retention_days,
            last_purge: None,
        }
    }

    /// Runs the sampling loop until shutdown.
    pub fn spawn(
        mut self,
        config: ServerMetricsConfig,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut collector = SystemMetricsCollector::new(
                ServiceUnits {
                    backend: config.backend_unit.clone(),
                    fareward: config.fareward_unit.clone(),
                    database: config.database_unit.clone(),
                },
                config.disk_mount.clone(),
                config.network_interface.clone(),
            );
            // The probe is its own task so a slow database never delays the host sample; this loop
            // only borrows its newest reading. Stopped by the same shutdown signal.
            let (database_readings, database_task) = match config.mariadb.clone() {
                Some(settings) => {
                    let (readings, task) = DatabaseProbe::new(settings)
                        .spawn(config.sample_interval, shutdown.clone());
                    (Some(readings), Some(task))
                }
                None => {
                    info!("MariaDB metrics probe off: no [mariadb].user configured");
                    (None, None)
                }
            };
            let mut peaks = WindowPeaks::default();
            let mut pending_row_index: Option<i64> = None;
            let mut rows_written = 0_u64;
            let mut write_failures = 0_u64;

            // Start on a whole second so the sub-samples of a window are evenly spread inside it
            // rather than clustered around whenever the daemon happened to boot.
            sleep(nanoseconds_to_next_second()).await;
            let mut ticker = tokio::time::interval(config.sample_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

            info!(
                sample_ms = config.sample_interval.as_millis(),
                row_seconds = config.row_seconds,
                retention_days = config.retention_days,
                mount = %config.disk_mount,
                "server metrics collector started"
            );

            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let row_index = unix_seconds() / config.row_seconds;

                        // The window this tick belongs to is not the pending one, so the pending
                        // window is complete and gets written before the new sub-sample is taken.
                        // Reading it here rather than after absorbing is what keeps a sub-sample
                        // from landing in two rows.
                        if pending_row_index.is_some_and(|pending| pending != row_index) {
                            self.write_window(
                                pending_row_index.unwrap_or_default(),
                                config.row_seconds,
                                &mut peaks,
                                &mut rows_written,
                                &mut write_failures,
                            )
                            .await;
                        }

                        if let Some(mut sample) = collector.sample() {
                            sample.database_engine = database_readings
                                .as_ref()
                                .map(DatabaseReadings::latest)
                                .unwrap_or_default();
                            peaks.absorb(sample);
                        }
                        pending_row_index = Some(row_index);
                    }
                }
            }

            // The window in progress is written as it stands. A partial window is an honest peak
            // over fewer seconds; dropping it would leave a hole every time the daemon restarts.
            if let Some(pending) = pending_row_index {
                self.write_window(
                    pending,
                    config.row_seconds,
                    &mut peaks,
                    &mut rows_written,
                    &mut write_failures,
                )
                .await;
            }
            if let Some(database_task) = database_task {
                database_task.await.ok();
            }
            info!(
                rows_written,
                write_failures, "server metrics collector stopped"
            );
        })
    }

    /// Writes one window's peaks and clears the accumulator. A window that absorbed nothing writes
    /// nothing: a row of sentinels would claim the machine was observed and found absent.
    async fn write_window(
        &mut self,
        row_index: i64,
        row_seconds: i64,
        peaks: &mut WindowPeaks,
        rows_written: &mut u64,
        write_failures: &mut u64,
    ) {
        if peaks.is_empty() {
            return;
        }
        // Taken before the write on purpose: an unwritable window still has to clear the
        // accumulator, or its peak would leak into every later row until the table appears.
        let sample = peaks.take();
        self.purge_when_due().await;
        let window_start = row_index * row_seconds;
        let date = (window_start / SECONDS_PER_DAY) as i16;
        let slot = ((window_start % SECONDS_PER_DAY) / row_seconds) as i16;

        match self.sink.write(date, slot, &sample) {
            Ok(()) => *rows_written += 1,
            Err(write_error) => {
                *write_failures += 1;
                warn!(error = %write_error, date, slot, "server_metrics write failed, dropping the row");
            }
        }
    }

    /// Deletes days past the retention, at most once per PURGE_INTERVAL. Runs inside the write
    /// path because this loop is the writer's only task; a failure is a warning like a lost row.
    async fn purge_when_due(&mut self) {
        if self
            .last_purge
            .is_some_and(|purged| purged.elapsed() < PURGE_INTERVAL)
        {
            return;
        }
        self.last_purge = Some(Instant::now());
        let cutoff_day = ((unix_seconds() / 86_400) as i16).saturating_sub(self.retention_days);
        if let Err(purge_error) = self.sink.purge_before(cutoff_day) {
            warn!(error = %purge_error, "server_metrics retention purge failed");
        }
    }
}

/// Wall-clock seconds. The slot is a position in the day, so it can only come from an absolute
/// clock — an `Instant` would restart at zero with the process.
fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn nanoseconds_to_next_second() -> Duration {
    let subsecond = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or(0);
    Duration::from_nanos(u64::from(1_000_000_000 - subsecond.min(999_999_999)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity of a row is derived from the window's start, not from a counter. These are the
    /// three cases that would corrupt a day: the first window, the last, and the rollover.
    fn window_identity(window_start: i64, row_seconds: i64) -> (i16, i16) {
        let row_index = window_start / row_seconds;
        let start = row_index * row_seconds;
        (
            (start / SECONDS_PER_DAY) as i16,
            ((start % SECONDS_PER_DAY) / row_seconds) as i16,
        )
    }

    #[test]
    fn slots_cover_a_day_and_roll_over_cleanly() {
        // 2026-01-01T00:00:00Z is unix day 20454.
        let midnight = 20_454 * SECONDS_PER_DAY;
        assert_eq!(window_identity(midnight, 5), (20_454, 0));
        assert_eq!(window_identity(midnight + 4, 5), (20_454, 0));
        assert_eq!(window_identity(midnight + 5, 5), (20_454, 1));
        // The last window of the day, and the first of the next.
        assert_eq!(
            window_identity(midnight + SECONDS_PER_DAY - 5, 5),
            (20_454, 17_279)
        );
        assert_eq!(window_identity(midnight + SECONDS_PER_DAY, 5), (20_455, 0));
    }

    #[test]
    fn the_first_tick_waits_for_a_whole_second() {
        let delay = nanoseconds_to_next_second();
        assert!(delay <= Duration::from_secs(1));
        assert!(delay > Duration::ZERO);
    }
}
