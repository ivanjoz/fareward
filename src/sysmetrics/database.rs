//! What MariaDB itself reports, read over SQL once a sample interval.
//!
//! The cgroup already answers "how much CPU and RAM does the database process use". This answers
//! the questions only the server can: how big the InnoDB buffer pool is, how much of it is dirty —
//! modified in RAM and still owed to disk — and how much disk the tables occupy.
//!
//! It runs as its own task and publishes its newest reading through a `watch` channel, and the
//! metrics loop only ever *borrows* that reading. The two are kept apart on purpose: a database that
//! is slow to answer, or a reconnect that waits out its timeout, must never delay the host sample
//! that would show *why* the database is slow. A reading older than [`STALE_AFTER`] is treated as
//! absent, so a stuck probe shows up as `-1` instead of a flat line repeating its last good value.
//!
//! Fails open like the rest of the module: every failure is a warning and `-1`, and a lost
//! connection is retried after [`RECONNECT_BACKOFF`].

use std::time::{Duration, Instant};

use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{info, warn};

use crate::{
    mariadb::{MariaDbConnection, MariaDbSettings},
    sysmetrics::{DatabaseEngineSample, NOT_MEASURED, gigabyte_tenths, megabytes},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const STATUS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// `information_schema.TABLES` opens every table's statistics, so it gets more room than the
/// status read and runs far less often.
const DISK_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Table sizes move by megabytes over minutes. Asking every second would make the probe's own
/// metadata reads the busiest thing in a quiet database.
const DISK_REFRESH: Duration = Duration::from_secs(60);
/// A disk figure is still reported this long after the last successful read, which spans a few
/// failed refreshes without letting a stale number stand for hours.
const DISK_MAX_AGE: Duration = Duration::from_secs(300);
const RECONNECT_BACKOFF: Duration = Duration::from_secs(15);
/// How old the published reading may be when the metrics loop takes it.
pub const STALE_AFTER: Duration = Duration::from_secs(3);

/// Both values in one round trip. `@@GLOBAL` reads the live pool size, which MariaDB can resize
/// at runtime, rather than whatever the configuration file said at boot.
const STATUS_QUERY: &str = "SELECT @@GLOBAL.innodb_buffer_pool_size, \
     (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS \
      WHERE VARIABLE_NAME = 'INNODB_BUFFER_POOL_BYTES_DIRTY')";

/// Data plus indexes of every table the account can see, which for the Genix account is the Genix
/// database. Redo logs, binlogs and the RocksDB WAL are outside this figure: it is what the tables
/// weigh, not what the data directory weighs.
const DISK_QUERY: &str = "SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) \
     FROM information_schema.TABLES \
     WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')";

/// The newest reading and when it was taken. `None` until the first one lands.
pub type DatabaseReading = Option<(Instant, DatabaseEngineSample)>;

/// What the metrics loop holds: a borrow of the probe's newest reading.
#[derive(Clone)]
pub struct DatabaseReadings(watch::Receiver<DatabaseReading>);

impl DatabaseReadings {
    /// The newest reading, or every column absent when there is none or it has gone stale.
    pub fn latest(&self) -> DatabaseEngineSample {
        match *self.0.borrow() {
            Some((taken_at, sample)) if taken_at.elapsed() <= STALE_AFTER => sample,
            _ => DatabaseEngineSample::default(),
        }
    }
}

pub struct DatabaseProbe {
    settings: MariaDbSettings,
    connection: Option<MariaDbConnection>,
    /// Set after a failed connect, so an unreachable server costs one attempt per backoff and one
    /// warning, not one of each a second.
    reconnect_after: Option<Instant>,
    /// The last successful disk read: when, and the value.
    disk: Option<(Instant, i16)>,
    last_disk_attempt: Option<Instant>,
}

impl DatabaseProbe {
    pub fn new(settings: MariaDbSettings) -> Self {
        Self {
            settings,
            connection: None,
            reconnect_after: None,
            disk: None,
            last_disk_attempt: None,
        }
    }

    /// Polls every `sample_interval` until shutdown, publishing each reading.
    pub fn spawn(
        mut self,
        sample_interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> (DatabaseReadings, JoinHandle<()>) {
        let (sender, receiver) = watch::channel(None);
        let task = tokio::spawn(async move {
            let mut ticker = interval(sample_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let sample = self.sample().await;
                        sender.send_replace(Some((Instant::now(), sample)));
                    }
                }
            }
        });
        (DatabaseReadings(receiver), task)
    }

    /// One reading. Never fails: whatever could not be read is [`NOT_MEASURED`].
    pub async fn sample(&mut self) -> DatabaseEngineSample {
        let mut sample = DatabaseEngineSample::default();
        if !self.ensure_connected().await {
            return sample;
        }

        match self.read_status().await {
            Ok((buffer_pool_mb, dirty_mb)) => {
                sample.buffer_pool_mb = buffer_pool_mb;
                sample.dirty_mb = dirty_mb;
            }
            Err(error) => {
                warn!(error = %error, "MariaDB status read failed, reconnecting");
                // A query that failed half-way leaves the stream mid-packet; only a new connection
                // is known to be in a clean state.
                self.connection = None;
                return sample;
            }
        }

        self.refresh_disk_when_due().await;
        sample.disk_gb_tenths = match self.disk {
            Some((read_at, value)) if read_at.elapsed() <= DISK_MAX_AGE => value,
            _ => NOT_MEASURED,
        };
        sample
    }

    async fn ensure_connected(&mut self) -> bool {
        if self.connection.is_some() {
            return true;
        }
        if self
            .reconnect_after
            .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return false;
        }
        match MariaDbConnection::connect(&self.settings, CONNECT_TIMEOUT).await {
            Ok(connection) => {
                info!(address = ?self.settings.address, "MariaDB metrics probe connected");
                self.connection = Some(connection);
                self.reconnect_after = None;
                true
            }
            Err(error) => {
                warn!(
                    error = format!("{error:#}"),
                    retry_seconds = RECONNECT_BACKOFF.as_secs(),
                    "MariaDB metrics probe could not connect"
                );
                self.reconnect_after = Some(Instant::now() + RECONNECT_BACKOFF);
                false
            }
        }
    }

    async fn read_status(&mut self) -> anyhow::Result<(i16, i16)> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let rows = connection.query(STATUS_QUERY, STATUS_QUERY_TIMEOUT).await?;
        let row = rows.first();
        let column = |index: usize| -> i16 {
            parse_bytes(row.and_then(|row| row.get(index)))
                .map(megabytes)
                .unwrap_or(NOT_MEASURED)
        };
        Ok((column(0), column(1)))
    }

    async fn refresh_disk_when_due(&mut self) {
        if self
            .last_disk_attempt
            .is_some_and(|attempted| attempted.elapsed() < DISK_REFRESH)
        {
            return;
        }
        self.last_disk_attempt = Some(Instant::now());
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        match connection.query(DISK_QUERY, DISK_QUERY_TIMEOUT).await {
            Ok(rows) => {
                if let Some(bytes) = parse_bytes(rows.first().and_then(|row| row.first())) {
                    self.disk = Some((Instant::now(), gigabyte_tenths(bytes)));
                }
            }
            Err(error) => {
                warn!(error = %error, "MariaDB table size read failed, reconnecting");
                self.connection = None;
            }
        }
    }
}

/// A text column holding a byte count. MariaDB returns `SUM()` as a decimal, so a fractional
/// suffix is tolerated and dropped.
fn parse_bytes(value: Option<&Option<String>>) -> Option<u64> {
    let text = value?.as_deref()?.trim();
    let whole = text.split('.').next()?;
    whole.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_parse_from_text_and_decimals() {
        assert_eq!(
            parse_bytes(Some(&Some("134217728".into()))),
            Some(134_217_728)
        );
        assert_eq!(
            parse_bytes(Some(&Some("1048576.0000".into()))),
            Some(1_048_576)
        );
        assert_eq!(parse_bytes(Some(&None)), None);
        assert_eq!(parse_bytes(None), None);
        assert_eq!(parse_bytes(Some(&Some("abc".into()))), None);
    }

    /// The point of publishing through a channel: a probe that stopped answering must read as
    /// absent, not as its last good value repeated forever.
    #[test]
    fn a_stale_reading_reads_as_not_measured() {
        let fresh = DatabaseEngineSample {
            buffer_pool_mb: 128,
            dirty_mb: 3,
            disk_gb_tenths: 12,
        };
        let (sender, receiver) = watch::channel(None);
        let readings = DatabaseReadings(receiver);
        assert_eq!(readings.latest(), DatabaseEngineSample::default());

        sender.send_replace(Some((Instant::now(), fresh)));
        assert_eq!(readings.latest(), fresh);

        let Some(old) = Instant::now().checked_sub(STALE_AFTER + Duration::from_secs(1)) else {
            return; // A monotonic clock this close to its origin cannot express "old".
        };
        sender.send_replace(Some((old, fresh)));
        assert_eq!(readings.latest(), DatabaseEngineSample::default());
    }

    /// Against a real server, which a unit test cannot assume:
    ///
    /// ```sh
    /// FAREWARD_TEST_MARIADB_SOCKET=/run/mysqld/mysqld.sock \
    /// FAREWARD_TEST_MARIADB_USER=genix FAREWARD_TEST_MARIADB_PASSWORD=... \
    ///   cargo test real_mariadb -- --ignored --nocapture
    /// ```
    ///
    /// `FAREWARD_TEST_MARIADB_HOST`/`_PORT` dial TCP instead of the socket.
    #[tokio::test]
    #[ignore = "needs a running MariaDB"]
    async fn real_mariadb_reports_pool_dirty_and_disk() {
        use crate::mariadb::MariaDbAddress;
        let variable = |name: &str| std::env::var(format!("FAREWARD_TEST_MARIADB_{name}")).ok();
        let address = match variable("SOCKET") {
            Some(socket) => MariaDbAddress::Socket(socket),
            None => MariaDbAddress::Tcp {
                host: variable("HOST").unwrap_or_else(|| "127.0.0.1".into()),
                port: variable("PORT").map_or(3306, |port| port.parse().unwrap()),
            },
        };
        let mut probe = DatabaseProbe::new(MariaDbSettings {
            address,
            user: variable("USER").unwrap_or_else(|| "root".into()),
            password: variable("PASSWORD").unwrap_or_default(),
        });
        let sample = probe.sample().await;
        println!("{sample:?}");
        assert!(sample.buffer_pool_mb > 0, "buffer pool read");
        assert!(sample.dirty_mb >= 0, "dirty bytes read");
        assert!(sample.disk_gb_tenths >= 0, "table sizes read");
        // The second sample reuses the connection and the cached disk figure.
        assert_eq!(probe.sample().await.disk_gb_tenths, sample.disk_gb_tenths);
    }
}
