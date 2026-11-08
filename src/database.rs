//! The MariaDB pool shared by the limiter, the request log and the metrics writer. The tables are
//! the backend ORM's (`fn-homologate` creates them); this daemon only reads and writes rows.

use anyhow::{Context, Result};
use mysql_async::{OptsBuilder, Pool, PoolConstraints, PoolOpts, prelude::Queryable};

use crate::config::DatabaseConfig;

/// Connections the pool may hold. The limiter flushes and reads in bursts and the two writers each
/// write one batch at a time, so a handful covers the whole process.
const POOL_MAX_CONNECTIONS: usize = 8;

/// Opens the pool and checks one connection, so a wrong password or database fails the start
/// instead of the first flush.
pub async fn connect_pool(config: &DatabaseConfig) -> Result<Pool> {
    let constraints = PoolConstraints::new(1, POOL_MAX_CONNECTIONS)
        .context("invalid MariaDB pool constraints")?;
    let options = OptsBuilder::default()
        .ip_or_hostname(config.host.clone())
        .tcp_port(config.port)
        .user(Some(config.user.clone()))
        .pass(Some(config.password.clone()))
        .db_name(Some(config.database.clone()))
        // Every statement here is a single-row or single-batch write: no explicit transactions.
        .pool_opts(PoolOpts::default().with_constraints(constraints));
    let pool = Pool::new(options);
    let mut connection = pool.get_conn().await.with_context(|| {
        format!(
            "failed to connect to MariaDB {}:{} database {}",
            config.host, config.port, config.database
        )
    })?;
    connection
        .ping()
        .await
        .context("MariaDB did not answer a ping")?;
    Ok(pool)
}

/// Today as a UnixDay, the `date` key of user_logs and server_metrics.
pub fn unix_day_today() -> i16 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    (seconds / 86_400) as i16
}

/// Rows deleted per statement by `purge_days_before`: short statements keep the row locks and the
/// undo log small, so a large first purge never stalls the inserts running beside it.
const PURGE_BATCH_ROWS: u32 = 10_000;

/// Deletes the rows of `table` whose `date` key is older than `retention_days`. MariaDB has no TTL,
/// which is what expired these rows on ScyllaDB. Returns the rows removed.
pub async fn purge_days_before(pool: &Pool, table: &str, retention_days: i16) -> Result<u64> {
    let cutoff_day = unix_day_today().saturating_sub(retention_days);
    // `table` is a compile-time constant of the caller, never request data.
    let statement = format!("DELETE FROM {table} WHERE date < ? LIMIT {PURGE_BATCH_ROWS}");
    let mut connection = pool
        .get_conn()
        .await
        .context("no MariaDB connection for the purge")?;
    let mut removed_rows = 0_u64;
    loop {
        connection
            .exec_drop(&statement, (cutoff_day,))
            .await
            .with_context(|| format!("{table} retention purge failed"))?;
        let batch_rows = connection.affected_rows();
        removed_rows += batch_rows;
        if batch_rows < u64::from(PURGE_BATCH_ROWS) {
            return Ok(removed_rows);
        }
    }
}
