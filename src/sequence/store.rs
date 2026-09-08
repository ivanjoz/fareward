//! ScyllaDB adapter for the shared `sequences` counter table.
//!
//! The table is the ORM's, created by `InitSequencesTable` in genix-orm and shaped
//! `sequences(name text PRIMARY KEY, current_value counter)`. This daemon does not create it: a
//! keyspace that has never run the ORM's init has no application tables to number either.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use scylla::{client::session::Session, statement::prepared::PreparedStatement};

/// The two durable operations a block reservation needs. A trait, like `LimiterStore`, so the
/// allocator's arithmetic can be tested without a cluster.
#[async_trait]
pub trait SequenceStore: Send + Sync {
    /// Adds `by` to the counter, creating the row if it does not exist.
    async fn bump(&self, name: &str, by: i64) -> Result<()>;
    /// The counter's current value, or zero when no row exists yet.
    async fn read(&self, name: &str) -> Result<i64>;
}

pub struct ScyllaSequenceStore {
    session: Arc<Session>,
    bump_counter: PreparedStatement,
    select_counter: PreparedStatement,
}

impl ScyllaSequenceStore {
    pub async fn with_session(session: Arc<Session>) -> Result<Self> {
        let bump_counter = session
            .prepare("UPDATE sequences SET current_value = current_value + ? WHERE name = ?")
            .await
            .context("failed to prepare the sequences counter update")?;
        // Deliberately NOT marked idempotent, unlike every statement in the limiter's store. A
        // driver-level retry of a counter update applies it twice, and here that would silently
        // move the counter past the block this daemon believes it owns.

        let mut select_counter = session
            .prepare("SELECT current_value FROM sequences WHERE name = ?")
            .await
            .context("failed to prepare the sequences counter read")?;
        select_counter.set_is_idempotent(true);

        Ok(Self {
            session,
            bump_counter,
            select_counter,
        })
    }
}

#[async_trait]
impl SequenceStore for ScyllaSequenceStore {
    async fn bump(&self, name: &str, by: i64) -> Result<()> {
        // Counter updates bind the delta first and the key second, matching the statement above.
        self.session
            .execute_unpaged(&self.bump_counter, (by, name))
            .await
            .with_context(|| format!("sequences counter update failed for {name}"))?;
        Ok(())
    }

    async fn read(&self, name: &str) -> Result<i64> {
        let query_result = self
            .session
            .execute_unpaged(&self.select_counter, (name,))
            .await
            .with_context(|| format!("sequences counter read failed for {name}"))?;
        let rows_result = query_result
            .into_rows_result()
            .context("sequences counter read did not return rows")?;
        let mut rows = rows_result
            // A counter cell can be empty for a row that exists, so it decodes as nullable.
            .rows::<(Option<i64>,)>()
            .context("sequences row shape is invalid")?;
        match rows.next() {
            Some(row) => {
                let (current_value,) = row.context("sequences row decode failed")?;
                Ok(current_value.unwrap_or(0))
            }
            // No row means a counter nothing has ever incremented, which reads as zero — the same
            // value the ORM's own GetCounter starts from.
            None => Ok(0),
        }
    }
}
