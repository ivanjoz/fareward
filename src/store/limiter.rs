//! The limiter's `LimiterStore` over the fjall store, with the grants read from an `AccessSource`.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::limiter::aggregation::UsageKey;
use crate::limiter::block::Rejections;
use crate::limiter::devices::StoredDevices;
use crate::limiter::storage::{
    AccessSource, LimiterStore, StoredBudget, StoredBudgetRow, StoredBudgetUsage, StoredUsage,
    StoredUserAccess,
};
use crate::store::{FjallStore, query::ReportQuery};

pub struct StoreBackend {
    store: FjallStore,
    access: Arc<dyn AccessSource>,
}

impl StoreBackend {
    pub fn new(store: FjallStore, access: Arc<dyn AccessSource>) -> Self {
        Self { store, access }
    }
}

/// Runs a store call on the blocking pool: fjall reads can touch the disk.
async fn blocking<T: Send + 'static>(
    store: &FjallStore,
    call: impl FnOnce(&FjallStore) -> Result<T> + Send + 'static,
) -> Result<T> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || call(&store))
        .await
        .context("store task panicked")?
}

fn user_of(key: &UsageKey) -> Option<i32> {
    (!key.is_company_aggregate()).then_some(key.user_id)
}

#[async_trait]
impl LimiterStore for StoreBackend {
    async fn load_exact(&self, key: UsageKey) -> Result<Option<StoredUsage>> {
        blocking(&self.store, move |store| {
            Ok(store
                .usage_rows(
                    key.company_id,
                    user_of(&key),
                    key.time_frame,
                    key.time_frame,
                )?
                .into_iter()
                .next())
        })
        .await
    }

    async fn load_range(
        &self,
        company_id: i32,
        user_id: i32,
        start_time_frame: i32,
        end_time_frame: i32,
    ) -> Result<Vec<StoredUsage>> {
        let key = UsageKey {
            company_id,
            user_id,
            time_frame: start_time_frame,
        };
        blocking(&self.store, move |store| {
            store.usage_rows(company_id, user_of(&key), start_time_frame, end_time_frame)
        })
        .await
    }

    async fn upsert(&self, key: UsageKey, used_credits: Vec<u8>) -> Result<()> {
        blocking(&self.store, move |store| {
            store.put_usage(key.company_id, user_of(&key), key.time_frame, used_credits)
        })
        .await
    }

    async fn load_budget(&self, company_id: i32) -> Result<Option<StoredBudgetRow>> {
        blocking(&self.store, move |store| {
            Ok(store.budget(company_id)?.map(|record| StoredBudgetRow {
                budget: record.budget,
                extra: record.extra(),
            }))
        })
        .await
    }

    async fn upsert_budget(&self, budget: StoredBudget) -> Result<()> {
        blocking(&self.store, move |store| store.put_budget(budget)).await
    }

    async fn upsert_budget_usage(&self, usage: StoredBudgetUsage) -> Result<()> {
        blocking(&self.store, move |store| store.put_budget_usage(usage)).await
    }

    async fn add_rejections(
        &self,
        company_id: i32,
        time_frame: i32,
        rejections: Rejections,
    ) -> Result<()> {
        blocking(&self.store, move |store| {
            store.add_rejections(company_id, time_frame, rejections)
        })
        .await
    }

    async fn load_user_access(
        &self,
        company_id: i32,
        user_id: i32,
    ) -> Result<Option<StoredUserAccess>> {
        self.access.load_user_access(company_id, user_id).await
    }

    async fn load_devices(
        &self,
        company_id: i32,
        time_frame: i32,
    ) -> Result<Option<StoredDevices>> {
        blocking(&self.store, move |store| {
            store.devices(company_id, time_frame)
        })
        .await
    }

    async fn put_devices(
        &self,
        company_id: i32,
        time_frame: i32,
        row: StoredDevices,
    ) -> Result<()> {
        blocking(&self.store, move |store| {
            store.put_devices(company_id, time_frame, &row)
        })
        .await
    }

    async fn flush_completed(&self) -> Result<()> {
        blocking(&self.store, |store| store.persist()).await
    }

    async fn put_grants(&self, entries: Vec<crate::store::grants::GrantEntry>) -> Result<()> {
        blocking(&self.store, move |store| store.put_grants(&entries)).await
    }

    async fn report(&self, query: ReportQuery) -> Result<Vec<u8>> {
        blocking(&self.store, move |store| query.answer(store)).await
    }
}
