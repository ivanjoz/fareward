//! Hot reload of the routes file (plan D1).
//!
//! The backend replaces the file with a write to a temporary name and a `rename`, so a reader never
//! sees half a file. This polls the file's modification time and size: no inotify dependency, and a
//! rename is caught the same as an in-place write. A change is parsed and validated whole before it
//! replaces the table; an invalid file keeps the previous table, so a bad deploy of the backend can
//! never leave the edge with no policy or with half of one.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::{error, info};

use crate::routes::table::RouteTable;

/// Counters for the reload, so a stale table is visible without reading logs.
#[derive(Debug, Default)]
pub struct ReloadMetrics {
    pub reloads: AtomicU64,
    pub rejected_files: AtomicU64,
}

/// The current table, shared by every request. A reader clones the `Arc` and keeps the table it
/// started with until it finishes, so a swap never changes the policy under a request.
pub struct RouteTableHandle {
    current: RwLock<Arc<RouteTable>>,
    path: PathBuf,
    /// The stamp of the last file read, taken before reading it, so a change that lands while (or
    /// after) it is read is seen by the next poll instead of being mistaken for the loaded version.
    seen: std::sync::Mutex<Option<FileStamp>>,
    pub metrics: ReloadMetrics,
}

/// What identifies one version of the file on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    modified: SystemTime,
    len: u64,
}

fn stamp(path: &Path) -> std::io::Result<FileStamp> {
    let metadata = std::fs::metadata(path)?;
    Ok(FileStamp {
        modified: metadata.modified()?,
        len: metadata.len(),
    })
}

fn load(path: &Path) -> Result<RouteTable> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read routes file {}", path.display()))?;
    RouteTable::parse(&content)
        .with_context(|| format!("routes file {} is invalid", path.display()))
}

impl RouteTableHandle {
    /// Loads the file once. A missing or invalid file is an error: the edge never runs without a
    /// table, because with no table every request would be refused, or worse, guessed.
    pub fn open(path: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let path = path.into();
        let seen = stamp(&path).ok();
        let table = load(&path)?;
        info!(
            path = %path.display(),
            version = table.version(),
            routes = table.len(),
            "route table loaded"
        );
        Ok(Arc::new(Self {
            current: RwLock::new(Arc::new(table)),
            path,
            seen: std::sync::Mutex::new(seen),
            metrics: ReloadMetrics::default(),
        }))
    }

    pub fn current(&self) -> Arc<RouteTable> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Re-reads the file now. On success the new table replaces the old one; on failure the old
    /// one stays and the error is returned.
    pub fn reload(&self) -> Result<()> {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = stamp(&self.path).ok();
        match load(&self.path) {
            Ok(table) => {
                info!(
                    path = %self.path.display(),
                    version = table.version(),
                    routes = table.len(),
                    "route table reloaded"
                );
                *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(table);
                self.metrics.reloads.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(load_error) => {
                self.metrics.rejected_files.fetch_add(1, Ordering::Relaxed);
                Err(load_error)
            }
        }
    }

    /// Polls the file every `interval` until `shutdown` turns true, reloading on every change of its
    /// modification time or size. A file that disappears keeps the current table: the backend
    /// replaces it by rename, so a missing file is a moment between two versions or an operator
    /// mistake, and in neither case is "no policy" the right answer.
    pub async fn watch(self: Arc<Self>, interval: Duration, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = ticker.tick() => {
                    let Ok(current) = stamp(&self.path) else { continue };
                    let last_seen = *self.seen.lock().unwrap_or_else(PoisonError::into_inner);
                    if Some(current) == last_seen {
                        continue;
                    }
                    if let Err(reload_error) = self.reload() {
                        error!(
                            path = %self.path.display(),
                            version = self.current().version(),
                            error = %format!("{reload_error:#}"),
                            "routes file rejected, keeping the previous table"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(version: &str) -> String {
        format!(
            "version = \"{version}\"\n[policy]\napi_prefixes = [\"api\"]\nsaas_company_id = 1\n\
             access_exempt_user_id = 1\noperator_company_id = 1\n[[route]]\nmethod = \"GET\"\npath = \"a\"\nroute_id = 1\n"
        )
    }

    /// Writes the way the backend does: a temporary file renamed over the real one.
    fn replace(path: &Path, content: &str) {
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, content).unwrap();
        std::fs::rename(&temporary, path).unwrap();
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fareward-routes-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_or_invalid_file_refuses_to_start() {
        let dir = scratch_dir("open");
        let path = dir.join("routes.toml");
        assert!(RouteTableHandle::open(&path).is_err());
        std::fs::write(&path, "version = ").unwrap();
        assert!(RouteTableHandle::open(&path).is_err());
    }

    #[test]
    fn an_invalid_file_keeps_the_previous_table() {
        let dir = scratch_dir("reload");
        let path = dir.join("routes.toml");
        replace(&path, &file("one"));
        let handle = RouteTableHandle::open(&path).unwrap();

        replace(&path, &file("two"));
        handle.reload().unwrap();
        assert_eq!(handle.current().version(), "two");

        replace(
            &path,
            &file("three").replace("route_id = 1", "route_id = 99999"),
        );
        assert!(handle.reload().is_err());
        assert_eq!(handle.current().version(), "two");
        assert_eq!(handle.metrics.rejected_files.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_watcher_picks_up_a_renamed_file() {
        let dir = scratch_dir("watch");
        let path = dir.join("routes.toml");
        replace(&path, &file("one"));
        let handle = RouteTableHandle::open(&path).unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let watcher = tokio::spawn(handle.clone().watch(Duration::from_millis(10), shutdown));

        // A different size, so the change is seen even where mtime has one-second resolution.
        replace(&path, &file("version-two"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while handle.current().version() != "version-two" {
            assert!(
                tokio::time::Instant::now() < deadline,
                "reload never happened"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        shutdown_sender.send(true).unwrap();
        watcher.await.unwrap();
    }
}
