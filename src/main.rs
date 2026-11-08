//! Genix server utilities: one process hosting two independent services.
//!
//!   - The raw-TCP credit rate limiter (`server`, `limiter`, `storage`).
//!   - The HTTP SSE bridge that relays agent events to browser tabs (`bridge`).
//!
//! They share only this process: the config load, the shutdown signal, and the tokio runtime.
//! Neither calls into the other.

use std::{sync::Arc, time::Instant};

use anyhow::{Context, Result};
use fareward::{
    bridge::{self, channel::ChannelRegistry, http::BridgeState},
    config::AppConfig,
    limiter::quota::RateLimiter,
    lock::registry::LockRegistry,
    routes::RouteTableHandle,
    service::server,
    spoe::{Agent, AgentLimits},
    store::{FjallStore, limiter::StoreBackend},
    sysmetrics::writer::ServerMetricsWriter,
};
use tokio::{net::TcpListener, sync::watch, time::MissedTickBehavior};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = AppConfig::load().context("fareward configuration is invalid")?;
    // Fareward's own store: usage, budgets and server metrics. Fails the start, because the limiter
    // must load the existing usage before admitting anything.
    let fjall_store = FjallStore::open(&config.store_path)?;
    info!(path = %config.store_path.display(), "store opened");
    let store = Arc::new(StoreBackend::new(
        fjall_store.clone(),
        Arc::new(fjall_store.clone()),
    ));
    let limiter = Arc::new(RateLimiter::new(
        config.shard_count,
        config.policy,
        store,
        config.access_cache_seconds,
    ));
    // Purely in-memory, unlike the limiter: locks are not loaded from anywhere and do not
    // survive a restart.
    let locks = Arc::new(LockRegistry::new(config.shard_count, config.locks));
    let listener = TcpListener::bind(config.listen_address)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_address))?;
    let unix_listener = match &config.unix_socket_path {
        Some(socket_path) => Some(server::bind_unix_socket(socket_path)?),
        None => None,
    };
    let bridge_listener = TcpListener::bind(config.bridge.listen_address)
        .await
        .with_context(|| format!("failed to bind {}", config.bridge.listen_address))?;
    // The rate limiter authenticates its frames with the service secret, not with the
    // token-signing one.
    let internal_apikey = Arc::new(config.internal_apikey.clone());
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);

    // Fails open, unlike the limiter: nothing calls into this task, so a metrics row that is never written costs a gap in a chart and nothing else. It is also the
    // only task here that keeps running when the backend is a Lambda, which is the whole point of
    // sampling the machine from this process rather than from the backend.
    let metrics_task = if config.server_metrics.enabled {
        Some(
            ServerMetricsWriter::new(Arc::new(fjall_store.clone()), &config.server_metrics)
                .spawn(config.server_metrics.clone(), shutdown_receiver.clone()),
        )
    } else {
        info!("server metrics collector disabled by configuration");
        None
    };

    // The HAProxy agent: one more front-end of the same limiter. A missing or invalid route table
    // fails the start, because the agent must never run without the backend's policy.
    let spoe_tasks = match &config.spoe {
        Some(spoe_config) => {
            let routes = RouteTableHandle::open(&spoe_config.routes_file)
                .context("the SPOE agent needs the route table [fareward].routes_file")?;
            let spoe_listener = server::bind_unix_socket(&spoe_config.socket_path)?;
            let agent = Agent::new(
                limiter.clone(),
                routes.clone(),
                Arc::new(config.secret_phrase.clone()),
                AgentLimits {
                    max_connections: spoe_config.max_connections,
                    max_inflight_per_connection: spoe_config.max_inflight_per_connection,
                    max_frame_size: spoe_config.max_frame_size,
                    shadow: spoe_config.shadow,
                },
            );
            info!(
                socket = %spoe_config.socket_path.display(),
                shadow = spoe_config.shadow,
                "spoe agent enabled"
            );
            Some((
                tokio::spawn(fareward::spoe::agent::run(
                    agent,
                    spoe_listener,
                    shutdown_receiver.clone(),
                )),
                tokio::spawn(routes.watch(spoe_config.routes_poll, shutdown_receiver.clone())),
            ))
        }
        None => None,
    };

    let flush_limiter = limiter.clone();
    let flush_interval = config.flush_interval;
    let mut flush_shutdown = shutdown_receiver.clone();
    let flush_task = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + flush_interval, flush_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = flush_shutdown.changed() => {
                    if changed.is_err() || *flush_shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let started = Instant::now();
                    let written = flush_limiter.flush_dirty().await;
                    info!(written, elapsed_ms = started.elapsed().as_millis(), "periodic flush finished");
                }
            }
        }
    });

    let server_task = tokio::spawn(server::run(
        listener,
        unix_listener,
        limiter.clone(),
        locks,
        internal_apikey.clone(),
        config.frame_timeout,
        config.max_connections,
        config.max_inflight_per_connection,
        shutdown_receiver.clone(),
    ));

    let bridge_state = Arc::new(BridgeState {
        registry: ChannelRegistry::new(),
        secret_phrase: config.secret_phrase,
        internal_apikey: config.internal_apikey,
        verbose_logs: config.bridge.verbose_logs,
        started_at: Instant::now(),
    });
    let mut bridge_shutdown = shutdown_receiver;
    let bridge_task = tokio::spawn(async move {
        info!(
            address = %config.bridge.listen_address,
            verbose = config.bridge.verbose_logs,
            "sse bridge listening"
        );
        // No request timeouts on this listener: every deadline here would kill a healthy
        // long-lived SSE stream. Dead connections surface as the keepalive write failing.
        axum::serve(bridge_listener, bridge::http::routes(bridge_state))
            .with_graceful_shutdown(async move {
                while !*bridge_shutdown.borrow_and_update() {
                    if bridge_shutdown.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
    });

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_sender.send(true);

    if let Err(join_error) = flush_task.await {
        error!(error = %join_error, "flush task failed");
    }
    // Awaited before the process exits so the window in progress gets its row written.
    if let Some(metrics_task) = metrics_task
        && let Err(join_error) = metrics_task.await
    {
        error!(error = %join_error, "server metrics task failed");
    }
    if let Err(bridge_error) = bridge_task.await.context("bridge task failed")? {
        error!(error = %bridge_error, "sse bridge stopped with an error");
    }
    server_task.await.context("server task failed")??;
    // Before the final flush: the agent charges through the same limiter.
    if let Some((agent_task, routes_task)) = spoe_tasks {
        let _ = agent_task.await;
        let _ = routes_task.await;
    }
    let written = limiter.flush_dirty().await;
    info!(written, "final usage flush finished");
    Ok(())
}
