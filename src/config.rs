//! Loads the daemon settings with environment-over-TOML precedence.

use std::{env, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use toml::{Table, Value};

use crate::{
    limiter::quota::{CreditLimits, LimitPolicy, ScopeLimits, Windows},
    lock::registry::LockLimits,
};

const DEFAULT_LISTEN_PORT: u16 = 14013;
const DEFAULT_FLUSH_SECONDS: u64 = 15;
/// How long a user's authorization grants stay cached. A grants push drops the cached grants of
/// the users it stores, so this is only a backstop that re-reads the store now and then.
const DEFAULT_ACCESS_CACHE_SECONDS: u64 = 600;
const DEFAULT_FRAME_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_MAX_CONNECTIONS: usize = 1_024;
/// Requests one connection may have in flight at once. With one request per socket the socket
/// itself was the ceiling; multiplexing removes that, so it has to be stated.
const DEFAULT_MAX_INFLIGHT_PER_CONNECTION: usize = 64;
const DEFAULT_LOCK_MAX_KEYS: usize = 100_000;
const DEFAULT_LOCK_MAX_TOTAL_WAITERS: u64 = 4_096;
/// The wire carries the lease as a `u16` of milliseconds, so no ceiling above 65_535 is
/// reachable in the first place.
const DEFAULT_LOCK_MAX_LEASE_MS: u64 = 60_000;

/// Keeps the bridge next to the other Genix services on the same hosts (14010 backend, 14013 this process's rate limiter).
const DEFAULT_BRIDGE_PORT: u16 = 14012;

/// One sub-sample a second, and the peak of five of them per row. Both mirror the Go side:
/// `ServerMetricSlotSeconds` in backend/core/types/server_metrics.go is 5, and the clustering key
/// of every stored row already means that. Changing `row_seconds` alone would leave the two sides
/// disagreeing about what slot 4 covers.
const DEFAULT_SERVER_METRICS_SAMPLE_SECONDS: u64 = 1;
const DEFAULT_SERVER_METRICS_ROW_SECONDS: u64 = 5;
/// A month of history. The first key column is the day, so it is purged whole.
const DEFAULT_SERVER_METRICS_TTL_DAYS: u64 = 30;
/// A row is 17280 slots a day of int16s, so the useful floor is set by the int16 key rather than by
/// storage: fewer than three seconds a slot overflows it.
const MINIMUM_SERVER_METRICS_ROW_SECONDS: u64 = 3;
const DEFAULT_SERVER_METRICS_BACKEND_UNIT: &str = "genix.service";
const DEFAULT_SERVER_METRICS_FAREWARD_UNIT: &str = "fareward.service";
/// The database's unit, sampled into the metrics' database columns.
const DEFAULT_SERVER_METRICS_DATABASE_UNIT: &str = "mariadb.service";

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub listen_address: SocketAddr,
    /// Optional Unix domain socket served next to the TCP listener, never instead of it: a Lambda
    /// backend can only reach the TCP port, while a backend on this same host skips the TCP/IP
    /// stack through the socket. Same frames, same handshake, same secret on both.
    pub unix_socket_path: Option<PathBuf>,
    pub flush_interval: Duration,
    pub frame_timeout: Duration,
    pub max_connections: usize,
    pub max_inflight_per_connection: usize,
    pub shard_count: usize,
    /// TTL of the cached `users.accesos_computed` grants the charge frame is authorized against.
    pub access_cache_seconds: i64,
    /// Signs the browser session tokens the SSE bridge verifies. Nothing else reads it.
    pub secret_phrase: Vec<u8>,
    /// Service-to-service secret: the rate limiter's TCP frame tag and the bridge's
    /// `X-Bridge-Auth` header. Distinct from `secret_phrase` so token signing and
    /// inter-service authentication can be rotated independently.
    pub internal_apikey: Vec<u8>,
    pub policy: LimitPolicy,
    /// Process-wide ceilings for the lock service. Per-action policy is deliberately absent:
    /// that belongs to the Go call sites, which is what keeps this service generic.
    pub locks: LockLimits,
    pub bridge: BridgeConfig,
    pub server_metrics: ServerMetricsConfig,
    /// The HAProxy SPOE agent; `None` unless `[spoe].socket` is set.
    pub spoe: Option<SpoeConfig>,
    /// `[store].path`: the directory of Fareward's own store (usage, budgets, server metrics).
    /// Local disk; it is the source of truth for those, so it is what a backup copies.
    pub store_path: PathBuf,
}

/// Where the store lives when `[store].path` is not set: the systemd StateDirectory convention.
pub const DEFAULT_STORE_PATH: &str = "/var/lib/fareward/store";

/// `[spoe]`: the agent HAProxy asks before reading a request body (plan phase 4).
#[derive(Clone, Debug)]
pub struct SpoeConfig {
    /// `[spoe].socket`: the Unix socket HAProxy connects to, its own and not the TCP protocol's.
    /// Access is the filesystem's (mode 0660), so it carries no frame tag.
    pub socket_path: PathBuf,
    /// `[fareward].routes_file`: the route table the backend writes at startup. One key read by
    /// both processes, so they cannot name two different files.
    pub routes_file: PathBuf,
    pub routes_poll: Duration,
    /// `[spoe].mode = "shadow"` (the default) evaluates without charging and the backend keeps
    /// deciding; `"enforce"` charges and HAProxy acts on the verdict. Enforcement has to be asked
    /// for: a missing key must never start refusing traffic.
    pub shadow: bool,
    pub max_connections: usize,
    pub max_inflight_per_connection: usize,
    pub max_frame_size: u32,
}

#[derive(Clone, Debug)]
pub struct ServerMetricsConfig {
    /// Off means no sampling loop at all: nothing calls into this, it only ticks.
    pub enabled: bool,
    pub sample_interval: Duration,
    /// Seconds per stored row, which is also what the clustering key counts. Kept as a number
    /// rather than a Duration because it is arithmetic on the key, not a delay.
    pub row_seconds: i64,
    /// Days of rows kept; older days are deleted by the writer's purge.
    pub retention_days: i16,
    pub disk_mount: String,
    /// Empty means the first interface that is not `lo`.
    pub network_interface: String,
    /// systemd units under `system.slice`. An absent one is not an error: the backend has no unit
    /// at all when it runs on Lambda, which is the case the `-1` sentinel exists for.
    pub backend_unit: String,
    pub fareward_unit: String,
    pub database_unit: String,
}

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    /// The SSE bridge's HTTP listener. Bound on all interfaces because nginx terminates TLS
    /// in front of it, matching the Go bridge this replaced.
    pub listen_address: SocketAddr,
    pub verbose_logs: bool,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let config = load_config()?;
        // [fareward] is its own section, not a key under [rate_limit]: this one port serves
        // every raw-TCP operation and the frame's opcode picks the service, so it belongs to the
        // process, not to one of the services running inside it.
        //
        // The bind address is DERIVED from `public` and never read from `host`, which is the
        // client's half of this section. Binding a literal host cannot work behind NAT — a cloud
        // VM's public IP is never on its NIC, so bind returns EADDRNOTAVAIL and the daemon dies at
        // startup. A boolean has no such unrepresentable state.
        let listen_port = optional_u64(&config, "FAREWARD_PORT", "fareward.port")?
            .unwrap_or(u64::from(DEFAULT_LISTEN_PORT));
        let listen_port = u16::try_from(listen_port)
            .ok()
            .filter(|port| *port > 0)
            .context("fareward.port must be a port number between 1 and 65535")?;
        let listen_octets = if optional_bool(&config, "FAREWARD_PUBLIC", "fareward.public") {
            [0, 0, 0, 0]
        } else {
            [127, 0, 0, 1]
        };
        let listen_address = SocketAddr::from((listen_octets, listen_port));
        let unix_socket_path =
            optional_string(&config, "FAREWARD_UNIX_SOCKET", "fareward.unix_socket")
                .map(PathBuf::from);
        let flush_seconds = optional_u64(
            &config,
            "RATE_LIMIT_FLUSH_SECONDS",
            "rate_limit.flush_seconds",
        )?
        .unwrap_or(DEFAULT_FLUSH_SECONDS);
        let frame_timeout_seconds = optional_u64(
            &config,
            "RATE_LIMIT_FRAME_TIMEOUT_SECONDS",
            "rate_limit.frame_timeout_seconds",
        )?
        .unwrap_or(DEFAULT_FRAME_TIMEOUT_SECONDS);
        let max_connections = optional_usize(
            &config,
            "RATE_LIMIT_MAX_CONNECTIONS",
            "rate_limit.max_connections",
        )?
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);
        let default_shards = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let configured_shards =
            optional_usize(&config, "RATE_LIMIT_SHARDS", "rate_limit.shards")?.unwrap_or(0);
        let shard_count = if configured_shards == 0 {
            default_shards
        } else {
            configured_shards
        };

        let max_inflight_per_connection = optional_usize(
            &config,
            "RATE_LIMIT_MAX_INFLIGHT_PER_CONNECTION",
            "rate_limit.max_inflight_per_connection",
        )?
        .unwrap_or(DEFAULT_MAX_INFLIGHT_PER_CONNECTION);
        let access_cache_seconds = optional_u64(
            &config,
            "RATE_LIMIT_ACCESS_CACHE_SECONDS",
            "rate_limit.access_cache_seconds",
        )?
        .unwrap_or(DEFAULT_ACCESS_CACHE_SECONDS);

        if flush_seconds == 0
            || frame_timeout_seconds == 0
            || max_connections == 0
            || max_inflight_per_connection == 0
            || access_cache_seconds == 0
        {
            bail!("rate-limiter durations and connection limits must be positive");
        }

        // Absent means zero means off, unlike the eight credit ceilings, which are required. The
        // asymmetry is deliberate: a missing quota is a configuration mistake worth refusing to
        // start over, while a missing free allowance is simply no free allowance.
        let policy = LimitPolicy {
            company: load_scope_limits(&config, "COMPANY", "company")?,
            user: load_scope_limits(&config, "USER", "user")?,
            company_extra_daily_cpu: optional_u64(
                &config,
                "RATE_LIMIT_COMPANY_EXTRA_CREDITS_24H",
                "rate_limit.company_extra_credits_24h",
            )?
            .unwrap_or(0),
            // Absent means the whole company allowance: a missing share is not a share of nothing,
            // and defaulting to anything below 100 would silently make part of every tenant's
            // purchased daily credit unreachable.
            user_daily_share_pct: optional_u64(
                &config,
                "RATE_LIMIT_USER_DAILY_SHARE_PCT",
                "rate_limit.user_daily_share_pct",
            )?
            .unwrap_or(100),
            // Off by default: turning it on drops every per-user gate, which is a policy decision
            // and not something a missing key should make.
            windows: load_windows(&config)?,
            disable_user_limit: optional_bool(
                &config,
                "RATE_LIMIT_DISABLE_USER_LIMIT",
                "rate_limit.disable_user_limit",
            ),
        };
        validate_policy(policy)?;

        let lock_max_keys = optional_usize(&config, "LOCK_MAX_KEYS", "lock.max_keys")?
            .unwrap_or(DEFAULT_LOCK_MAX_KEYS);
        let lock_max_total_waiters =
            optional_u64(&config, "LOCK_MAX_TOTAL_WAITERS", "lock.max_total_waiters")?
                .unwrap_or(DEFAULT_LOCK_MAX_TOTAL_WAITERS);
        let lock_max_lease_ms = optional_u64(&config, "LOCK_MAX_LEASE_MS", "lock.max_lease_ms")?
            .unwrap_or(DEFAULT_LOCK_MAX_LEASE_MS);
        if lock_max_keys == 0 || lock_max_total_waiters == 0 || lock_max_lease_ms == 0 {
            bail!("lock ceilings must be positive");
        }
        let locks = LockLimits {
            max_keys: lock_max_keys,
            max_total_waiters: u32::try_from(lock_max_total_waiters)
                .context("lock.max_total_waiters must fit in uint32")?,
            max_lease: Duration::from_millis(lock_max_lease_ms),
        };

        let server_metrics = load_server_metrics(&config)?;
        let spoe = load_spoe(&config)?;

        let bridge_port = optional_u64(&config, "SSE_BRIDGE_PORT", "sse_bridge.port")?
            .map(|port| u16::try_from(port).context("sse_bridge.port must be a valid TCP port"))
            .transpose()?
            .unwrap_or(DEFAULT_BRIDGE_PORT);
        if bridge_port == 0 {
            bail!("sse_bridge.port must be greater than zero");
        }

        Ok(Self {
            store_path: PathBuf::from(
                optional_string(&config, "FAREWARD_STORE_PATH", "store.path")
                    .filter(|path| !path.is_empty())
                    .unwrap_or_else(|| DEFAULT_STORE_PATH.to_owned()),
            ),
            listen_address,
            unix_socket_path,
            flush_interval: Duration::from_secs(flush_seconds),
            frame_timeout: Duration::from_secs(frame_timeout_seconds),
            max_connections,
            max_inflight_per_connection,
            shard_count,
            access_cache_seconds: access_cache_seconds as i64,
            secret_phrase: required_string(&config, "SECRET_PHRASE", "secret_phrase")?.into_bytes(),
            internal_apikey: required_string(&config, "INTERNAL_APIKEY", "internal_apikey")?
                .into_bytes(),
            bridge: BridgeConfig {
                listen_address: SocketAddr::from(([0, 0, 0, 0], bridge_port)),
                verbose_logs: optional_string(&config, "SSE_BRIDGE_VERBOSE", "sse_bridge.verbose")
                    .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true")),
            },
            policy,
            locks,
            server_metrics,
            spoe,
        })
    }
}

/// Every value defaults: a guessed sampling interval is a sampling
/// interval, not a guessed quota. An absent `[server_metrics]` section means "on, with these".
fn load_server_metrics(config: &Table) -> Result<ServerMetricsConfig> {
    let sample_seconds = optional_u64(
        config,
        "SERVER_METRICS_SAMPLE_SECONDS",
        "server_metrics.sample_seconds",
    )?
    .unwrap_or(DEFAULT_SERVER_METRICS_SAMPLE_SECONDS);
    let row_seconds = optional_u64(
        config,
        "SERVER_METRICS_ROW_SECONDS",
        "server_metrics.row_seconds",
    )?
    .unwrap_or(DEFAULT_SERVER_METRICS_ROW_SECONDS);
    let ttl_days = optional_u64(config, "SERVER_METRICS_TTL_DAYS", "server_metrics.ttl_days")?
        .unwrap_or(DEFAULT_SERVER_METRICS_TTL_DAYS);

    // row_seconds decides what the clustering key MEANS, so it is validated rather than trusted.
    // A value that does not divide the day leaves a short last slot whose peak covers a different
    // span than every other row; below three seconds the slot count overflows the int16 key.
    if sample_seconds == 0 || ttl_days == 0 {
        bail!("server_metrics.sample_seconds and ttl_days must be positive");
    }
    if row_seconds < MINIMUM_SERVER_METRICS_ROW_SECONDS || 86_400 % row_seconds != 0 {
        bail!(
            "server_metrics.row_seconds must divide 86400 evenly and be at least {MINIMUM_SERVER_METRICS_ROW_SECONDS}"
        );
    }
    if row_seconds % sample_seconds != 0 || sample_seconds > row_seconds {
        bail!("server_metrics.sample_seconds must divide server_metrics.row_seconds evenly");
    }
    // The purge compares against the int16 UnixDay key, so the retention must fit it too.
    let retention_days =
        i16::try_from(ttl_days).context("server_metrics.ttl_days must fit in int16")?;

    let unit_name = |env_key: &str, toml_path: &str, default: &str| {
        optional_string(config, env_key, toml_path).unwrap_or_else(|| default.to_owned())
    };

    Ok(ServerMetricsConfig {
        enabled: optional_string(config, "SERVER_METRICS_ENABLED", "server_metrics.enabled")
            .is_none_or(|value| value == "1" || value.eq_ignore_ascii_case("true")),
        sample_interval: Duration::from_secs(sample_seconds),
        row_seconds: row_seconds as i64,
        retention_days,
        disk_mount: optional_string(
            config,
            "SERVER_METRICS_DISK_MOUNT",
            "server_metrics.disk_mount",
        )
        .unwrap_or_else(|| "/".to_owned()),
        network_interface: optional_string(
            config,
            "SERVER_METRICS_NETWORK_INTERFACE",
            "server_metrics.network_interface",
        )
        .unwrap_or_default(),
        backend_unit: unit_name(
            "SERVER_METRICS_BACKEND_UNIT",
            "server_metrics.backend_unit",
            DEFAULT_SERVER_METRICS_BACKEND_UNIT,
        ),
        fareward_unit: unit_name(
            "SERVER_METRICS_FAREWARD_UNIT",
            "server_metrics.fareward_unit",
            DEFAULT_SERVER_METRICS_FAREWARD_UNIT,
        ),
        database_unit: unit_name(
            "SERVER_METRICS_DATABASE_UNIT",
            "server_metrics.database_unit",
            DEFAULT_SERVER_METRICS_DATABASE_UNIT,
        ),
    })
}

/// `rate_limit.short_window_seconds` and `rate_limit.long_window_minutes`. Absent means the windows
/// the daemon had before they were configurable, ten seconds and one hour, so a configuration that
/// predates them keeps its behaviour.
fn load_windows(config: &Table) -> Result<Windows> {
    let defaults = Windows::default();
    let windows = Windows {
        short_seconds: optional_u64(
            config,
            "RATE_LIMIT_SHORT_WINDOW_SECONDS",
            "rate_limit.short_window_seconds",
        )?
        .unwrap_or(defaults.short_seconds),
        long_minutes: optional_u64(
            config,
            "RATE_LIMIT_LONG_WINDOW_MINUTES",
            "rate_limit.long_window_minutes",
        )?
        .unwrap_or(defaults.long_minutes),
    };
    validate_windows(windows)?;
    Ok(windows)
}

fn validate_windows(windows: Windows) -> Result<()> {
    if windows.short_seconds == 0 {
        bail!("rate_limit.short_window_seconds must be greater than zero");
    }
    // Five-minute steps because a restart rebuilds the long window from the five-minute usage
    // rows; any other length would start or end in the middle of one.
    if windows.long_minutes == 0 || windows.long_minutes % 5 != 0 {
        bail!("rate_limit.long_window_minutes must be a positive multiple of 5");
    }
    // A long window past a day would outlive the daily entitlement it sits under; that is what
    // the daily gate is for.
    if windows.long_minutes > 24 * 60 {
        bail!("rate_limit.long_window_minutes must be at most 1440 (one day)");
    }
    if windows.short_seconds >= windows.long_minutes * 60 {
        bail!("rate_limit.short_window_seconds must be shorter than the long window");
    }
    Ok(())
}

fn load_scope_limits(config: &Table, env_scope: &str, toml_scope: &str) -> Result<ScopeLimits> {
    // Environment names stay flat while TOML values live in the grouped rate_limit section.
    let value = |env_credit, toml_credit, env_window, toml_window| {
        rate_limit_value(
            config,
            env_scope,
            toml_scope,
            env_credit,
            toml_credit,
            env_window,
            toml_window,
        )
    };
    Ok(ScopeLimits {
        cpu: CreditLimits {
            short: value("CPU", "cpu", "SHORT", "short")?,
            long: value("CPU", "cpu", "LONG", "long")?,
        },
        inference: CreditLimits {
            short: value("INFERENCE", "inference", "SHORT", "short")?,
            long: value("INFERENCE", "inference", "LONG", "long")?,
        },
    })
}

/// The credits per window, from `company_cpu_short` and the like.
fn rate_limit_value(
    config: &Table,
    env_scope: &str,
    toml_scope: &str,
    env_credit: &str,
    toml_credit: &str,
    env_window: &str,
    toml_window: &str,
) -> Result<u64> {
    required_u64(
        config,
        &format!("RATE_LIMIT_{env_scope}_{env_credit}_{env_window}"),
        &format!("rate_limit.{toml_scope}_{toml_credit}_{toml_window}"),
    )
}

fn validate_policy(policy: LimitPolicy) -> Result<()> {
    for (scope_name, scope) in [("company", policy.company), ("user", policy.user)] {
        for (credit_name, limits) in [("cpu", scope.cpu), ("inference", scope.inference)] {
            if limits.short == 0 {
                bail!("rate_limit.{scope_name}_{credit_name} limits must be positive");
            }
            if limits.short > limits.long {
                bail!(
                    "rate_limit.{scope_name}_{credit_name} limits must be nondecreasing from the short to the long window"
                );
            }
        }
    }
    // No ordering rule against the long-window ceilings: this is a different axis, not a longer window.
    // The only bound is the int64 column the counter is flushed to.
    if policy.company_extra_daily_cpu > i64::MAX as u64 {
        bail!("rate_limit.company_extra_credits_24h must fit a signed 64-bit database column");
    }
    // Zero would refuse every charge for every user while the company still had credit, and past 100
    // the per-user gate would sit above the company's own and could never be the one to refuse.
    if policy.user_daily_share_pct == 0 || policy.user_daily_share_pct > 100 {
        bail!("rate_limit.user_daily_share_pct must be between 1 and 100");
    }
    Ok(())
}

fn load_config() -> Result<Table> {
    let explicit_path = env::var("GENIX_CONFIG_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let mut candidates = Vec::new();
    if let Some(path) = explicit_path {
        candidates.push(path);
    }
    candidates.push(PathBuf::from("../config.toml"));
    candidates.push(PathBuf::from("config.toml"));

    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let mut config = read_config_table(&path)?;
        // config.local.toml next to config.toml holds what only this host differs in; the Go
        // backend (core/config_local.go) and the configure scripts apply it with the same rule.
        let local_path = path.with_file_name(LOCAL_CONFIG_FILE_NAME);
        if local_path.is_file() {
            merge_config_override(&mut config, read_config_table(&local_path)?);
        }
        return Ok(config);
    }

    // An empty table still permits an environment-only deployment.
    Ok(Table::new())
}

/// The per-host override that sits next to config.toml. See merge_config_override.
const LOCAL_CONFIG_FILE_NAME: &str = "config.local.toml";

fn read_config_table(path: &std::path::Path) -> Result<Table> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let value: Value =
        toml::from_str(&text).with_context(|| format!("invalid TOML in {}", path.display()))?;
    value
        .as_table()
        .cloned()
        .with_context(|| format!("{} must contain a TOML table", path.display()))
}

/// Lays the override over the base config. A table present in both merges key by key, recursively;
/// any other value — scalar, array, or array of tables — replaces the base value whole.
fn merge_config_override(base: &mut Table, override_config: Table) {
    for (key, override_value) in override_config {
        match (base.get_mut(&key), override_value) {
            (Some(Value::Table(base_table)), Value::Table(override_table)) => {
                merge_config_override(base_table, override_table)
            }
            (_, override_value) => {
                base.insert(key, override_value);
            }
        }
    }
}

fn value_text(config: &Table, env_key: &str, toml_path: &str) -> Option<String> {
    if let Ok(value) = env::var(env_key)
        && !value.trim().is_empty()
    {
        return Some(value.trim().to_owned());
    }
    match value_at_path(config, toml_path) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Some(Value::Integer(value)) => Some(value.to_string()),
        Some(Value::Float(value)) => Some(value.to_string()),
        Some(Value::Boolean(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn value_at_path<'a>(config: &'a Table, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = config.get(parts.next()?)?;
    for part in parts {
        value = value.as_table()?.get(part)?;
    }
    Some(value)
}

fn optional_string(config: &Table, env_key: &str, toml_path: &str) -> Option<String> {
    value_text(config, env_key, toml_path)
}

fn load_spoe(config: &Table) -> Result<Option<SpoeConfig>> {
    let Some(socket) = optional_string(config, "FAREWARD_SPOE_SOCKET", "spoe.socket")
        .filter(|path| !path.is_empty())
    else {
        return Ok(None);
    };
    let routes_file = optional_string(config, "FAREWARD_ROUTES_FILE", "fareward.routes_file")
        .filter(|path| !path.is_empty())
        .context("[spoe].socket is set, so [fareward].routes_file must name the route table")?;
    let shadow = match optional_string(config, "FAREWARD_SPOE_MODE", "spoe.mode").as_deref() {
        None | Some("shadow") => true,
        Some("enforce") => false,
        Some(other) => bail!("spoe.mode must be \"shadow\" or \"enforce\", not {other:?}"),
    };
    let positive = |value: Option<usize>, default: usize, name: &str| -> Result<usize> {
        let value = value.unwrap_or(default);
        if value == 0 {
            bail!("{name} must be positive");
        }
        Ok(value)
    };
    let max_frame_size = optional_u64(
        config,
        "FAREWARD_SPOE_MAX_FRAME_SIZE",
        "spoe.max_frame_size",
    )?
    .unwrap_or(16_384);
    // HAProxy's own floor and its tune.bufsize ceiling; outside them the handshake cannot agree.
    if !(256..=1_048_576).contains(&max_frame_size) {
        bail!("spoe.max_frame_size must be between 256 and 1048576");
    }
    Ok(Some(SpoeConfig {
        socket_path: PathBuf::from(socket),
        routes_file: PathBuf::from(routes_file),
        routes_poll: Duration::from_millis(
            optional_u64(
                config,
                "FAREWARD_SPOE_ROUTES_POLL_MS",
                "spoe.routes_poll_ms",
            )?
            .unwrap_or(2_000)
            .max(100),
        ),
        shadow,
        max_connections: positive(
            optional_usize(
                config,
                "FAREWARD_SPOE_MAX_CONNECTIONS",
                "spoe.max_connections",
            )?,
            64,
            "spoe.max_connections",
        )?,
        max_inflight_per_connection: positive(
            optional_usize(
                config,
                "FAREWARD_SPOE_MAX_INFLIGHT",
                "spoe.max_inflight_per_connection",
            )?,
            256,
            "spoe.max_inflight_per_connection",
        )?,
        max_frame_size: max_frame_size as u32,
    }))
}

/// Absent reads as false, and "1" is accepted next to "true" so an environment override can be
/// written either way.
fn optional_bool(config: &Table, env_key: &str, toml_path: &str) -> bool {
    value_text(config, env_key, toml_path)
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn required_string(config: &Table, env_key: &str, toml_path: &str) -> Result<String> {
    value_text(config, env_key, toml_path)
        .with_context(|| format!("missing required setting {toml_path} (environment: {env_key})"))
}

fn optional_u64(config: &Table, env_key: &str, toml_path: &str) -> Result<Option<u64>> {
    value_text(config, env_key, toml_path)
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("{toml_path}/{env_key} must be an unsigned integer"))
        })
        .transpose()
}

fn required_u64(config: &Table, env_key: &str, toml_path: &str) -> Result<u64> {
    let value = optional_u64(config, env_key, toml_path)?.with_context(|| {
        format!("missing required setting {toml_path} (environment: {env_key})")
    })?;
    if value == 0 {
        bail!("{toml_path}/{env_key} must be greater than zero");
    }
    Ok(value)
}

fn optional_usize(config: &Table, env_key: &str, toml_path: &str) -> Result<Option<usize>> {
    optional_u64(config, env_key, toml_path)?
        .map(|value| {
            usize::try_from(value).with_context(|| format!("{toml_path}/{env_key} is too large"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_override_merges_tables_and_replaces_arrays() {
        let mut config: Table = toml::from_str(
            "[fareward]\nport = 14013\npublic = true\n[[models]]\nid = 'a'\n[[models]]\nid = 'b'",
        )
        .unwrap();
        let local: Table =
            toml::from_str("[fareward]\npublic = false\n[[models]]\nid = 'c'").unwrap();
        merge_config_override(&mut config, local);

        assert_eq!(
            optional_u64(&config, "IGNORED_PORT", "fareward.port").unwrap(),
            Some(14013)
        );
        assert_eq!(config["fareward"]["public"].as_bool(), Some(false));
        let models = config["models"].as_array().unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["id"].as_str(), Some("c"));
    }

    #[test]
    fn nested_numeric_and_string_values_are_accepted() {
        // TOML integers and quoted values both support deployment templating.
        let config: Table = toml::from_str("[test]\na = 42\nb = '43'").unwrap();
        assert_eq!(
            optional_u64(&config, "IGNORED_A", "test.a").unwrap(),
            Some(42)
        );
        assert_eq!(
            optional_u64(&config, "IGNORED_B", "test.b").unwrap(),
            Some(43)
        );
    }

    #[test]
    fn a_toml_boolean_is_read_as_a_flag() {
        // `public = true` is a real TOML boolean, not a quoted one: value_text has to decode that
        // arm or the daemon silently keeps binding loopback and the off-box backend never connects.
        let config: Table = toml::from_str("[fareward]\npublic = true").unwrap();
        assert!(optional_bool(&config, "IGNORED", "fareward.public"));

        let private: Table = toml::from_str("[fareward]\nport = 14013").unwrap();
        assert!(!optional_bool(&private, "IGNORED", "fareward.public"));
    }

    /// The section is optional, and its defaults are what the nested deployment scripts under
    /// `scripts/configure/` actually produce.
    #[test]
    fn server_metrics_defaults_to_the_installed_unit_names() {
        let metrics = load_server_metrics(&Table::new()).unwrap();
        assert!(metrics.enabled);
        assert_eq!(metrics.row_seconds, 5);
        assert_eq!(metrics.sample_interval, Duration::from_secs(1));
        assert_eq!(metrics.backend_unit, "genix.service");
        assert_eq!(metrics.database_unit, "mariadb.service");
        assert_eq!(metrics.retention_days, 30);
        assert!(metrics.network_interface.is_empty());
    }

    /// row_seconds is the meaning of the clustering key, so the values that would corrupt it are
    /// refused at startup rather than discovered as a day with a strange last row.
    #[test]
    fn a_row_width_that_does_not_divide_the_day_is_rejected() {
        let uneven: Table = toml::from_str("[server_metrics]\nrow_seconds = 7").unwrap();
        assert!(load_server_metrics(&uneven).is_err());

        // Under three seconds the 17280-slot key stops fitting an int16.
        let too_fine: Table = toml::from_str("[server_metrics]\nrow_seconds = 2").unwrap();
        assert!(load_server_metrics(&too_fine).is_err());

        // A sub-sample longer than the window it feeds would leave rows with no samples at all.
        let mismatched: Table =
            toml::from_str("[server_metrics]\nrow_seconds = 5\nsample_seconds = 2").unwrap();
        assert!(load_server_metrics(&mismatched).is_err());

        let valid: Table =
            toml::from_str("[server_metrics]\nrow_seconds = 10\nsample_seconds = 5").unwrap();
        assert_eq!(load_server_metrics(&valid).unwrap().row_seconds, 10);
    }

    #[test]
    fn zero_credit_limits_are_rejected() {
        let positive = CreditLimits { short: 1, long: 1 };
        let policy = LimitPolicy {
            company: ScopeLimits {
                cpu: CreditLimits {
                    short: 0,
                    ..positive
                },
                inference: positive,
            },
            user: ScopeLimits {
                cpu: positive,
                inference: positive,
            },
            company_extra_daily_cpu: 0,
            user_daily_share_pct: 100,
            disable_user_limit: false,
            windows: Windows::default(),
        };

        assert!(validate_policy(policy).is_err());
    }

    #[test]
    fn an_extra_daily_pool_beyond_int64_is_rejected() {
        let positive = CreditLimits { short: 1, long: 1 };
        let scope = ScopeLimits {
            cpu: positive,
            inference: positive,
        };
        // The counter that tracks this pool is persisted in an int64 column, so a ceiling above it
        // could never be enforced after a restart.
        let policy = LimitPolicy {
            company: scope,
            user: scope,
            company_extra_daily_cpu: i64::MAX as u64 + 1,
            user_daily_share_pct: 100,
            disable_user_limit: false,
            windows: Windows::default(),
        };
        assert!(validate_policy(policy).is_err());

        let usable = LimitPolicy {
            company_extra_daily_cpu: 50_000,
            ..policy
        };
        assert!(validate_policy(usable).is_ok());
    }

    #[test]
    fn absent_windows_keep_ten_seconds_and_one_hour() {
        assert_eq!(load_windows(&Table::new()).unwrap(), Windows::default());
        let configured: Table =
            toml::from_str("[rate_limit]\nshort_window_seconds = 10\nlong_window_minutes = 10")
                .unwrap();
        assert_eq!(
            load_windows(&configured).unwrap(),
            Windows {
                short_seconds: 10,
                long_minutes: 10,
            }
        );
    }

    #[test]
    fn the_long_window_steps_by_five_minutes_and_outlasts_the_short_one() {
        let windows = |toml: &str| load_windows(&toml::from_str(toml).unwrap());
        assert!(windows("[rate_limit]\nlong_window_minutes = 7").is_err());
        assert!(windows("[rate_limit]\nlong_window_minutes = 0").is_err());
        assert!(windows("[rate_limit]\nlong_window_minutes = 1445").is_err());
        assert!(windows("[rate_limit]\nshort_window_seconds = 0").is_err());
        assert!(
            windows("[rate_limit]\nshort_window_seconds = 300\nlong_window_minutes = 5").is_err()
        );
        assert!(windows("[rate_limit]\nlong_window_minutes = 15").is_ok());
    }

    /// `_short`/`_long` are the only names: the `_10s`/`_1h` ones are not read at all.
    #[test]
    fn window_limits_are_read_under_their_short_and_long_names() {
        let configured: Table = toml::from_str(
            "[rate_limit]\ncompany_cpu_short = 5\ncompany_cpu_long = 50\n\
             company_inference_short = 6\ncompany_inference_long = 60",
        )
        .unwrap();
        let limits = load_scope_limits(&configured, "COMPANY", "company").unwrap();
        assert_eq!((limits.cpu.short, limits.cpu.long), (5, 50));
        assert_eq!((limits.inference.short, limits.inference.long), (6, 60));

        let old_names: Table = toml::from_str(
            "[rate_limit]\ncompany_cpu_10s = 5\ncompany_cpu_1h = 50\n\
             company_inference_10s = 6\ncompany_inference_1h = 60",
        )
        .unwrap();
        assert!(load_scope_limits(&old_names, "COMPANY", "company").is_err());
        assert!(load_scope_limits(&Table::new(), "COMPANY", "company").is_err());
    }

    #[test]
    fn the_user_daily_share_must_stay_inside_one_to_a_hundred() {
        let positive = CreditLimits { short: 1, long: 1 };
        let scope = ScopeLimits {
            cpu: positive,
            inference: positive,
        };
        let policy = LimitPolicy {
            company: scope,
            user: scope,
            company_extra_daily_cpu: 0,
            user_daily_share_pct: 80,
            disable_user_limit: false,
            windows: Windows::default(),
        };
        assert!(validate_policy(policy).is_ok());
        // Zero refuses every user of a company that still has credit; past 100 the gate can never be
        // the one that refuses.
        for invalid_share in [0, 101] {
            assert!(
                validate_policy(LimitPolicy {
                    user_daily_share_pct: invalid_share,
                    ..policy
                })
                .is_err()
            );
        }
    }
}
