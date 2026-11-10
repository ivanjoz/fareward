//! Per-company cap on distinct clients: how many (IP, device) pairs one company may use in the short
//! and in the long window, and the five-minute activity of those pairs.
//!
//! A *device* is the browser signature the frontend packs into an int64 and appends to the session
//! token. It is not a secret and not an identity: the client can send anything. That is the point.
//! A caller rotating signatures (or addresses) makes every request a new pair, the company runs out
//! of pairs within the window, and the rotating caller is refused while the pairs that were already
//! active keep working, because a refused pair is never admitted into the set.
//!
//! The windows are sliding and exact: each pair remembers when it was last served, and a window's
//! count is the pairs served within that many seconds of now. That set never holds more pairs than
//! the long cap admits (plus the expired ones the flush has not pruned yet), whatever the client
//! sends.
//!
//! Activity is tallied per five-minute frame, and the flush keeps only the frame's busiest
//! `TOP_DEVICES` pairs plus the number of refusals, in `usage_device`.

use std::{
    collections::{BTreeMap, HashMap},
    net::Ipv6Addr,
    time::{Duration, Instant},
};

use crate::limiter::{block::Until, protocol::Window, quota::Windows};

/// How many pairs a five-minute row keeps, by request count.
pub const TOP_DEVICES: usize = 12;

/// Pairs one company's five-minute tally tracks at most. Only reachable with the cap turned off, or
/// above it: with the cap on, a frame cannot see more pairs than the cap admits. Past it a new pair
/// is still served, it just does not enter the tally.
const MAX_TRACKED_PER_FRAME: usize = 1_024;

/// One client: the address the request came from and the signature it sent. IPv4 is held mapped
/// into IPv6 so both families share one key and one stored layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Client {
    pub ip: Ipv6Addr,
    /// The browser signature, 0 when the token carried none or an unreadable one.
    pub device: i64,
}

/// `rate_limit.max_devices_short` / `max_devices_long`: distinct pairs per company per window. Zero
/// turns that window's cap off; both zero turns the gate off, and only the tally remains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceLimits {
    pub short: u32,
    pub long: u32,
}

impl DeviceLimits {
    pub fn enabled(&self) -> bool {
        self.short > 0 || self.long > 0
    }
}

/// The device gate's refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceViolation {
    pub window: Window,
    /// Distinct pairs the company already used in that window.
    pub seen: u32,
    /// Seconds until the oldest of those pairs leaves the window, with the usual one-second margin.
    pub retry_after: u64,
}

/// What one pair did in one five-minute frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceUsage {
    pub requests: u32,
    pub cpu: u64,
}

impl DeviceUsage {
    fn add(&mut self, other: DeviceUsage) {
        self.requests = self.requests.saturating_add(other.requests);
        self.cpu = self.cpu.saturating_add(other.cpu);
    }
}

/// One `usage_device` row: a company's five-minute frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredDevices {
    /// Requests the device gate refused in the frame.
    pub rejected: u32,
    /// Distinct pairs served in the frame, all of them and not only the ones in `top`. Capped at
    /// the pairs one frame tracks (1024).
    pub distinct: u32,
    /// The busiest pairs, most requests first, at most `TOP_DEVICES`.
    pub top: Vec<(Client, DeviceUsage)>,
}

/// A frame's tally, versioned like every other record the flush writes: a write that completes
/// after a concurrent request must not mark the newer figure as durable.
#[derive(Debug, Default)]
struct FrameTally {
    usage: HashMap<Client, DeviceUsage>,
    rejected: u32,
    /// `distinct` as a previous process stored it. That process's pairs outside its top are not
    /// known here, so after a restart the frame reports the larger of the two counts.
    stored_distinct: u32,
    /// False until the row a previous process may have written for this frame has been added in.
    seeded: bool,
    version: u64,
    flushed_version: u64,
}

impl FrameTally {
    fn touch(&mut self) {
        self.version = self.version.wrapping_add(1);
    }

    fn top(&self) -> StoredDevices {
        let mut ranked: Vec<(Client, DeviceUsage)> =
            self.usage.iter().map(|(&c, &u)| (c, u)).collect();
        // Requests first, then CPU, then the key, so equal tallies rank the same on every flush.
        ranked.sort_by(|(a_client, a), (b_client, b)| {
            b.requests
                .cmp(&a.requests)
                .then(b.cpu.cmp(&a.cpu))
                .then(a_client.cmp(b_client))
        });
        let distinct = u32::try_from(ranked.len())
            .unwrap_or(u32::MAX)
            .max(self.stored_distinct);
        ranked.truncate(TOP_DEVICES);
        StoredDevices {
            rejected: self.rejected,
            distinct,
            top: ranked,
        }
    }
}

/// A company's pairs: when each was last served (the gate) and the per-frame tallies (the flush).
#[derive(Debug, Default)]
pub struct CompanyDevices {
    last_seen: HashMap<Client, Instant>,
    frames: BTreeMap<i32, FrameTally>,
}

impl CompanyDevices {
    /// `None` when `client` may be served. A pair already active in a window does not count against
    /// that window again; a new one is refused once the window holds the cap.
    pub fn check(
        &self,
        client: Client,
        limits: DeviceLimits,
        windows: Windows,
        unix_seconds: i64,
        now: Instant,
    ) -> Option<DeviceViolation> {
        let last = self.last_seen.get(&client).copied();
        let long = Duration::from_secs(windows.long_minutes.saturating_mul(60));
        // Shortest window first, matching the credit gates.
        for (window, cap, length) in [
            (Window::Short, limits.short, windows.short()),
            (Window::Long, limits.long, long),
        ] {
            if cap == 0 || last.is_some_and(|seen| within(seen, now, length)) {
                continue;
            }
            let mut seen = 0_u32;
            let mut oldest = now;
            for &served in self.last_seen.values() {
                if within(served, now, length) {
                    seen += 1;
                    oldest = oldest.min(served);
                }
            }
            if seen >= cap {
                return Some(DeviceViolation {
                    window,
                    seen,
                    retry_after: Until::Monotonic(oldest + length).retry_after(unix_seconds, now),
                });
            }
        }
        None
    }

    /// A served request: refreshes the pair's place in the windows (only when the gate is on, the
    /// only reader of it) and adds the request to the frame's tally.
    pub fn record(
        &mut self,
        client: Client,
        cpu: u64,
        time_frame: i32,
        gate_enabled: bool,
        now: Instant,
    ) {
        if gate_enabled {
            self.last_seen.insert(client, now);
        }
        let tally = self.frames.entry(time_frame).or_default();
        let tracked = tally.usage.contains_key(&client);
        if tracked || tally.usage.len() < MAX_TRACKED_PER_FRAME {
            tally
                .usage
                .entry(client)
                .or_default()
                .add(DeviceUsage { requests: 1, cpu });
            tally.touch();
        }
    }

    pub fn record_refusal(&mut self, time_frame: i32) {
        let tally = self.frames.entry(time_frame).or_default();
        tally.rejected = tally.rejected.saturating_add(1);
        tally.touch();
    }

    /// Frames with something to write whose stored row has not been read yet.
    pub fn unseeded(&self) -> impl Iterator<Item = i32> + '_ {
        self.frames
            .iter()
            .filter(|(_, tally)| !tally.seeded && tally.version != tally.flushed_version)
            .map(|(&frame, _)| frame)
    }

    /// Adds the row a previous process wrote for `time_frame`. Its pairs were that process's top
    /// only, so the merged figures are a lower bound for any pair outside it, which is as good as a
    /// restart lets them be.
    pub fn seed(&mut self, time_frame: i32, stored: Option<StoredDevices>) {
        let Some(tally) = self.frames.get_mut(&time_frame) else {
            return;
        };
        if tally.seeded {
            return;
        }
        tally.seeded = true;
        if let Some(stored) = stored {
            tally.rejected = tally.rejected.saturating_add(stored.rejected);
            tally.stored_distinct = stored.distinct;
            for (client, usage) in stored.top {
                tally.usage.entry(client).or_default().add(usage);
            }
            tally.touch();
        }
    }

    /// The rows to write: every seeded frame changed since its last successful write.
    pub fn dirty(&self) -> Vec<(i32, StoredDevices, u64)> {
        self.frames
            .iter()
            .filter(|(_, tally)| tally.seeded && tally.version != tally.flushed_version)
            .map(|(&frame, tally)| (frame, tally.top(), tally.version))
            .collect()
    }

    pub fn mark_flushed(&mut self, time_frame: i32, version: u64) {
        if let Some(tally) = self.frames.get_mut(&time_frame)
            && tally.version == version
        {
            tally.flushed_version = version;
        }
    }

    /// Drops the pairs that left the long window and the written frames other than the current
    /// one. True when nothing is left and the company can be forgotten.
    pub fn prune(&mut self, windows: Windows, current_frame: i32, now: Instant) -> bool {
        let long = Duration::from_secs(windows.long_minutes.saturating_mul(60));
        self.last_seen
            .retain(|_, &mut served| within(served, now, long));
        self.frames.retain(|&frame, tally| {
            frame == current_frame || tally.version != tally.flushed_version
        });
        self.last_seen.is_empty() && self.frames.is_empty()
    }
}

/// Whether `served` is less than `length` before `now`.
fn within(served: Instant, now: Instant, length: Duration) -> bool {
    now.saturating_duration_since(served) < length
}

/// The signature appended to a session token as `<token>.<signature>`, in decimal. Signed int64,
/// or its unsigned reading, since a JavaScript `BigInt` packed with shifts is naturally unsigned.
/// Anything else, including no suffix at all, is 0: the unknown device of that address.
pub fn parse_signature(text: &str) -> i64 {
    let text = text.trim();
    text.parse::<i64>()
        .or_else(|_| text.parse::<u64>().map(|unsigned| unsigned as i64))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOWS: Windows = Windows {
        short_seconds: 10,
        long_minutes: 10,
    };
    const LIMITS: DeviceLimits = DeviceLimits { short: 2, long: 3 };
    const FRAME: i32 = 100_000_001;

    fn client(device: i64) -> Client {
        Client {
            ip: Ipv6Addr::LOCALHOST,
            device,
        }
    }

    fn serve(devices: &mut CompanyDevices, device: i64, now: Instant) -> Option<DeviceViolation> {
        let refusal = devices.check(client(device), LIMITS, WINDOWS, 0, now);
        match refusal {
            None => devices.record(client(device), 5, FRAME, true, now),
            Some(_) => devices.record_refusal(FRAME),
        }
        refusal
    }

    #[test]
    fn a_new_pair_past_the_short_cap_is_refused_and_known_pairs_keep_working() {
        let start = Instant::now();
        let mut devices = CompanyDevices::default();
        assert_eq!(serve(&mut devices, 1, start), None);
        assert_eq!(serve(&mut devices, 2, start), None);
        let refusal = serve(&mut devices, 3, start).expect("third pair in ten seconds");
        assert_eq!(refusal.window, Window::Short);
        assert_eq!(refusal.seen, 2);
        assert_eq!(refusal.retry_after, 11);
        // The pairs already admitted are not new: they pass however often they come back.
        assert_eq!(serve(&mut devices, 1, start), None);
        assert_eq!(serve(&mut devices, 2, start), None);
    }

    #[test]
    fn the_long_window_caps_pairs_that_the_short_one_already_forgot() {
        let start = Instant::now();
        let mut devices = CompanyDevices::default();
        assert_eq!(serve(&mut devices, 1, start), None);
        assert_eq!(serve(&mut devices, 2, start), None);
        let later = start + Duration::from_secs(11);
        assert_eq!(serve(&mut devices, 3, later), None);
        let refusal = serve(&mut devices, 4, later).expect("fourth pair in ten minutes");
        assert_eq!(refusal.window, Window::Long);
        assert_eq!(refusal.seen, 3);
        // A pair the long window still holds comes back into the short one without counting anew.
        assert_eq!(serve(&mut devices, 1, later), None);
        // Once the first pairs leave the long window there is room again.
        let much_later = start + Duration::from_secs(601);
        assert_eq!(serve(&mut devices, 4, much_later), None);
    }

    #[test]
    fn a_rotating_caller_never_grows_the_set() {
        let start = Instant::now();
        let mut devices = CompanyDevices::default();
        for device in 0..1_000 {
            serve(&mut devices, device, start);
        }
        assert_eq!(devices.last_seen.len(), 2);
        let row = &devices.frames[&FRAME];
        assert_eq!(row.rejected, 998);
        assert_eq!(row.usage.len(), 2);
    }

    #[test]
    fn the_row_keeps_the_busiest_twelve_by_requests() {
        let now = Instant::now();
        let mut devices = CompanyDevices::default();
        for device in 0..20_i64 {
            for _ in 0..=device {
                devices.record(client(device), 1, FRAME, false, now);
            }
        }
        devices.seed(FRAME, None);
        let dirty = devices.dirty();
        assert_eq!(dirty.len(), 1);
        let (_, row, version) = &dirty[0];
        assert_eq!(row.top.len(), TOP_DEVICES);
        assert_eq!(row.top[0].0.device, 19);
        assert_eq!(row.top[0].1.requests, 20);
        assert_eq!(row.top[11].0.device, 8);
        // Every pair counts as distinct, not only the twelve kept.
        assert_eq!(row.distinct, 20);
        devices.mark_flushed(FRAME, *version);
        assert!(devices.dirty().is_empty());
    }

    #[test]
    fn a_previous_process_row_is_added_once() {
        let now = Instant::now();
        let mut devices = CompanyDevices::default();
        devices.record(client(7), 3, FRAME, false, now);
        assert_eq!(devices.unseeded().collect::<Vec<_>>(), vec![FRAME]);
        // Not written before it is seeded: it would overwrite the stored row with a partial one.
        assert!(devices.dirty().is_empty());
        let stored = StoredDevices {
            rejected: 4,
            distinct: 15,
            top: vec![(
                client(7),
                DeviceUsage {
                    requests: 10,
                    cpu: 30,
                },
            )],
        };
        devices.seed(FRAME, Some(stored.clone()));
        devices.seed(FRAME, Some(stored));
        let (_, row, _) = &devices.dirty()[0];
        assert_eq!(row.rejected, 4);
        // The previous process saw fifteen pairs; only one of them is known here.
        assert_eq!(row.distinct, 15);
        assert_eq!(
            row.top[0].1,
            DeviceUsage {
                requests: 11,
                cpu: 33
            }
        );
    }

    #[test]
    fn prune_forgets_expired_pairs_and_written_frames() {
        let start = Instant::now();
        let mut devices = CompanyDevices::default();
        devices.record(client(1), 1, FRAME, true, start);
        devices.seed(FRAME, None);
        let (_, _, version) = devices.dirty()[0].clone();
        devices.mark_flushed(FRAME, version);
        // Dirty frames survive; the current frame survives; the pair survives inside the window.
        assert!(!devices.prune(WINDOWS, FRAME, start));
        assert!(devices.prune(WINDOWS, FRAME + 1, start + Duration::from_secs(600)));
    }

    #[test]
    fn signatures_parse_signed_unsigned_or_fall_back_to_zero() {
        assert_eq!(parse_signature("1311"), 1311);
        assert_eq!(parse_signature("-5"), -5);
        assert_eq!(parse_signature("18446744073709551615"), -1);
        assert_eq!(parse_signature(""), 0);
        assert_eq!(parse_signature("abc"), 0);
    }
}
