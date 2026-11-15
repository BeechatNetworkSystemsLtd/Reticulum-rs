use alloc::collections::BTreeMap;
use std::collections::VecDeque;

use tokio::time::Duration;
use tokio::time::Instant;

use crate::hash::AddressHash;

/// Python `Transport.MAX_RATE_TIMESTAMPS`.
const MAX_RATE_TIMESTAMPS: usize = 16;

/// One rate-table row: destination, violations, block remaining, age, timestamps.
type RateSnapshot = (AddressHash, u32, Option<Duration>, Duration, Vec<f64>);

pub struct AnnounceRateLimit {
    pub target: Duration,
    pub grace: u32,
    pub penalty: Option<Duration>,
}

impl Default for AnnounceRateLimit {
    fn default() -> Self {
        Self {
            target: Duration::from_secs(3600),
            grace: 10,
            penalty: Some(Duration::from_secs(7200)),
        }
    }
}

struct AnnounceLimitEntry {
    rate_limit: Option<AnnounceRateLimit>,
    violations: u32,
    last_announce: Instant,
    blocked_until: Instant,
    /// Announce unix times, oldest first, capped at [`MAX_RATE_TIMESTAMPS`].
    timestamps: VecDeque<f64>,
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

impl AnnounceLimitEntry {
    pub fn new(rate_limit: Option<AnnounceRateLimit>) -> Self {
        let mut timestamps = VecDeque::new();
        timestamps.push_back(unix_now());
        Self {
            rate_limit,
            violations: 0,
            last_announce: Instant::now(),
            blocked_until: Instant::now(),
            timestamps,
        }
    }

    fn record_announce_time(&mut self) {
        self.timestamps.push_back(unix_now());
        while self.timestamps.len() > MAX_RATE_TIMESTAMPS {
            self.timestamps.pop_front();
        }
    }

    pub fn handle_announce(&mut self) -> Option<Duration> {
        let mut is_blocked = false;
        let now = Instant::now();

        if let Some(ref rate_limit) = self.rate_limit {
            if now < self.blocked_until {
                self.blocked_until = now + rate_limit.target;
                if let Some(penalty) = rate_limit.penalty {
                    self.blocked_until += penalty;
                }
                is_blocked = true;
            } else {
                let next_allowed = self.last_announce + rate_limit.target;
                if now < next_allowed {
                    self.violations += 1;
                    // Python blocks when violations exceed grace (`>`), so a
                    // grace of N still allows the Nth fast announce.
                    if self.violations > rate_limit.grace {
                        self.violations = 0;
                        self.blocked_until = now + rate_limit.target;
                        is_blocked = true;
                    }
                }
            }
        }

        self.last_announce = now;
        self.record_announce_time();

        if is_blocked {
            Some(self.blocked_until - now)
        } else {
            None
        }
    }
}

pub struct AnnounceLimits {
    limits: BTreeMap<AddressHash, AnnounceLimitEntry>,
}

impl AnnounceLimits {
    pub fn new() -> Self {
        Self {
            limits: BTreeMap::new(),
        }
    }

    pub fn check(&mut self, destination: &AddressHash) -> Option<Duration> {
        self.apply(destination, None)
    }

    /// Like [`Self::check`], storing `limit` as this destination's rate
    /// before the check. Callers pass the receiving interface's rate.
    pub fn check_limited(
        &mut self,
        destination: &AddressHash,
        limit: AnnounceRateLimit,
    ) -> Option<Duration> {
        self.apply(destination, Some(limit))
    }

    /// `Some` stores that rate and then checks. `None` drops any rate
    /// another interface stored for `destination` before the check, so an
    /// interface with no target does not keep or consult it. A missing
    /// entry is inserted with `limit` (`None` is not
    /// [`AnnounceRateLimit::default`]).
    fn apply(
        &mut self,
        destination: &AddressHash,
        limit: Option<AnnounceRateLimit>,
    ) -> Option<Duration> {
        if let Some(entry) = self.limits.get_mut(destination) {
            entry.rate_limit = limit;
            return entry.handle_announce();
        }

        self.limits
            .insert(*destination, AnnounceLimitEntry::new(limit));

        None
    }

    /// `(destination, violations, blocked_for, since_last, timestamps)`.
    /// `blocked_for` is set only while the destination is still blocked.
    /// `timestamps` is the announce window, oldest first, at most 16.
    pub(super) fn snapshot(&self) -> Vec<RateSnapshot> {
        let now = Instant::now();
        self.limits
            .iter()
            .map(|(destination, entry)| {
                let blocked_for = (now < entry.blocked_until)
                    .then(|| entry.blocked_until.saturating_duration_since(now));
                let since_last = now.saturating_duration_since(entry.last_announce);
                (
                    *destination,
                    entry.violations,
                    blocked_for,
                    since_last,
                    entry.timestamps.iter().copied().collect(),
                )
            })
            .collect()
    }
}
