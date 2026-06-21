use alloc::collections::BTreeMap;

use tokio::time::Duration;
use tokio::time::Instant;

use crate::hash::AddressHash;

pub struct AnnounceRateLimit {
  pub target: Duration,
  pub grace: u32,
  pub penalty: Option<Duration>
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
}

impl AnnounceLimitEntry {
    pub fn new(rate_limit: Option<AnnounceRateLimit>) -> Self {
        Self {
            rate_limit,
            violations: 0,
            last_announce: Instant::now(),
            blocked_until: Instant::now(),
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
                    if self.violations >= rate_limit.grace {
                        self.violations = 0;
                        self.blocked_until = now + rate_limit.target;
                        is_blocked = true;
                    }
                }
            }
        }

        self.last_announce = now;

        if is_blocked {
            Some(self.blocked_until - now)
        } else {
            None
        }
    }
}

pub struct AnnounceLimits {
    limits: BTreeMap<AddressHash, AnnounceLimitEntry>
}

impl AnnounceLimits {
    pub fn new() -> Self {
        Self { limits: BTreeMap::new() }
    }

    pub fn check(&mut self, destination: &AddressHash) -> Option<Duration> {
        if let Some(entry) = self.limits.get_mut(destination) {
            return entry.handle_announce();
        }

        self.limits.insert(
            *destination,
            AnnounceLimitEntry::new(Default::default())
        );

        None
    }
}
