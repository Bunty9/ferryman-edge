//! Per-tenant rate limiter using `governor`'s GCRA (Generic Cell Rate
//! Algorithm). Keyed by `Claims::sub` after JWT verification.
//!
//! Governor's keyed limiter uses a sharded `DashMap` internally — no
//! allocations on the hot path once a key is seen. GCRA is preferred over
//! a leaky-bucket counter here because it allows the same RPS budget with
//! a configurable burst, without storing per-tenant token state.

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

/// Shared keyed limiter type alias. Cloning is an `Arc` bump — no shard
/// rebuild.
pub type Limiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Construct a keyed limiter with the given per-tenant requests/sec quota.
/// Burst is implicit: GCRA allows `rps` requests within one second before
/// the next request is gated. `rps == 0` disables rate limiting (`None`) —
/// the caller should skip the `check` call entirely rather than treat 0 as
/// "1 rps".
pub fn build_limiter(rps: u32) -> Option<Arc<Limiter>> {
    let quota = Quota::per_second(NonZeroU32::new(rps)?);
    Some(Arc::new(RateLimiter::keyed(quota)))
}

/// Check the limiter for `tenant`. Returns `true` if the request is
/// allowed, `false` if it has been throttled and the caller should return
/// 429.
pub fn check(limiter: &Limiter, tenant: &str) -> bool {
    limiter.check_key(&tenant.to_string()).is_ok()
}

/// Periodically evict stale per-tenant state so the keyed store doesn't
/// grow unbounded over the life of the process (one entry per distinct
/// `sub` ever seen otherwise). Runs forever — spawn it once at boot and let
/// it ride alongside the limiter's `Arc`.
pub fn spawn_gc(limiter: Arc<Limiter>, every: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_rps_disables_limiting() {
        assert!(build_limiter(0).is_none());
    }

    #[test]
    fn quota_allows_burst_then_rejects() {
        let limiter = build_limiter(2).unwrap();
        assert!(check(&limiter, "tenant-a"));
        assert!(check(&limiter, "tenant-a"));
        assert!(!check(&limiter, "tenant-a"));
    }

    #[test]
    fn separate_tenants_are_independent() {
        let limiter = build_limiter(1).unwrap();
        assert!(check(&limiter, "tenant-a"));
        assert!(!check(&limiter, "tenant-a"));
        // A different tenant has its own bucket.
        assert!(check(&limiter, "tenant-b"));
    }

    #[tokio::test]
    async fn gc_does_not_panic_on_empty_limiter() {
        let limiter = build_limiter(10).unwrap();
        check(&limiter, "tenant-a");
        spawn_gc(limiter.clone(), Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
