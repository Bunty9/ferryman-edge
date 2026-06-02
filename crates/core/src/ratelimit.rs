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

/// Shared keyed limiter type alias. Cloning is an `Arc` bump — no shard
/// rebuild.
pub type Limiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Construct a keyed limiter with the given per-tenant requests/sec quota.
/// Burst is implicit: GCRA allows `rps` requests within one second before
/// the next request is gated.
pub fn build_limiter(rps: u32) -> Arc<Limiter> {
    let quota = Quota::per_second(NonZeroU32::new(rps.max(1)).unwrap());
    Arc::new(RateLimiter::keyed(quota))
}

/// Check the limiter for `tenant`. `Ok(())` means the request is allowed;
/// `Err(())` means it has been throttled and the caller should return 429.
pub fn check(limiter: &Limiter, tenant: &str) -> Result<(), ()> {
    limiter.check_key(&tenant.to_string()).map_err(|_| ())
}
