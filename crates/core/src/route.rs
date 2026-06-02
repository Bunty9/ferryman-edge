//! Routing table + per-upstream circuit breaker.
//!
//! Copied verbatim from `ferryman/crates/core/src/route.rs` (P2). P4 layers
//! atop these primitives — mTLS handshake, JWT validation, per-tenant rate
//! limiting all happen *before* a request reaches `RouteTable::lookup`.
//!
//! Lookup is O(N) over a `Vec` sorted DESC by prefix length so the most
//! specific match wins (e.g. `/api/v1/users` beats `/api`). For N in the
//! tens of routes typical of a self-hosted edge, a linear scan beats a trie
//! on cache behaviour and is trivial to reason about.

use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// A backend the proxy may forward to. `alive` and `last_failure_unix` are
/// touched from the request hot path and the health-check loop, so they
/// stay atomic (no Mutex on the request path).
#[derive(Clone)]
pub struct Upstream {
    pub uri: http::Uri,
    pub alive: Arc<AtomicBool>,
    pub last_failure_unix: Arc<AtomicU64>,
    pub cooldown_secs: u64,
}

impl Upstream {
    pub fn new(uri: http::Uri, cooldown_secs: u64) -> Self {
        Self {
            uri,
            alive: Arc::new(AtomicBool::new(true)),
            last_failure_unix: Arc::new(AtomicU64::new(0)),
            cooldown_secs,
        }
    }

    /// Routable when alive, or when the cooldown has elapsed (half-open
    /// state — let one probe through to see if the upstream is back).
    pub fn is_routable(&self) -> bool {
        if self.alive.load(Ordering::Relaxed) {
            return true;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.last_failure_unix.load(Ordering::Relaxed)) >= self.cooldown_secs
    }

    /// Mark this upstream as failed and stamp the failure time. Called from
    /// both the request hot path (on transport error / 5xx) and the active
    /// health checker.
    pub fn mark_failed(&self) {
        self.alive.store(false, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_failure_unix.store(now, Ordering::Relaxed);
    }
}

/// Routing decisions table. `rules` is sorted DESC by prefix length at
/// construction time so iteration order is the lookup order.
pub struct RouteTable {
    pub rules: Vec<(String, Upstream)>,
}

impl RouteTable {
    pub fn new(mut rules: Vec<(String, Upstream)>) -> Self {
        rules.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self { rules }
    }

    pub fn lookup(&self, path: &str) -> Option<&Upstream> {
        self.rules
            .iter()
            .find(|(prefix, up)| path.starts_with(prefix.as_str()) && up.is_routable())
            .map(|(_, up)| up)
    }
}

/// Hot-swappable handle. Cloning is cheap (Arc bump); `load()` is a single
/// atomic read.
pub type SharedTable = Arc<ArcSwap<RouteTable>>;
