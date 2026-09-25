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
//!
//! The circuit breaker is an explicit Closed/Open/HalfOpen state machine
//! (`AtomicU8`, lock-free) rather than the "alive" bool P2 shipped:
//!
//!   * Closed    — routable. A failure (`mark_failed`) moves to Open.
//!   * Open      — not routable until `cooldown_secs` has elapsed since the
//!     failure. Once elapsed, exactly one caller wins a CAS into HalfOpen
//!     and is routed as the probe; everyone else still sees "not
//!     routable" — no thundering herd on recovery.
//!   * HalfOpen  — the probe's outcome (`mark_success` / `mark_failed`)
//!     decides Closed vs. Open again. If the probe never reports back
//!     (crashed task, dropped connection), a HalfOpen older than
//!     `cooldown_secs` is treated as stale and made eligible for a fresh
//!     probe, so a hung probe can't wedge the upstream open forever.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

const CLOSED: u8 = 0;
const OPEN: u8 = 1;
const HALF_OPEN: u8 = 2;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn emit_circuit_gauge(uri: &http::Uri, state: u8) {
    let host = uri.authority().map_or_else(String::new, |a| a.to_string());
    let v = match state {
        CLOSED => 0.0,
        OPEN => 1.0,
        _ => 2.0,
    };
    metrics::gauge!("ferryman_circuit_state", "upstream" => host).set(v);
}

/// A backend the proxy may forward to. `state` and `last_transition_unix`
/// are touched from the request hot path and the health-check loop, so
/// they stay atomic (no Mutex on the request path).
#[derive(Clone)]
pub struct Upstream {
    pub uri: http::Uri,
    state: Arc<AtomicU8>,
    last_transition_unix: Arc<AtomicU64>,
    pub cooldown_secs: u64,
}

impl Upstream {
    pub fn new(uri: http::Uri, cooldown_secs: u64) -> Self {
        Self {
            uri,
            state: Arc::new(AtomicU8::new(CLOSED)),
            last_transition_unix: Arc::new(AtomicU64::new(0)),
            cooldown_secs,
        }
    }

    /// Whether this upstream should receive the current request. Closed is
    /// always routable. Open becomes routable to exactly one caller once
    /// `cooldown_secs` has elapsed — that caller becomes the HalfOpen probe.
    /// A HalfOpen whose probe never reported back and has itself gone stale
    /// (older than `cooldown_secs`) is treated the same way, so recovery
    /// never wedges on a lost probe.
    pub fn is_routable(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            CLOSED => true,
            HALF_OPEN if self.cooldown_elapsed() => {
                // Stale probe — nobody reported back. Downgrade to Open so
                // the single-flight below can arm a fresh probe. If we lose
                // this race, whoever won will drive the same downgrade.
                let _ = self.state.compare_exchange(
                    HALF_OPEN,
                    OPEN,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
                self.try_probe()
            }
            OPEN => self.try_probe(),
            _ => false, // HalfOpen, probe still in flight within cooldown
        }
    }

    fn cooldown_elapsed(&self) -> bool {
        let now = now_secs();
        now.saturating_sub(self.last_transition_unix.load(Ordering::Acquire)) >= self.cooldown_secs
    }

    /// Single-flight Open -> HalfOpen transition. Only the CAS winner is
    /// routed; everyone else sees `false`.
    fn try_probe(&self) -> bool {
        if !self.cooldown_elapsed() {
            return false;
        }
        if self
            .state
            .compare_exchange(OPEN, HALF_OPEN, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.last_transition_unix
                .store(now_secs(), Ordering::Release);
            emit_circuit_gauge(&self.uri, HALF_OPEN);
            true
        } else {
            false
        }
    }

    /// Mark this upstream as failed and stamp the failure time. Called from
    /// both the request hot path (on transport error / 5xx) and the active
    /// health checker. Moves the breaker to Open, whether it was Closed or
    /// a failed HalfOpen probe.
    pub fn mark_failed(&self) {
        self.last_transition_unix
            .store(now_secs(), Ordering::Release);
        if self.state.swap(OPEN, Ordering::AcqRel) != OPEN {
            emit_circuit_gauge(&self.uri, OPEN);
        }
    }

    /// Mark this upstream healthy — either a HalfOpen probe succeeded, or
    /// the active health checker got a clean response. Closes the breaker.
    /// Called on every successful request, so the gauge is only touched on
    /// an actual transition.
    pub fn mark_success(&self) {
        if self.state.swap(CLOSED, Ordering::AcqRel) != CLOSED {
            emit_circuit_gauge(&self.uri, CLOSED);
        }
    }
}

/// Prefix-match on a path-segment boundary: `path == prefix`, or `path`
/// starts with `prefix` followed by `/`, or `prefix` itself ends with `/`.
/// `/` matches everything. This keeps `/svc-a` from matching `/svc-abc`.
fn matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    if prefix.ends_with('/') {
        return true;
    }
    matches!(path.as_bytes().get(prefix.len()), None | Some(b'/'))
}

/// Routing decisions table. `rules` is sorted DESC by prefix length at
/// construction time so iteration order is the lookup order.
pub struct RouteTable {
    pub rules: Vec<(String, Upstream)>,
}

impl RouteTable {
    pub fn new(mut rules: Vec<(String, Upstream)>) -> Self {
        rules.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
        Self { rules }
    }

    pub fn lookup(&self, path: &str) -> Option<&Upstream> {
        self.rules
            .iter()
            .find(|(prefix, up)| matches_prefix(path, prefix) && up.is_routable())
            .map(|(_, up)| up)
    }

    /// Whether any rule's prefix matches `path`, ignoring circuit-breaker
    /// state. Lets the caller tell "no route configured" (404) apart from
    /// "a route matched but its upstream isn't currently routable" (503).
    pub fn has_prefix(&self, path: &str) -> bool {
        self.rules
            .iter()
            .any(|(prefix, _)| matches_prefix(path, prefix))
    }
}

/// Hot-swappable handle. Cloning is cheap (Arc bump); `load()` is a single
/// atomic read.
pub type SharedTable = Arc<arc_swap::ArcSwap<RouteTable>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(cooldown_secs: u64) -> Upstream {
        Upstream::new("http://localhost:8001".parse().unwrap(), cooldown_secs)
    }

    /// Back-date the breaker's last transition so the next `is_routable()`
    /// sees the cooldown as elapsed, without sleeping in the test.
    fn force_cooldown_elapsed(up: &Upstream) {
        up.last_transition_unix.store(0, Ordering::Relaxed);
    }

    // ----- prefix matching --------------------------------------------

    #[test]
    fn segment_boundary_matching() {
        assert!(matches_prefix("/svc-a", "/svc-a"));
        assert!(matches_prefix("/svc-a/foo", "/svc-a"));
        assert!(!matches_prefix("/svc-abc", "/svc-a"));
        assert!(matches_prefix("/svc-a/foo", "/svc-a/"));
    }

    #[test]
    fn root_prefix_is_catch_all() {
        assert!(matches_prefix("/anything/at/all", "/"));
        assert!(matches_prefix("", "/"));
    }

    #[test]
    fn longest_prefix_wins() {
        let root: http::Uri = "http://localhost:8000".parse().unwrap();
        let svc_a: http::Uri = "http://localhost:8001".parse().unwrap();
        let svc_a_v2: http::Uri = "http://localhost:8002".parse().unwrap();
        let table = RouteTable::new(vec![
            ("/".to_string(), Upstream::new(root, 0)),
            ("/svc-a".to_string(), Upstream::new(svc_a.clone(), 0)),
            ("/svc-a/v2".to_string(), Upstream::new(svc_a_v2.clone(), 0)),
        ]);
        assert_eq!(table.lookup("/svc-a/v2/x").unwrap().uri, svc_a_v2);
        assert_eq!(table.lookup("/svc-a/other").unwrap().uri, svc_a);
    }

    // ----- circuit breaker ----------------------------------------------

    #[test]
    fn closed_is_routable() {
        let up = upstream(30);
        assert!(up.is_routable());
    }

    #[test]
    fn open_not_routable_before_cooldown() {
        let up = upstream(30);
        up.mark_failed();
        assert!(!up.is_routable());
    }

    #[test]
    fn single_probe_under_half_open() {
        let up = upstream(30);
        up.mark_failed();
        force_cooldown_elapsed(&up);
        // First caller after cooldown wins the probe slot.
        assert!(up.is_routable());
        // Second caller, right after, must not also get routed — the fresh
        // HalfOpen transition just re-stamped the timestamp, so it isn't
        // stale yet under the 30s cooldown.
        assert!(!up.is_routable());
    }

    #[test]
    fn probe_success_closes_breaker() {
        let up = upstream(30);
        up.mark_failed();
        force_cooldown_elapsed(&up);
        assert!(up.is_routable()); // becomes the probe
        up.mark_success();
        assert!(up.is_routable()); // closed — routable again, no gating
        assert!(up.is_routable());
    }

    #[test]
    fn probe_failure_reopens_breaker() {
        let up = upstream(30);
        up.mark_failed();
        force_cooldown_elapsed(&up);
        assert!(up.is_routable()); // becomes the probe
        up.mark_failed(); // probe failed
        assert!(!up.is_routable()); // back to Open, cooldown not elapsed again
    }

    #[test]
    fn stale_half_open_reprobes() {
        let up = upstream(30);
        up.mark_failed();
        force_cooldown_elapsed(&up);
        assert!(up.is_routable()); // wins the probe, now HalfOpen
        assert!(!up.is_routable()); // second caller blocked while probe pending
                                    // Probe never reports back. Back-date the HalfOpen transition past
                                    // the cooldown to simulate it going stale.
        force_cooldown_elapsed(&up);
        assert!(up.is_routable()); // re-armed as a fresh probe, not wedged
    }
}
