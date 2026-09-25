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
        let state = self.state.load(Ordering::Acquire);
        if state == CLOSED {
            return true;
        }
        // Open, or HalfOpen with a probe in flight. The transition timestamp
        // is the single-flight token: only the caller whose CAS moves it
        // from the stale value to `now` becomes the probe. Using the state
        // byte as the token instead leaves an ABA window where two callers
        // both see a stale HalfOpen and both probe.
        let stamped = self.last_transition_unix.load(Ordering::Acquire);
        let now = now_secs();
        if now.saturating_sub(stamped) < self.cooldown_secs {
            return false;
        }
        if self
            .last_transition_unix
            .compare_exchange(stamped, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        if self
            .state
            .compare_exchange(OPEN, HALF_OPEN, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            emit_circuit_gauge(&self.uri, HALF_OPEN);
        }
        true
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

    /// The upstream for the most specific matching prefix, if that upstream
    /// is routable. A tripped breaker yields `None` — it never falls through
    /// to a shorter prefix, which would send one service's traffic to
    /// another service's backend.
    pub fn lookup(&self, path: &str) -> Option<&Upstream> {
        self.rules
            .iter()
            .find(|(prefix, _)| matches_prefix(path, prefix))
            .map(|(_, up)| up)
            .filter(|up| up.is_routable())
    }

    /// Carry circuit-breaker state across a reload: every rule whose prefix,
    /// upstream URI, and cooldown are unchanged reuses the old `Upstream`
    /// (and so its shared breaker atomics). Without this a SIGUSR1 during an
    /// incident would reset every breaker to Closed and send full traffic at
    /// dead backends.
    pub fn inherit_breakers(&mut self, old: &RouteTable) {
        for (prefix, up) in &mut self.rules {
            if let Some((_, prev)) = old.rules.iter().find(|(p, prev)| {
                p == prefix && prev.uri == up.uri && prev.cooldown_secs == up.cooldown_secs
            }) {
                *up = prev.clone();
            }
        }
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
    fn open_breaker_does_not_fall_through_to_shorter_prefix() {
        let specific = upstream(30);
        let catch_all = upstream(30);
        let table = RouteTable::new(vec![
            ("/".to_string(), catch_all),
            ("/svc-a".to_string(), specific.clone()),
        ]);
        specific.mark_failed();
        assert!(table.lookup("/svc-a/x").is_none());
        assert!(table.has_prefix("/svc-a/x"));
        assert!(table.lookup("/other").is_some());
    }

    #[test]
    fn reload_inherits_breaker_state_for_unchanged_rules() {
        let a = upstream(30);
        let old = RouteTable::new(vec![("/svc-a".to_string(), a.clone())]);
        a.mark_failed();

        let mut same = RouteTable::new(vec![("/svc-a".to_string(), upstream(30))]);
        same.inherit_breakers(&old);
        assert!(same.lookup("/svc-a").is_none(), "breaker stays open");

        let mut moved = RouteTable::new(vec![(
            "/svc-a".to_string(),
            Upstream::new("http://localhost:9999".parse().unwrap(), 30),
        )]);
        moved.inherit_breakers(&old);
        assert!(
            moved.lookup("/svc-a").is_some(),
            "new upstream starts closed"
        );
    }

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
    fn concurrent_callers_admit_exactly_one_probe() {
        for _ in 0..200 {
            let up = upstream(30);
            up.mark_failed();
            force_cooldown_elapsed(&up);
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let admitted: usize = (0..8)
                .map(|_| {
                    let (up, barrier) = (up.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        up.is_routable() as usize
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .sum();
            assert_eq!(admitted, 1);
        }
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
