//! Active health checker. Probes every upstream's `/health` on a fixed
//! interval; flips the circuit breaker (`Upstream::mark_success` /
//! `mark_failed`) and emits the `ferryman_upstream_alive` gauge.
//!
//! Copied verbatim from `ferryman/crates/core/src/health.rs` (P2).

use crate::route::SharedTable;
use std::time::Duration;

/// Builds the probe URL (`path`, e.g. `/health`) for an upstream. `http::Uri`'s `Display`
/// renders an empty path as `/` (e.g. `http://localhost:8001` becomes
/// `http://localhost:8001/`), so a naive `format!("{uri}/health")` produces
/// a double slash. Trim any trailing `/` from the base first.
fn health_url(uri: &http::Uri, path: &str) -> String {
    let base = uri.to_string();
    format!("{}{path}", base.trim_end_matches('/'))
}

/// Upstreams with `health_disabled` are never probed; requests drive their breaker.
fn should_probe(up: &crate::route::Upstream) -> bool {
    !up.health_disabled()
}

/// Runs forever. Cancel by aborting the spawned task.
pub async fn health_loop(table: SharedTable, interval: Duration) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(?e, "failed to build health-check reqwest client");
            return;
        }
    };
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let current = table.load_full();
        for (_, up) in &current.rules {
            if !should_probe(up) {
                continue;
            }
            let url = health_url(&up.uri, up.health_path());
            let host = up
                .uri
                .authority()
                .map_or_else(String::new, |a| a.to_string());
            match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => {
                    up.mark_success();
                    metrics::gauge!("ferryman_upstream_alive", "upstream" => host).set(1.0);
                }
                _ => {
                    up.mark_failed();
                    metrics::gauge!("ferryman_upstream_alive", "upstream" => host).set(0.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_double_slash_for_bare_authority() {
        let uri: http::Uri = "http://localhost:8001".parse().unwrap();
        assert_eq!(health_url(&uri, "/health"), "http://localhost:8001/health");
    }

    #[test]
    fn preserves_non_root_path() {
        let uri: http::Uri = "http://localhost:8001/base".parse().unwrap();
        assert_eq!(
            health_url(&uri, "/health"),
            "http://localhost:8001/base/health"
        );
    }

    #[test]
    fn custom_path() {
        let uri: http::Uri = "http://localhost:8001/base/".parse().unwrap();
        assert_eq!(
            health_url(&uri, "/ready"),
            "http://localhost:8001/base/ready"
        );
    }

    #[test]
    fn disabled_upstream_is_not_probed() {
        let uri: http::Uri = "http://localhost:8001".parse().unwrap();
        let up = crate::route::Upstream::new(uri, 30);
        assert!(should_probe(&up));
        assert!(!should_probe(&up.with_health(None, true)));
    }
}
