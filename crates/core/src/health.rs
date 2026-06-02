//! Active health checker. Probes every upstream's `/health` on a fixed
//! interval; flips `Upstream::alive` and emits the
//! `ferryman_upstream_alive` gauge.
//!
//! Copied verbatim from `ferryman/crates/core/src/health.rs` (P2).

use crate::route::SharedTable;
use std::sync::atomic::Ordering;
use std::time::Duration;

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
            let url = format!("{}/health", up.uri);
            let host = up.uri.host().unwrap_or("").to_string();
            match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => {
                    up.alive.store(true, Ordering::Relaxed);
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
