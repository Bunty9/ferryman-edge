//! SIGUSR1-driven routing-table reload.
//!
//! P2 used `notify` filesystem watching. P4 deliberately swaps to
//! `SIGUSR1` because:
//!
//!   * k8s mounts ConfigMaps via a symlink-swap dance. `notify` reports
//!     this as a chain of remove + create events on the *symlink target*,
//!     not the watched path. Without per-platform special-casing the
//!     watcher silently misses the reload.
//!   * Editors emit a parade of `Modify` events for in-place writes that
//!     have no business triggering a reload (cursor moves, autosave drafts).
//!   * `SIGUSR1` is one POSIX call with predictable semantics across every
//!     deploy target. The operator runs `kill -USR1 $(pidof ferryman-edge-server)`
//!     after a `kubectl rollout restart` of the ConfigMap, or wires it into
//!     their cert-manager renewal hook.
//!
//! The JWT public key reloads on the same signal (`spawn_jwt_reload`).
//!
//! The TLS material has its own SIGUSR1 reloader inside
//! `ferryman-edge-core::tls::ReloadingTls`. Both share the same signal —
//! a single trigger reloads both surfaces atomically (from the operator's
//! point of view) without dropping connections.

use arc_swap::ArcSwap;
use ferryman_edge_core::ferryman_core::{build_table, RouteTable, SharedTable};
use ferryman_edge_core::{EdgeConfig, JwtVerifier};
use std::path::PathBuf;
use std::sync::Arc;

/// Parse `raw` and swap in the new routing table. Upstreams that survive
/// the reload (same `host:port`) keep their breaker, so an open circuit
/// stays open and in-flight tickets report to the live breaker. On any
/// error the live table is untouched. Returns the config's deprecation
/// warnings.
pub fn apply(raw: &str, table: &SharedTable) -> anyhow::Result<Vec<String>> {
    let cfg = EdgeConfig::parse(raw)?;
    let next = build_table(cfg.core, Some(&table.load()))?;
    table.store(Arc::new(next));
    table.load().publish_gauges();
    Ok(cfg.deprecations)
}

/// Spawn the SIGUSR1 reload loop. Routes, their health keys and the four
/// top-level timeouts reload; `[limits]`, `[jwt]` issuer/audience,
/// `health_interval_secs` and `keepalive_timeout_secs` are boot-only. The
/// `[mtls]` / `[jwt]` paths are fixed at boot; file contents are re-read on
/// SIGUSR1. Returns immediately; the loop runs until process exit.
pub fn spawn_reload(path: PathBuf, table: SharedTable) {
    tokio::spawn(async move {
        let mut sig =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e, "failed to register SIGUSR1 for route reload");
                    return;
                }
            };
        while sig.recv().await.is_some() {
            match std::fs::read_to_string(&path)
                .map_err(anyhow::Error::from)
                .and_then(|raw| apply(&raw, &table))
            {
                Ok(deprecations) => {
                    for d in deprecations {
                        tracing::warn!(config = %path.display(), "{d}");
                    }
                    tracing::info!(path = %path.display(), "routing table reloaded");
                }
                Err(e) => {
                    tracing::error!(path = %path.display(), ?e, "route reload failed; keeping old table");
                }
            }
        }
    });
}

/// Spawn the SIGUSR1 loop that re-reads the JWT public key from the
/// boot-time `pem_path` and swaps it in (cache invalidated). A failed read
/// or parse logs the error and keeps the old key.
pub fn spawn_jwt_reload(pem_path: PathBuf, jwt: Arc<JwtVerifier>) {
    tokio::spawn(async move {
        let mut sig =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e, "failed to register SIGUSR1 for JWT key reload");
                    return;
                }
            };
        while sig.recv().await.is_some() {
            match std::fs::read(&pem_path)
                .map_err(anyhow::Error::from)
                .and_then(|pem| jwt.reload_key(&pem))
            {
                Ok(true) => tracing::info!(path = %pem_path.display(), "JWT key reloaded"),
                Ok(false) => {
                    tracing::debug!(path = %pem_path.display(), "JWT key unchanged; token cache kept")
                }
                Err(e) => {
                    tracing::error!(path = %pem_path.display(), ?e, "JWT key reload failed; keeping old key")
                }
            }
        }
    });
}

/// Wrap a table for hot swapping (boot, tests and embedders).
pub fn new_shared(table: RouteTable) -> SharedTable {
    Arc::new(ArcSwap::from_pointee(table))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferryman_edge_core::ferryman_core::CircuitState;

    const CFG: &str = "failure_threshold = 1\n[mtls]\ncert_path = \"c\"\nkey_path = \"k\"\n\
        client_ca_path = \"ca\"\n[jwt]\njwks_path = \"j\"\n\
        [[routes]]\nprefix = \"/a\"\nupstream = \"http://127.0.0.1:9\"\n";

    fn state(table: &SharedTable) -> CircuitState {
        table.load().lookup("/a").unwrap().upstream.state()
    }

    #[test]
    fn reload_keeps_an_open_breaker_and_rejects_bad_config() {
        let table = new_shared(build_table(EdgeConfig::parse(CFG).unwrap().core, None).unwrap());
        let up = table.load().lookup("/a").unwrap().upstream.clone();
        let ticket = up.try_acquire().unwrap();
        up.record_failure(ticket);
        assert_eq!(up.state(), CircuitState::Open);

        // The route changes (new prefix added), the upstream stays: breaker kept.
        let moved =
            format!("{CFG}[[routes]]\nprefix = \"/b\"\nupstream = \"http://127.0.0.1:9\"\n");
        assert!(apply(&moved, &table).unwrap().is_empty());
        assert_eq!(state(&table), CircuitState::Open);
        assert!(table.load().lookup("/b").is_some());

        for bad in [
            "not = [toml".to_string(),
            format!("{CFG}[limits]\nbogus = 1\n"),
            CFG.replace("[mtls]", "[nope]"),
            format!("{CFG}[tls]\ncert_path='c'\nkey_path='k'\nclient_ca_path='a'\n"),
            CFG.replace("prefix = \"/a\"", "prefix = \"/%61\""),
            format!("trusted_proxies = [\"10.0.0.0/8\"]\n{CFG}"),
        ] {
            assert!(apply(&bad, &table).is_err(), "{bad}");
            assert_eq!(state(&table), CircuitState::Open);
            assert!(table.load().lookup("/b").is_some(), "live table kept");
        }
    }
}
