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
//! The TLS material has its own SIGUSR1 reloader inside
//! `ferryman-edge-core::tls::ReloadingTls`. Both share the same signal —
//! a single trigger reloads both surfaces atomically (from the operator's
//! point of view) without dropping connections.

use arc_swap::ArcSwap;
use ferryman_edge_core::{build_table, ConfigToml, RouteTable, SharedTable};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Spawn the SIGUSR1 reload loop. Returns immediately; the loop runs until
/// process exit.
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
            match reload_once(&path) {
                Ok(mut new_table) => {
                    new_table.inherit_breakers(&table.load());
                    table.store(Arc::new(new_table));
                    tracing::info!(path = %path.display(), "routing table reloaded");
                }
                Err(e) => {
                    tracing::error!(path = %path.display(), ?e, "route reload failed; keeping old table");
                }
            }
        }
    });
}

fn reload_once(path: &Path) -> anyhow::Result<RouteTable> {
    let raw = std::fs::read_to_string(path)?;
    let cfg: ConfigToml = toml::from_str(&raw)?;
    build_table(&cfg)
}

/// Helper for tests / integration code that build their own `SharedTable`
/// outside of `main()`.
#[allow(dead_code)]
pub fn new_shared(table: RouteTable) -> SharedTable {
    Arc::new(ArcSwap::from_pointee(table))
}
