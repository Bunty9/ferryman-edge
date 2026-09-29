//! Write `ferryman.toml` for a given topology.
//!
//! The schema is `ConfigToml` in `ferryman-edge-core`. Paths are written
//! absolute so the proxy can be started from any working directory.

use crate::pki::Pki;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;

/// What the proxy should route to, and how it should behave.
pub struct Topology {
    /// `(prefix, upstream address, per-route breaker cooldown override)`.
    pub routes: Vec<(String, SocketAddr, Option<u64>)>,
    /// Per-tenant requests/second cap (also the burst size).
    pub tenant_rps: u32,
    /// How often the active health checker probes each upstream's `/health`.
    pub health_interval_secs: u64,
    /// Circuit-breaker cooldown for routes without an override (must be >= 1).
    pub default_cooldown_secs: u64,
}

pub fn write(pki: &Pki, topo: &Topology, path: &Path) -> anyhow::Result<()> {
    let abs = |name: &str| -> anyhow::Result<String> {
        Ok(std::path::absolute(pki.path(name))?.display().to_string())
    };
    let mut s = String::new();
    // Top-level keys must come before any [table].
    writeln!(s, "health_interval_secs = {}", topo.health_interval_secs)?;
    writeln!(s, "default_cooldown_secs = {}", topo.default_cooldown_secs)?;
    writeln!(s, "tenant_rps = {}", topo.tenant_rps)?;
    writeln!(s, "\n[tls]")?;
    writeln!(s, "cert_path = {:?}", abs("server.crt")?)?;
    writeln!(s, "key_path = {:?}", abs("server.key")?)?;
    // Every client cert must chain to this CA; nothing else is accepted.
    writeln!(s, "client_ca_path = {:?}", abs("ca.crt")?)?;
    writeln!(s, "\n[jwt]")?;
    writeln!(s, "jwks_path = {:?}", abs("jwt-signing.pub")?)?;
    // Without these two, any token signed by the issuer key would pass,
    // whichever service it was minted for.
    writeln!(s, "issuer = {:?}", crate::tokens::ISSUER)?;
    writeln!(s, "audience = {:?}", crate::tokens::AUDIENCE)?;
    for (prefix, addr, cooldown) in &topo.routes {
        writeln!(s, "\n[[routes]]")?;
        writeln!(s, "prefix = {prefix:?}")?;
        writeln!(s, "upstream = \"http://{addr}\"")?;
        if let Some(c) = cooldown {
            writeln!(s, "cooldown_secs = {c}")?;
        }
    }
    std::fs::write(path, s)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_config_parses_and_builds_a_table() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki {
            dir: dir.path().into(),
        };
        let topo = Topology {
            routes: vec![
                ("/a".into(), "127.0.0.1:9001".parse().unwrap(), None),
                ("/b".into(), "127.0.0.1:9002".parse().unwrap(), Some(2)),
            ],
            tenant_rps: 5,
            health_interval_secs: 1,
            default_cooldown_secs: 2,
        };
        let path = dir.path().join("ferryman.toml");
        write(&pki, &topo, &path).unwrap();
        let cfg: ferryman_edge_core::ConfigToml =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            ferryman_edge_core::build_table(&cfg).unwrap().rules.len(),
            2
        );
        assert_eq!(cfg.jwt.audience.as_deref(), Some("ferryman-edge"));
    }
}
