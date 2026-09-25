//! TOML config schema for ferryman-edge.
//!
//! Extends P2's `ferryman-core::config::ConfigToml` with:
//!   - `[tls]`           : cert, key, client_ca paths for mTLS termination.
//!   - `jwks_path`       : RSA public-key PEM used by `JwtVerifier`.
//!   - per-tenant rps cap: applied by the `governor`-based rate limiter.
//!
//! The reload path stays simple: SIGUSR1 triggers a full re-read of this
//! file. See `crates/server/src/reload.rs` for why FS-watch is not used in
//! P4 (k8s ConfigMap mounts emit unhelpful events).

use crate::route::{RouteTable, Upstream};
use serde::Deserialize;

/// Top-level config file.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigToml {
    /// Active health-check interval in seconds.
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u64,
    /// Default circuit-breaker cooldown if a route doesn't override.
    #[serde(default = "default_cooldown")]
    pub default_cooldown_secs: u64,
    /// Per-tenant rate limit, requests/sec. `0` disables rate limiting.
    #[serde(default = "default_rps")]
    pub tenant_rps: u32,
    /// mTLS material — required when `--bind-mtls` is enabled.
    pub tls: TlsToml,
    /// JWT issuer public key (RSA PEM) for in-line token validation.
    pub jwt: JwtToml,
    pub routes: Vec<RouteToml>,
}

fn default_health_interval() -> u64 {
    5
}
fn default_cooldown() -> u64 {
    30
}
fn default_rps() -> u32 {
    1_000
}

/// mTLS material loaded by `tls::build_mtls_config`.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsToml {
    /// Server certificate chain (PEM, may be a bundle).
    pub cert_path: String,
    /// Server private key (PEM, PKCS#8 or RSA).
    pub key_path: String,
    /// Client-CA bundle — every accepted client cert must chain to one of
    /// these roots. May include intermediates.
    pub client_ca_path: String,
}

/// JWT verification config.
#[derive(Debug, Clone, Deserialize)]
pub struct JwtToml {
    /// Path to the RSA public key PEM used for RS256 verification.
    pub jwks_path: String,
}

/// One routing rule.
#[derive(Debug, Clone, Deserialize)]
pub struct RouteToml {
    /// Path prefix to match (e.g. `/svc-a`).
    pub prefix: String,
    /// Upstream URI, e.g. `http://localhost:8001`.
    pub upstream: String,
    /// Per-route circuit-breaker cooldown override.
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
}

/// Build a [`RouteTable`] from a parsed [`ConfigToml`]. Returns an error if
/// any upstream URI fails to parse or has no authority (e.g. a relative
/// path with no scheme/host — nothing the proxy could dial) — the caller
/// should keep the old table in that case.
pub fn build_table(cfg: &ConfigToml) -> anyhow::Result<RouteTable> {
    let default_cooldown = cfg.default_cooldown_secs;
    let mut rules = Vec::with_capacity(cfg.routes.len());
    for r in &cfg.routes {
        let uri: http::Uri = r.upstream.parse()?;
        if uri.authority().is_none() {
            anyhow::bail!(
                "route {:?}: upstream {:?} has no authority (scheme://host)",
                r.prefix,
                r.upstream
            );
        }
        let cooldown = r.cooldown_secs.unwrap_or(default_cooldown);
        rules.push((r.prefix.clone(), Upstream::new(uri, cooldown)));
    }
    Ok(RouteTable::new(rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_config_toml_parses_and_builds() {
        let raw = include_str!("../../../config.toml");
        let cfg: ConfigToml = toml::from_str(raw).expect("config.toml should parse");
        build_table(&cfg).expect("build_table should succeed for config.toml");
    }

    #[test]
    fn build_table_rejects_upstream_without_authority() {
        let cfg = ConfigToml {
            health_interval_secs: 5,
            default_cooldown_secs: 30,
            tenant_rps: 1000,
            tls: TlsToml {
                cert_path: "certs/server.crt".into(),
                key_path: "certs/server.key".into(),
                client_ca_path: "certs/ca-bundle.crt".into(),
            },
            jwt: JwtToml {
                jwks_path: "certs/jwt-pub.pem".into(),
            },
            routes: vec![RouteToml {
                prefix: "/svc-a".into(),
                upstream: "/no-authority-here".into(),
                cooldown_secs: None,
            }],
        };
        assert!(build_table(&cfg).is_err());
    }
}
