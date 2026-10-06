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
    /// Required `iss` claim. Unset = not checked.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Required `aud` claim. Unset = not checked (tokens that carry an `aud`
    /// are then rejected by `jsonwebtoken`).
    #[serde(default)]
    pub audience: Option<String>,
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

/// Keys added after 0.1.1, parsed from the same TOML string as
/// [`ConfigToml`] (which ignores unknown keys). Kept in separate
/// `#[non_exhaustive]` types so the 0.1.1 structs stay unchanged. Use
/// [`parse_config`] to get both.
#[derive(Debug, Clone, Deserialize, Default)]
#[non_exhaustive]
pub struct ConfigExt {
    /// `[limits]`. Boot-only: not re-read on SIGUSR1.
    #[serde(default)]
    pub limits: Limits,
    /// Health keys of each `[[routes]]` table, matched to
    /// [`ConfigToml::routes`] by `prefix`. Reloaded on SIGUSR1.
    #[serde(default)]
    pub routes: Vec<RouteExt>,
}

/// `[limits]` table. Defaults equal the 0.1.1 hard-coded values.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct Limits {
    /// Max client request body, bytes (<= 1 GiB).
    pub max_request_body_bytes: u64,
    /// Deadline for reading the client request body.
    pub request_body_timeout_secs: u64,
    /// Deadline for the upstream response.
    pub upstream_timeout_secs: u64,
    /// TLS handshake deadline.
    pub tls_handshake_timeout_secs: u64,
    /// Deadline for the first request on a connection (also the HTTP/1
    /// header-read timeout).
    pub first_request_timeout_secs: u64,
    /// HTTP/2 max concurrent streams per connection.
    pub h2_max_concurrent_streams: u32,
    /// Graceful-shutdown drain window.
    pub shutdown_drain_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 8 * 1024 * 1024,
            request_body_timeout_secs: 30,
            upstream_timeout_secs: 30,
            tls_handshake_timeout_secs: 10,
            first_request_timeout_secs: 10,
            h2_max_concurrent_streams: 64,
            shutdown_drain_secs: 25,
        }
    }
}

/// Per-route health keys; other `[[routes]]` keys are ignored here.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct RouteExt {
    /// Prefix of the route these keys belong to.
    pub prefix: String,
    /// Health probe path. `None` = `/health`.
    #[serde(default)]
    pub health_path: Option<String>,
    /// Skip active health probing for this route.
    #[serde(default)]
    pub health_disabled: bool,
}

const MAX_SECS: u64 = 86_400;
const MAX_BODY: u64 = 1 << 30;

impl ConfigExt {
    fn validate(&self, cfg: &ConfigToml) -> anyhow::Result<()> {
        let l = &self.limits;
        for (key, v) in [
            ("request_body_timeout_secs", l.request_body_timeout_secs),
            ("upstream_timeout_secs", l.upstream_timeout_secs),
            ("tls_handshake_timeout_secs", l.tls_handshake_timeout_secs),
            ("first_request_timeout_secs", l.first_request_timeout_secs),
            ("shutdown_drain_secs", l.shutdown_drain_secs),
        ] {
            anyhow::ensure!(
                (1..=MAX_SECS).contains(&v),
                "limits.{key} must be between 1 and {MAX_SECS}"
            );
        }
        anyhow::ensure!(
            (1..=MAX_BODY).contains(&l.max_request_body_bytes),
            "limits.max_request_body_bytes must be between 1 and {MAX_BODY}"
        );
        anyhow::ensure!(
            l.h2_max_concurrent_streams > 0,
            "limits.h2_max_concurrent_streams must be at least 1"
        );
        anyhow::ensure!(
            cfg.health_interval_secs > 0,
            "health_interval_secs must be at least 1"
        );
        for r in &self.routes {
            // Typo guard. Unreachable via parse_config (same tables), but
            // ConfigExt is Deserialize, so it can come from elsewhere.
            anyhow::ensure!(
                cfg.routes.iter().any(|c| c.prefix == r.prefix),
                "route {:?}: health keys match no [[routes]] prefix",
                r.prefix
            );
            if let Some(p) = &r.health_path {
                anyhow::ensure!(
                    p.starts_with('/')
                        && !p.contains(['?', '#'])
                        && p.parse::<http::uri::PathAndQuery>().is_ok(),
                    "route {}: health_path {p:?} must start with '/' and contain no '?' or '#'",
                    r.prefix
                );
            }
        }
        Ok(())
    }
}

/// Parse and validate both config views from one TOML string.
pub fn parse_config(raw: &str) -> anyhow::Result<(ConfigToml, ConfigExt)> {
    let cfg: ConfigToml = toml::from_str(raw)?;
    let ext: ConfigExt = toml::from_str(raw)?;
    ext.validate(&cfg)?;
    Ok((cfg, ext))
}

/// Build a [`RouteTable`] from a parsed [`ConfigToml`]. Returns an error if
/// any upstream URI fails to parse or has no authority (e.g. a relative
/// path with no scheme/host — nothing the proxy could dial) — the caller
/// should keep the old table in that case. Same as [`build_table_ext`] with
/// [`ConfigExt::default`].
pub fn build_table(cfg: &ConfigToml) -> anyhow::Result<RouteTable> {
    build_table_ext(cfg, &ConfigExt::default())
}

/// [`build_table`] plus the per-route health keys from `ext`. With
/// duplicate prefixes the first `ext` entry for a prefix applies to all
/// rules with that prefix (the first rule wins lookups anyway).
pub fn build_table_ext(cfg: &ConfigToml, ext: &ConfigExt) -> anyhow::Result<RouteTable> {
    ext.validate(cfg)?;
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
        // 0 would let every caller through as a "probe": the breaker would
        // be silently disabled.
        anyhow::ensure!(
            cooldown > 0,
            "route {}: cooldown_secs must be at least 1",
            r.prefix
        );
        let mut up = Upstream::new(uri, cooldown);
        if let Some(x) = ext.routes.iter().find(|x| x.prefix == r.prefix) {
            up = up.with_health(x.health_path.clone(), x.health_disabled);
        }
        rules.push((r.prefix.clone(), up));
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
                issuer: None,
                audience: None,
            },
            routes: vec![RouteToml {
                prefix: "/svc-a".into(),
                upstream: "/no-authority-here".into(),
                cooldown_secs: None,
            }],
        };
        assert!(build_table(&cfg).is_err());
    }

    #[test]
    fn build_table_rejects_zero_cooldown() {
        let raw = include_str!("../../../config.toml").replace(
            "upstream = \"http://localhost:8001\"",
            "upstream = \"http://localhost:8001\"\ncooldown_secs = 0",
        );
        let cfg: ConfigToml = toml::from_str(&raw).unwrap();
        assert!(build_table(&cfg).is_err());
    }

    fn base() -> String {
        include_str!("../../../config.toml").to_string()
    }

    #[test]
    fn shipped_config_has_default_limits() {
        let (_, ext) = parse_config(&base()).unwrap();
        let l = &ext.limits;
        assert_eq!(l.max_request_body_bytes, 8 * 1024 * 1024);
        assert_eq!(
            (
                l.request_body_timeout_secs,
                l.upstream_timeout_secs,
                l.tls_handshake_timeout_secs,
                l.first_request_timeout_secs,
                l.h2_max_concurrent_streams,
                l.shutdown_drain_secs
            ),
            (30, 30, 10, 10, 64, 25)
        );
    }

    #[test]
    fn limits_validation_names_the_key() {
        for (line, key) in [
            ("max_request_body_bytes = 0", "max_request_body_bytes"),
            (
                "max_request_body_bytes = 1073741825",
                "max_request_body_bytes",
            ),
            ("request_body_timeout_secs = 0", "request_body_timeout_secs"),
            ("upstream_timeout_secs = 86401", "upstream_timeout_secs"),
            (
                "tls_handshake_timeout_secs = 0",
                "tls_handshake_timeout_secs",
            ),
            (
                "first_request_timeout_secs = 0",
                "first_request_timeout_secs",
            ),
            ("h2_max_concurrent_streams = 0", "h2_max_concurrent_streams"),
            ("shutdown_drain_secs = 0", "shutdown_drain_secs"),
        ] {
            let raw = format!("{}\n[limits]\n{line}\n", base());
            let e = parse_config(&raw).unwrap_err().to_string();
            assert!(e.contains(key), "{line}: {e}");
        }
        let ok = format!(
            "{}\n[limits]\nmax_request_body_bytes = 1073741824\nupstream_timeout_secs = 86400\n",
            base()
        );
        parse_config(&ok).unwrap();
    }

    #[test]
    fn health_path_validation_and_mapping() {
        for bad in ["healthz", "/h?x=1", "/h#f", "/a b", "/a\\u0001b"] {
            let raw = base().replacen(
                "upstream = \"http://localhost:8001\"",
                &format!("upstream = \"http://localhost:8001\"\nhealth_path = \"{bad}\""),
                1,
            );
            let e = parse_config(&raw).unwrap_err().to_string();
            assert!(e.contains("health_path"), "{bad}: {e}");
        }
        let raw = base().replacen(
            "upstream = \"http://localhost:8001\"",
            "upstream = \"http://localhost:8001\"\nhealth_path = \"/ready\"\nhealth_disabled = true",
            1,
        );
        let (cfg, ext) = parse_config(&raw).unwrap();
        let t = build_table_ext(&cfg, &ext).unwrap();
        let a = t.lookup("/svc-a").unwrap();
        assert_eq!((a.health_path(), a.health_disabled()), ("/ready", true));
        let b = t.lookup("/svc-b").unwrap();
        assert_eq!((b.health_path(), b.health_disabled()), ("/health", false));
    }

    #[test]
    fn ext_prefix_matching_no_route_is_an_error() {
        let (cfg, _) = parse_config(&base()).unwrap();
        let ext: ConfigExt =
            toml::from_str("[[routes]]\nprefix = \"/typo\"\nhealth_disabled = true").unwrap();
        let e = build_table_ext(&cfg, &ext).err().unwrap().to_string();
        assert!(e.contains("/typo"), "{e}");
    }

    #[test]
    fn zero_health_interval_rejected_everywhere() {
        let raw = base().replace("health_interval_secs = 5", "health_interval_secs = 0");
        assert!(parse_config(&raw).is_err());
        let cfg: ConfigToml = toml::from_str(&raw).unwrap();
        assert!(build_table(&cfg).is_err());
    }
}
