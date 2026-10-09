//! TOML config for ferryman-edge: one file, two owners (ROADMAP A7).
//!
//! [`EdgeConfig::parse`] reads the file into a `toml::Table`, removes the
//! edge-only keys and deserialises them into edge structs: `[mtls]` (or its
//! deprecated alias `[tls]`), `[jwt]` and `[limits]` (which also holds
//! `tenant_rps`). What remains is [`ConfigToml`], the proxy-core schema. It
//! mirrors ferryman-core 0.3 key for key, so the rebase onto it swaps the
//! type without a schema change. Every table rejects unknown keys. serde
//! cannot combine `flatten` with `deny_unknown_fields`, hence two passes.
//! Deprecated spellings still load. Each one adds a line to
//! [`EdgeConfig::deprecations`], which the binary logs as a warning.

use crate::route::{RouteTable, Upstream};
use anyhow::{bail, ensure, Context};
use serde::Deserialize;
use std::time::Duration;

/// Upper bound for every duration key, so `Duration` arithmetic can't overflow.
const MAX_SECS: u64 = 86_400;
const MAX_BODY: u64 = 1 << 30;

/// The whole config file.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EdgeConfig {
    /// Top-level keys and `[[routes]]`: routing, breaker, health, timeouts.
    pub core: ConfigToml,
    /// `[mtls]`: the server identity and the client CA.
    pub mtls: MtlsToml,
    /// `[jwt]`: RS256 verification.
    pub jwt: JwtToml,
    /// `[limits]`: connection limits and the per-tenant rate. Boot-only.
    pub limits: Limits,
    /// Deprecated spellings found in the file, one readable line each.
    pub deprecations: Vec<String>,
}

/// Top-level keys and `[[routes]]`. Names, defaults and meaning follow
/// ferryman-core 0.3's `ConfigToml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigToml {
    /// Active health-check interval in seconds. Boot-only.
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u64,
    /// Breaker cooldown for routes that don't set `cooldown_secs`.
    #[serde(default = "default_cooldown")]
    pub default_cooldown_secs: u64,
    /// Upstream deadline, from the end of the client's upload to the
    /// upstream's response head.
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// HTTP/1 keep-alive idle timeout (also the header-read timeout of
    /// later requests on a connection). Boot-only.
    #[serde(default = "default_keepalive")]
    pub keepalive_timeout_secs: u64,
    /// Longest gap between request-body frames.
    #[serde(default = "default_body_idle")]
    pub request_body_idle_timeout_secs: u64,
    /// Total time allowed to receive a request body.
    #[serde(default = "default_body_total")]
    pub request_body_timeout_secs: u64,
    pub routes: Vec<RouteToml>,
}

fn default_health_interval() -> u64 {
    5
}
fn default_cooldown() -> u64 {
    30
}
fn default_upstream_timeout() -> u64 {
    30
}
fn default_keepalive() -> u64 {
    10
}
fn default_body_idle() -> u64 {
    30
}
fn default_body_total() -> u64 {
    300
}

/// One `[[routes]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteToml {
    /// Path prefix to match (e.g. `/svc-a`).
    pub prefix: String,
    /// Upstream URI, e.g. `http://localhost:8001`.
    pub upstream: String,
    /// Per-route circuit-breaker cooldown override.
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    /// Health probe path. `None` = `/health`.
    #[serde(default)]
    pub health_path: Option<String>,
    /// Skip active health probing for this route.
    #[serde(default)]
    pub health_disabled: bool,
}

/// `[mtls]` (deprecated alias `[tls]`): material for `tls::build_mtls_config`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsToml {
    /// Server certificate chain (PEM, may be a bundle).
    pub cert_path: String,
    /// Server private key (PEM, PKCS#8 or RSA).
    pub key_path: String,
    /// Client-CA bundle: every accepted client cert must chain to one of these.
    pub client_ca_path: String,
}

/// `[jwt]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// `[limits]`. Boot-only: not re-read on SIGUSR1.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Max client request body, bytes (<= 1 GiB).
    pub max_request_body_bytes: u64,
    /// TLS handshake deadline.
    pub tls_handshake_timeout_secs: u64,
    /// Deadline for the first request on a connection.
    pub first_request_timeout_secs: u64,
    /// HTTP/2 max concurrent streams per connection.
    pub h2_max_concurrent_streams: u32,
    /// Graceful-shutdown drain window.
    pub shutdown_drain_secs: u64,
    /// Per-tenant requests/second, keyed by JWT `sub`. `0` disables.
    pub tenant_rps: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 8 * 1024 * 1024,
            tls_handshake_timeout_secs: 10,
            first_request_timeout_secs: 10,
            h2_max_concurrent_streams: 64,
            shutdown_drain_secs: 25,
            tenant_rps: 1_000,
        }
    }
}

impl Limits {
    fn validate(&self) -> anyhow::Result<()> {
        for (key, v) in [
            (
                "tls_handshake_timeout_secs",
                self.tls_handshake_timeout_secs,
            ),
            (
                "first_request_timeout_secs",
                self.first_request_timeout_secs,
            ),
            ("shutdown_drain_secs", self.shutdown_drain_secs),
        ] {
            ensure!(
                (1..=MAX_SECS).contains(&v),
                "limits.{key} must be between 1 and {MAX_SECS}"
            );
        }
        ensure!(
            (1..=MAX_BODY).contains(&self.max_request_body_bytes),
            "limits.max_request_body_bytes must be between 1 and {MAX_BODY}"
        );
        ensure!(
            self.h2_max_concurrent_streams > 0,
            "limits.h2_max_concurrent_streams must be at least 1"
        );
        Ok(())
    }
}

impl EdgeConfig {
    /// Parse and validate the edge tables; the core part is validated by
    /// [`build_table`].
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let mut top: toml::Table = raw.parse().context("config is not valid TOML")?;
        let mut deprecations = Vec::new();

        let mtls = match (top.remove("mtls"), top.remove("tls")) {
            (Some(_), Some(_)) => {
                bail!("both [mtls] and its deprecated alias [tls] are set; keep [mtls]")
            }
            (Some(t), None) => t,
            (None, Some(t)) => {
                deprecations.push("[tls] is deprecated: rename the table to [mtls]".to_string());
                t
            }
            (None, None) => bail!("missing [mtls] table (cert_path, key_path, client_ca_path)"),
        };
        let jwt = top
            .remove("jwt")
            .context("missing [jwt] table (jwks_path)")?;
        let mut limits = match top.remove("limits") {
            None => toml::Table::new(),
            Some(toml::Value::Table(t)) => t,
            Some(_) => bail!("limits must be a table"),
        };
        if let Some(v) = top.remove("tenant_rps") {
            ensure!(
                !limits.contains_key("tenant_rps"),
                "tenant_rps is set at the top level (deprecated) and in [limits]; keep [limits] tenant_rps"
            );
            deprecations.push(
                "top-level tenant_rps is deprecated: move it to [limits] tenant_rps".to_string(),
            );
            limits.insert("tenant_rps".into(), v);
        }
        for key in ["upstream_timeout_secs", "request_body_timeout_secs"] {
            if let Some(v) = limits.remove(key) {
                ensure!(
                    !top.contains_key(key),
                    "{key} is set in [limits] (deprecated) and at the top level; keep the top-level key"
                );
                deprecations.push(format!(
                    "[limits] {key} is deprecated: move it to the top level"
                ));
                top.insert(key.into(), v);
            }
        }

        let limits: Limits = toml::Value::Table(limits)
            .try_into()
            .context("in [limits]")?;
        limits.validate()?;
        Ok(Self {
            core: toml::Value::Table(top).try_into()?,
            mtls: mtls.try_into().context("in [mtls]")?,
            jwt: jwt.try_into().context("in [jwt]")?,
            limits,
            deprecations,
        })
    }
}

/// Validate the core keys and build a [`RouteTable`]. On error the caller
/// keeps its old table.
pub fn build_table(cfg: &ConfigToml) -> anyhow::Result<RouteTable> {
    for (key, v) in [
        ("health_interval_secs", cfg.health_interval_secs),
        ("default_cooldown_secs", cfg.default_cooldown_secs),
        ("upstream_timeout_secs", cfg.upstream_timeout_secs),
        ("keepalive_timeout_secs", cfg.keepalive_timeout_secs),
        (
            "request_body_idle_timeout_secs",
            cfg.request_body_idle_timeout_secs,
        ),
        ("request_body_timeout_secs", cfg.request_body_timeout_secs),
    ] {
        ensure!(
            (1..=MAX_SECS).contains(&v),
            "{key} must be between 1 and {MAX_SECS}"
        );
    }
    let mut rules = Vec::with_capacity(cfg.routes.len());
    for r in &cfg.routes {
        let uri: http::Uri = r
            .upstream
            .parse()
            .with_context(|| format!("route {:?}: invalid upstream {:?}", r.prefix, r.upstream))?;
        ensure!(
            uri.authority().is_some(),
            "route {:?}: upstream {:?} has no authority (scheme://host)",
            r.prefix,
            r.upstream
        );
        let cooldown = r.cooldown_secs.unwrap_or(cfg.default_cooldown_secs);
        // 0 would let every caller through as a "probe".
        ensure!(
            cooldown > 0,
            "route {}: cooldown_secs must be at least 1",
            r.prefix
        );
        if let Some(p) = &r.health_path {
            ensure!(
                p.starts_with('/')
                    && !p.contains(['?', '#'])
                    && p.parse::<http::uri::PathAndQuery>().is_ok(),
                "route {}: health_path {p:?} must start with '/' and contain no '?' or '#'",
                r.prefix
            );
        }
        let up = Upstream::new(uri, cooldown).with_health(r.health_path.clone(), r.health_disabled);
        rules.push((r.prefix.clone(), up));
    }
    let secs = Duration::from_secs;
    let mut table = RouteTable::new(rules)
        .with_keepalive_timeout(secs(cfg.keepalive_timeout_secs))
        .with_request_body_idle_timeout(secs(cfg.request_body_idle_timeout_secs))
        .with_request_body_timeout(secs(cfg.request_body_timeout_secs));
    table.upstream_timeout = secs(cfg.upstream_timeout_secs);
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config file exactly as 0.1.2 documented it.
    const V012: &str = r#"
health_interval_secs = 5
default_cooldown_secs = 30
tenant_rps = 7

[limits]
upstream_timeout_secs = 12
request_body_timeout_secs = 40
max_request_body_bytes = 1024

[tls]
cert_path = "c"
key_path = "k"
client_ca_path = "ca"

[jwt]
jwks_path = "j"

[[routes]]
prefix = "/svc-a"
upstream = "http://localhost:8001"
health_path = "/ready"
"#;

    /// New-style config with an extra line in each section.
    fn cfg(top: &str, mtls: &str, jwt: &str, limits: &str, route: &str) -> String {
        format!(
            "{top}\n[mtls]\ncert_path = \"c\"\nkey_path = \"k\"\nclient_ca_path = \"ca\"\n{mtls}\n\
             [jwt]\njwks_path = \"j\"\n{jwt}\n[limits]\n{limits}\n\
             [[routes]]\nprefix = \"/svc-a\"\nupstream = \"http://localhost:8001\"\n{route}\n"
        )
    }

    #[test]
    fn repo_config_toml_parses_without_warnings_and_builds() {
        let c = EdgeConfig::parse(include_str!("../../../config.toml")).unwrap();
        assert!(c.deprecations.is_empty(), "{:?}", c.deprecations);
        build_table(&c.core).unwrap();
    }

    #[test]
    fn edge_0_1_2_config_loads_with_deprecation_warnings() {
        let c = EdgeConfig::parse(V012).unwrap();
        assert_eq!(c.mtls.cert_path, "c");
        assert_eq!(c.limits.tenant_rps, 7);
        assert_eq!(c.limits.max_request_body_bytes, 1024);
        assert_eq!(c.core.upstream_timeout_secs, 12);
        assert_eq!(c.core.request_body_timeout_secs, 40);
        assert_eq!(c.deprecations.len(), 4, "{:?}", c.deprecations);
        for want in [
            "[mtls]",
            "[limits] tenant_rps",
            "upstream_timeout_secs",
            "request_body_timeout_secs",
        ] {
            assert!(
                c.deprecations.iter().any(|d| d.contains(want)),
                "{want}: {:?}",
                c.deprecations
            );
        }
        build_table(&c.core).unwrap();
    }

    #[test]
    fn defaults_match_ferryman_core() {
        let c = EdgeConfig::parse(&cfg("", "", "", "", "")).unwrap();
        let k = &c.core;
        assert_eq!(
            (
                k.health_interval_secs,
                k.default_cooldown_secs,
                k.upstream_timeout_secs,
                k.keepalive_timeout_secs,
                k.request_body_idle_timeout_secs,
                k.request_body_timeout_secs
            ),
            (5, 30, 30, 10, 30, 300)
        );
        let l = &c.limits;
        assert_eq!(
            (
                l.tls_handshake_timeout_secs,
                l.first_request_timeout_secs,
                l.h2_max_concurrent_streams,
                l.shutdown_drain_secs,
                l.tenant_rps
            ),
            (10, 10, 64, 25, 1000)
        );
        let t = build_table(&c.core).unwrap();
        assert_eq!(t.upstream_timeout, Duration::from_secs(30));
        assert_eq!(t.keepalive_timeout(), Duration::from_secs(10));
        assert_eq!(t.request_body_idle_timeout(), Duration::from_secs(30));
        assert_eq!(t.request_body_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn old_and_new_spellings_together_are_errors() {
        let both_tls = format!(
            "{}\n[tls]\ncert_path = \"c\"\nkey_path = \"k\"\nclient_ca_path = \"ca\"\n",
            cfg("", "", "", "", "")
        );
        let rps = cfg("tenant_rps = 1", "", "", "tenant_rps = 2", "");
        let timeout = cfg(
            "upstream_timeout_secs = 1",
            "",
            "",
            "upstream_timeout_secs = 2",
            "",
        );
        for (raw, want) in [
            (both_tls, "[mtls]"),
            (rps, "tenant_rps"),
            (timeout, "upstream_timeout_secs"),
        ] {
            let e = format!("{:#}", EdgeConfig::parse(&raw).unwrap_err());
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected_in_every_table() {
        for raw in [
            cfg("bogus = 1", "", "", "", ""),
            cfg("", "bogus = 1", "", "", ""),
            cfg("", "", "bogus = 1", "", ""),
            cfg("", "", "", "bogus = 1", ""),
            cfg("", "", "", "", "bogus = 1"),
        ] {
            let e = format!("{:#}", EdgeConfig::parse(&raw).unwrap_err());
            assert!(e.contains("bogus"), "{e}");
        }
    }

    #[test]
    fn missing_mtls_or_jwt_is_an_error() {
        let no_mtls = cfg("", "", "", "", "").replace("[mtls]", "[unused]");
        assert!(EdgeConfig::parse(&no_mtls).is_err());
        let no_jwt =
            "[mtls]\ncert_path = \"c\"\nkey_path = \"k\"\nclient_ca_path = \"ca\"\nroutes = []\n";
        let e = format!("{:#}", EdgeConfig::parse(no_jwt).unwrap_err());
        assert!(e.contains("[jwt]"), "{e}");
    }

    #[test]
    fn limits_validation_names_the_key() {
        for (line, key) in [
            ("max_request_body_bytes = 0", "max_request_body_bytes"),
            (
                "tls_handshake_timeout_secs = 0",
                "tls_handshake_timeout_secs",
            ),
            (
                "first_request_timeout_secs = 86401",
                "first_request_timeout_secs",
            ),
            ("h2_max_concurrent_streams = 0", "h2_max_concurrent_streams"),
            ("shutdown_drain_secs = 0", "shutdown_drain_secs"),
        ] {
            let e = format!(
                "{:#}",
                EdgeConfig::parse(&cfg("", "", "", line, "")).unwrap_err()
            );
            assert!(e.contains(key), "{line}: {e}");
        }
    }

    #[test]
    fn core_validation_names_the_key() {
        for (line, key) in [
            ("health_interval_secs = 0", "health_interval_secs"),
            ("upstream_timeout_secs = 0", "upstream_timeout_secs"),
            ("keepalive_timeout_secs = 86401", "keepalive_timeout_secs"),
            (
                "request_body_idle_timeout_secs = 0",
                "request_body_idle_timeout_secs",
            ),
            ("request_body_timeout_secs = 0", "request_body_timeout_secs"),
        ] {
            let c = EdgeConfig::parse(&cfg(line, "", "", "", "")).unwrap();
            let e = build_table(&c.core).err().unwrap().to_string();
            assert!(e.contains(key), "{line}: {e}");
        }
        for (route, key) in [
            ("cooldown_secs = 0", "cooldown_secs"),
            ("health_path = \"healthz\"", "health_path"),
            ("health_path = \"/h?x=1\"", "health_path"),
        ] {
            let c = EdgeConfig::parse(&cfg("", "", "", "", route)).unwrap();
            let e = build_table(&c.core).err().unwrap().to_string();
            assert!(e.contains(key), "{route}: {e}");
        }
        let c = EdgeConfig::parse(
            &cfg("", "", "", "", "").replace("http://localhost:8001", "/no-authority"),
        )
        .unwrap();
        assert!(build_table(&c.core).is_err());
    }

    #[test]
    fn health_keys_reach_the_upstream() {
        let c = EdgeConfig::parse(&cfg(
            "",
            "",
            "",
            "",
            "health_path = \"/ready\"\nhealth_disabled = true",
        ))
        .unwrap();
        let t = build_table(&c.core).unwrap();
        let a = t.lookup("/svc-a").unwrap();
        assert_eq!((a.health_path(), a.health_disabled()), ("/ready", true));
    }
}
