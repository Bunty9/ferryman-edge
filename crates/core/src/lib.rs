//! ferryman-edge-core: mTLS, JWT and per-tenant rate-limit primitives for
//! the ferryman-edge proxy, on top of [`ferryman_core`] (routing table,
//! Admission-ticket circuit breaker, health checks, core config).
//!
//!   - `tls`: rustls 0.23 + ring mTLS server config + `ReloadingTls`
//!     (SIGUSR1 swap without dropping live connections).
//!   - `jwt`: `JwtVerifier`, RS256 with a moka cache (10k entries, 5 min).
//!   - `ratelimit`: keyed `governor` GCRA limiter.
//!   - `config`: `EdgeConfig`, the two-pass parse: `[mtls]`, `[jwt]` and
//!     `[limits]` here, everything else is `ferryman_core::ConfigToml`.
//!
//! `ferryman_core` is re-exported so embedders use the exact version this
//! crate was built against.

pub mod config;
pub mod jwt;
pub mod ratelimit;
pub mod tls;

pub use ferryman_core;

pub use config::{ConfigError, EdgeConfig, JwtToml, Limits, MtlsToml};
pub use jwt::{Claims, JwtVerifier};
pub use ratelimit::{build_limiter, check, spawn_gc, Limiter};
pub use tls::{build_mtls_config, ReloadingTls};
