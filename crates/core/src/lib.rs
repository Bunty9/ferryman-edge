//! ferryman-edge-core — programmable mTLS L7 proxy primitives.
//!
//! Extends `ferryman-core` (P2) with:
//!   - `tls`    : rustls 0.23 + aws-lc-rs mTLS server config + `ReloadingTls`
//!     that swaps cert/key/ca on `SIGUSR1` without dropping live
//!     connections.
//!   - `jwt`    : `JwtVerifier` with a moka LRU cache (default 10k entries,
//!     5 min TTL) keyed by the raw token string.
//!   - `ratelimit`: keyed `governor` GCRA limiter; allocation-free on the
//!     hot path.
//!   - `route`  : the P2 routing table (Upstream, RouteTable, SharedTable).
//!     Copied verbatim — P4 layers atop, does not modify.
//!   - `health` : active probe loop (copied from P2).
//!   - `config` : TOML schema extended with `tls`, `jwks_path`, per-tenant
//!     rate-limit caps.
//!
//! The server crate composes these behind a `tokio-rustls` acceptor and a
//! hyper service.

pub mod config;
pub mod health;
pub mod jwt;
pub mod ratelimit;
pub mod route;
pub mod tls;

pub use config::{
    build_table, build_table_ext, parse_config, ConfigExt, ConfigToml, JwtToml, Limits, RouteExt,
    RouteToml, TlsToml,
};
pub use health::health_loop;
pub use jwt::{Claims, JwtVerifier};
pub use ratelimit::{build_limiter, check, spawn_gc, Limiter};
pub use route::{RouteTable, SharedTable, Upstream};
pub use tls::{build_mtls_config, ReloadingTls};
