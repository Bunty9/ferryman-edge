//! ferryman-edge-core — programmable mTLS L7 proxy primitives.
//!
//! Extends `ferryman-core` (P2) with:
//!   - `tls`    : rustls 0.23 + ring mTLS server config + `ReloadingTls`
//!     that swaps cert/key/ca on `SIGUSR1` without dropping live
//!     connections.
//!   - `jwt`    : `JwtVerifier` with a moka LRU cache (default 10k entries,
//!     5 min TTL) keyed by the raw token string.
//!   - `ratelimit`: keyed `governor` GCRA limiter; allocation-free on the
//!     hot path.
//!   - `route`  : the P2 routing table (Upstream, RouteTable, SharedTable).
//!     Copied verbatim — P4 layers atop, does not modify.
//!   - `health` : active probe loop (copied from P2).
//!   - `config` : `EdgeConfig` two-pass parse (`[mtls]`, `[jwt]`, `[limits]`)
//!     over the core-shaped `ConfigToml`.
//!
//! The server crate composes these behind a `tokio-rustls` acceptor and a
//! hyper service.

pub mod config;
pub mod health;
pub mod jwt;
pub mod ratelimit;
pub mod route;
pub mod tls;

pub use config::{build_table, ConfigToml, EdgeConfig, JwtToml, Limits, MtlsToml, RouteToml};
pub use health::health_loop;
pub use jwt::{Claims, JwtVerifier};
pub use ratelimit::{build_limiter, check, spawn_gc, Limiter};
pub use route::{RouteTable, SharedTable, Upstream};
pub use tls::{build_mtls_config, ReloadingTls};
