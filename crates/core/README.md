# ferryman-edge-core

[![crates.io](https://img.shields.io/crates/v/ferryman-edge-core.svg)](https://crates.io/crates/ferryman-edge-core)
[![docs.rs](https://img.shields.io/docsrs/ferryman-edge-core)](https://docs.rs/ferryman-edge-core)

Building blocks behind the [`ferryman-edge`](https://github.com/Bunty9/ferryman-edge)
mTLS reverse proxy: mTLS, JWT, per-tenant rate limiting and the edge config.
Routing, the circuit breaker and health checks come from
[`ferryman-core`](https://crates.io/crates/ferryman-core) 0.3, re-exported
as `ferryman_edge_core::ferryman_core` so you get the exact version this
crate was built against. No HTTP serving here — the
[`ferryman-edge`](https://crates.io/crates/ferryman-edge) crate
wires these behind a `tokio-rustls` acceptor.

| Module | What it gives you |
| --- | --- |
| `tls` | `build_mtls_config` (rustls 0.23 + ring, required client certs, ALPN h2/http1.1) and `ReloadingTls`, which swaps cert/key/client-CA atomically on `SIGUSR1` or `reload()` |
| `jwt` | `JwtVerifier`: RS256 with a 10k-entry / 5-minute moka cache; `exp` re-checked on cache hits, `nbf` enforced, optional `iss` / `aud`; `reload_key` swaps the public key and clears the cache (no-op if the PEM is unchanged) |
| `ratelimit` | Per-tenant GCRA limiter (`governor`), `0` rps = disabled, `spawn_gc` to bound per-tenant state |
| `config` | `EdgeConfig::parse` (`[mtls]`, `[jwt]`, `[limits]`) over `ferryman_core::ConfigToml`; errors are `ConfigError` (core errors wrapped as `ConfigError::Core`) |
| `ferryman_core` | Re-export: `RouteTable`, `Upstream` with its Admission-ticket breaker, `build_table`, `health_loop`, `path::{bad_path, ambiguous_route}` |

```rust
use ferryman_edge_core::{build_limiter, check, JwtVerifier};

async fn authorize(pem: &[u8], token: &str) -> anyhow::Result<bool> {
    let jwt = JwtVerifier::new(pem)?.with_issuer("https://issuer.example");
    let limiter = build_limiter(100).expect("non-zero rps");
    Ok(match jwt.verify(token).await {
        Some(claims) => check(&limiter, &claims.sub),
        None => false,
    })
}
```

Routing from the same config file:

```rust
use ferryman_edge_core::ferryman_core::build_table;
use ferryman_edge_core::EdgeConfig;

fn table(raw: &str) -> anyhow::Result<()> {
    let cfg = EdgeConfig::parse(raw)?;
    let table = build_table(cfg.core, None)?;
    if let Some(route) = table.lookup("/svc-a/users") {
        if let Some(ticket) = route.upstream.try_acquire() {
            // forward, then report: record_success / record_failure, or
            // release when the request ended without a verdict
            route.upstream.record_success(ticket);
        }
    }
    Ok(())
}
```

`ReloadingTls::new` spawns a tokio task, so call it inside a runtime, and
install a rustls crypto provider first
(`rustls::crypto::ring::default_provider().install_default()`).

Minimum Rust version: 1.88. Licensed under MIT or Apache-2.0, at your option.
