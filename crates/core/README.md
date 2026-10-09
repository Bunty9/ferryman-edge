# ferryman-edge-core

[![crates.io](https://img.shields.io/crates/v/ferryman-edge-core.svg)](https://crates.io/crates/ferryman-edge-core)
[![docs.rs](https://img.shields.io/docsrs/ferryman-edge-core)](https://docs.rs/ferryman-edge-core)

Building blocks behind the [`ferryman-edge`](https://github.com/Bunty9/ferryman-edge)
mTLS reverse proxy. No HTTP serving here — the
[`ferryman-edge`](https://crates.io/crates/ferryman-edge) crate
wires these behind a `tokio-rustls` acceptor.

| Module | What it gives you |
| --- | --- |
| `tls` | `build_mtls_config` (rustls 0.23 + ring, required client certs, ALPN h2/http1.1) and `ReloadingTls`, which swaps cert/key/client-CA atomically on `SIGUSR1` or `reload()` |
| `jwt` | `JwtVerifier`: RS256 with a 10k-entry / 5-minute moka cache; `exp` re-checked on cache hits, `nbf` enforced, optional `iss` / `aud`; `reload_key` swaps the public key and clears the cache |
| `ratelimit` | Per-tenant GCRA limiter (`governor`), `0` rps = disabled, `spawn_gc` to bound per-tenant state |
| `route` | `RouteTable` with segment-boundary longest-prefix matching and a lock-free Closed / Open / HalfOpen circuit breaker per upstream |
| `health` | Active `/health` probe loop feeding the breaker |
| `config` | TOML schema (`parse_config`, `ConfigExt` with `[limits]`, per-route `health_path` / `health_disabled`), `build_table` / `build_table_ext` |

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

`ReloadingTls::new` spawns a tokio task, so call it inside a runtime, and
install a rustls crypto provider first
(`rustls::crypto::ring::default_provider().install_default()`).

Minimum Rust version: 1.88. Licensed under MIT or Apache-2.0, at your option.
