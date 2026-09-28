# ferryman-edge-core

Building blocks behind the [`ferryman-edge`](https://github.com/Bunty9/ferryman-edge)
mTLS reverse proxy. No HTTP serving here — the
[`ferryman-edge`](https://crates.io/crates/ferryman-edge) crate
wires these behind a `tokio-rustls` acceptor.

| Module | What it gives you |
| --- | --- |
| `tls` | `build_mtls_config` (rustls 0.23 + aws-lc-rs, required client certs, ALPN h2/http1.1) and `ReloadingTls`, which swaps cert/key/client-CA atomically on `SIGUSR1` or `reload()` |
| `jwt` | `JwtVerifier`: RS256 with a 10k-entry / 5-minute moka cache; `exp` re-checked on cache hits, `nbf` enforced, optional `iss` / `aud` |
| `ratelimit` | Per-tenant GCRA limiter (`governor`), `0` rps = disabled, `spawn_gc` to bound per-tenant state |
| `route` | `RouteTable` with segment-boundary longest-prefix matching and a lock-free Closed / Open / HalfOpen circuit breaker per upstream |
| `health` | Active `/health` probe loop feeding the breaker |
| `config` | TOML schema and `build_table` |

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
(`rustls::crypto::aws_lc_rs::default_provider().install_default()`).

Minimum Rust version: 1.88. Licensed under MIT or Apache-2.0, at your option.
