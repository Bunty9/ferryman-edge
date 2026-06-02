---
title: ferryman-edge — Programmable mTLS L7 Proxy (P4)
status: draft
date: 2026-05-28
related:
    - ../../../backend-cloud-roadmap.md
    - ../../../projects-l3-l4.md
    - ../../../ferryman/docs/specs/2026-05-28-ferryman-design.md
---

# ferryman-edge — Design Spec

> Companion spec lifted from `projects-l3-l4.md` § "P4 — Programmable mTLS
> L7 Proxy (ferryman-edge)". Code blocks are the authoritative
> implementation reference for the scaffold; downstream phases extend, they
> do not contradict. Default stack pins live in `backend-cloud-roadmap.md`
> § 3 and are mirrored verbatim in [`Cargo.toml`](../../Cargo.toml). P4
> extends P2 — see the sibling `ferryman/` project for the routing-table /
> circuit-breaker primitives this layers on top of.

## 1. Problem

Extend P2. Real edge proxies do mTLS termination, JWT validation in-line,
per-route rate limiting, cert hot-reload — and they make defensible
decisions on body-buffering, HTTP/2 stream control, connection pooling.
**Interview pitch:** this is the project that gets the Cloudflare Pingora
team to reply.

## 2. Architecture (delta on top of P2)

```
                Client (with mTLS cert)
                       |
                       v
              +--------+---------+
              | rustls TLS+mTLS  |  cert reload via FS watch
              | + JWT validate   |  (no connection drops)
              +--------+---------+
                       |
                       v
              +--------+---------+
              | per-tenant rate  |  governor crate, keyed by JWT.sub
              | limit (per route)|
              +--------+---------+
                       |
                       v
              +--------+---------+
              | RouteService     |
              | (P2's table)     |
              +--------+---------+
                       |
                       v
              +--------+---------+
              | hyper client     |  pool: 1 conn per upstream * N
              | HTTP/2 multiplex |  feature flag: boxed_body vs collected
              +--------+---------+
                       |
                       v
                  upstream svc
```

## 3. Stack additions over P2

- `rustls` 0.23, `tokio-rustls`, `rustls-pemfile`.
- `jsonwebtoken` 9 + `moka` 0.12 (in-memory LRU for JWT verification cache).
- `governor` for rate limiting (GCRA algorithm, no allocations on hot path).
- `aws-lc-rs` provider for FIPS-mode rustls (interview talking point).

## 4. Key Rust code

### 4.1 mTLS server bootstrap (`crates/core/src/tls.rs`)

```rust
use rustls::server::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::sync::Arc;

pub fn build_mtls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> anyhow::Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(
        &mut std::io::BufReader::new(std::fs::File::open(cert_path)?)
    ).collect::<Result<_,_>>()?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(
        &mut std::io::BufReader::new(std::fs::File::open(key_path)?)
    )?.ok_or_else(|| anyhow::anyhow!("no key"))?;

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(client_ca_path)?)) {
        roots.add(c?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
```

### 4.2 Cert hot-reload (the *interesting* part — no connection drops)

```rust
use arc_swap::ArcSwap;

pub struct ReloadingTls {
    inner: Arc<ArcSwap<ServerConfig>>,
    paths: (String, String, String),
}

impl ReloadingTls {
    pub fn new(cert: &str, key: &str, ca: &str) -> anyhow::Result<Arc<Self>> {
        let cfg = build_mtls_config(cert, key, ca)?;
        let s = Arc::new(Self {
            inner: Arc::new(ArcSwap::new(cfg)),
            paths: (cert.into(), key.into(), ca.into()),
        });
        Self::watch(s.clone());
        Ok(s)
    }

    pub fn current(&self) -> Arc<ServerConfig> { self.inner.load_full() }

    fn watch(s: Arc<Self>) {
        let paths = s.paths.clone();
        tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()).unwrap();
            // SIGUSR1 triggers reload — simpler and more reliable than notify on k8s ConfigMap mounts
            while sig.recv().await.is_some() {
                match build_mtls_config(&paths.0, &paths.1, &paths.2) {
                    Ok(cfg) => {
                        s.inner.store(cfg);
                        tracing::info!("mTLS config reloaded");
                    }
                    Err(e) => tracing::error!(?e, "mTLS reload failed; keeping old"),
                }
            }
        });
    }
}
```

### 4.3 JWT validation cache (`crates/core/src/jwt.rs`)

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, TokenData};
use moka::future::Cache;

#[derive(Clone, serde::Deserialize)]
pub struct Claims { pub sub: String, pub exp: usize, pub scope: String }

pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
    cache: Cache<String, Claims>,
}

impl JwtVerifier {
    pub fn new(jwks_pem: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            key: DecodingKey::from_rsa_pem(jwks_pem)?,
            validation: Validation::new(Algorithm::RS256),
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(std::time::Duration::from_secs(300))
                .build(),
        })
    }

    pub async fn verify(&self, token: &str) -> Option<Claims> {
        if let Some(claims) = self.cache.get(token).await {
            return Some(claims);
        }
        let TokenData { claims, .. } = decode::<Claims>(token, &self.key, &self.validation).ok()?;
        self.cache.insert(token.to_string(), claims.clone()).await;
        Some(claims)
    }
}
```

### 4.4 Per-tenant rate limit middleware

```rust
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use std::num::NonZeroU32;

type Limiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

pub fn build_limiter(rps: u32) -> Arc<Limiter> {
    Arc::new(RateLimiter::keyed(Quota::per_second(NonZeroU32::new(rps).unwrap())))
}

pub async fn check(limiter: &Limiter, tenant: &str) -> Result<(), ()> {
    limiter.check_key(&tenant.to_string()).map_err(|_| ())
}
```

### 4.5 Body-buffering tradeoff (the defensible decision)

```rust
// Cargo feature `boxed_body` enables streaming forwarding (low alloc, good for big payloads).
// Default off => collect body once (smaller code, faster for JSON < 256KB).
//
// Numbers from bench: boxed=200µs add-on@10MB, collected=80µs@1KB but allocates ~req_size.
// Pingora's choice was boxed for general traffic; for an internal proxy on small JSON,
// collected wins. Document this in README. Hiring panel question: "why is the default off?"

#[cfg(not(feature = "boxed_body"))]
async fn forward_body(body: hyper::body::Incoming) -> anyhow::Result<Body> {
    let bytes = http_body_util::BodyExt::collect(body).await?.to_bytes();
    Ok(http_body_util::Full::new(bytes))
}

#[cfg(feature = "boxed_body")]
async fn forward_body(body: hyper::body::Incoming) -> anyhow::Result<http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>> {
    use http_body_util::BodyExt;
    Ok(body.boxed())
}
```

## 5. Deployment

- Same Fly.io 2-region as P2.
- Certs via Let's Encrypt + cert-manager equivalent (build a tiny ACME script).
- `kill -USR1 $(pidof ferryman-edge)` to hot-reload — demo this in a screencast.

## 6. Eval / benchmarks

- TLS handshake p99 < 50ms with full mTLS chain validation.
- 50k rps with mTLS + JWT validation enabled, p99 < 8ms.
- Hot-reload: stream `wrk2` continuously, trigger SIGUSR1 → demonstrate zero failed requests during reload.
- Cert chain: 4 intermediate CAs, document validation cost.

## 7. Source references

- Pingora paper / Cloudflare engineering blog.
- rustls 0.23 release notes (provider selection).
- gemini-research.md Domain 2 (RouterService + boxed_body deep dive).
