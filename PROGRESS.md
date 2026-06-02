# PROGRESS — ferryman-edge

> Per-sprint tracker. Template adapted from `project-plan.md` § 7,
> customised for P4 (ferryman-edge) bench targets and the Phase C
> sequencing in `backend-cloud-roadmap.md` § 2 (weeks 23–30). P4 extends
> P2 (`ferryman/`) — the scaffold is a sibling project, not a fork, and
> deliberately mirrors P2's conventions so the diff between them reads
> cleanly in a hiring loop.

## Sprint — Phase 1 scaffold

- [x] Workspace `Cargo.toml` with `crates/core` + `crates/server`, P4
      stack pins (`rustls` 0.23 + `aws-lc-rs`, `tokio-rustls` 0.26,
      `jsonwebtoken` 9, `moka` 0.12, `governor` 0.7).
- [x] `crates/core/src/route.rs` — `Upstream`, `RouteTable`, `SharedTable`
      (verbatim from P2).
- [x] `crates/core/src/health.rs` — `health_loop` (verbatim from P2).
- [x] `crates/core/src/config.rs` — extended `ConfigToml` with `TlsToml`,
      `JwtToml`, `tenant_rps`.
- [x] `crates/core/src/tls.rs` — `build_mtls_config` + `ReloadingTls`
      (SIGUSR1 reload).
- [x] `crates/core/src/jwt.rs` — `Claims`, `JwtVerifier` with moka LRU.
- [x] `crates/core/src/ratelimit.rs` — `Limiter`, `build_limiter`, `check`
      (governor GCRA).
- [x] `crates/server/src/main.rs` — `tokio-rustls` acceptor boot
      (`todo!()` on the per-connection auth pipeline), Prometheus
      exporter, SIGUSR1 route reload, aws-lc-rs provider install.
- [x] `crates/server/src/proxy.rs` — `handle` + cfg-gated `forward_body`.
- [x] `crates/server/src/reload.rs` — SIGUSR1-based routing-table reload.
- [x] `config.toml` — TLS paths, JWKS path, two upstreams, per-tenant
      rps cap.
- [x] `certs/.gitkeep` + `.gitignore` carve-outs for `*.pem`/`*.key`/`*.crt`.
- [x] `scripts/gen-test-certs.sh` — root + 3 intermediates + server +
      client + RSA JWT keypair (executable).
- [x] `Dockerfile` — cargo-chef multi-stage, distroless `cc-debian12`
      final (NOT scratch — aws-lc-rs needs libc).
- [x] `fly.toml` — 2-region (`sin` + `iad`); raw TCP service for mTLS.
- [x] `.github/workflows/ci.yml` — fmt + clippy + nextest + deny + bench
      + **mTLS smoke** (curl --cacert --cert --key).
- [x] `benches/reload.sh` — wrk2 + `kill -USR1` zero-loss reload check
      (executable).
- [x] `benches/wrk2.lua` — JWT-header harness.
- [x] `deny.toml`, `rust-toolchain.toml`, `.gitignore`.
- [x] `README.md` with **Design tradeoffs** defending boxed_body /
      SIGUSR1 / aws-lc-rs.
- [x] `docs/specs/2026-05-28-ferryman-edge-design.md` (full P4 spec, no
      personal info).
- [x] `docs/plans/2026-05-28-ferryman-edge-phase-1-scaffold.md`.
- [ ] `cargo check --workspace` passes locally (verified at end of
      scaffold).
- [ ] `cargo run -p ferryman-edge-server -- --config config.toml`
      binds `:8443`, a curl with valid client cert completes the
      handshake.

## Next sprint — Phase 2: real request path under mTLS + JWT

- [ ] Fill in `tls_serve`: `TlsAcceptor::from(tls.current()).accept(stream)`
      → `hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
      .serve_connection(TokioIo::new(tls), service_fn(...))` wiring the
      JWT verifier + rate-limit check around `proxy::handle`.
- [ ] Reject requests with no/invalid `Authorization: Bearer …` header
      (401); reject over-quota tenants (429); both with metrics.
- [ ] Explicit circuit-breaker state machine + `ferryman_circuit_state`
      gauge (carry from P2 stretch list).
- [ ] Criterion bench in `crates/core/benches/jwt_verify.rs` — cache
      hit vs miss at 10k/100k tokens.
- [ ] `wrk2 -c 1000 -t 16 -R 50000 -d 60s` with mTLS + JWT enabled;
      target p99 < 8 ms.
- [ ] `benches/reload.sh` 60s run with zero failed requests during
      SIGUSR1 reload — the headline demo for the writeup.
- [ ] `boxed_body` feature: ship a second hyper client pool over
      `BoxBody<Bytes, hyper::Error>` so the feature flag actually
      changes runtime behaviour.
- [ ] Fly.io 2-region deploy + reload screencast.

## Done

(none yet — scaffold landing is the first commit)

## Blocked

- (none)

## Bench numbers (targets per `projects-l3-l4.md` § P4; updated weekly)

| metric                                                            | target          | current | as-of      |
|-------------------------------------------------------------------|-----------------|---------|------------|
| Throughput (`wrk2 -c 1000 -t 16 -R 50000 -d 60s`) w/ mTLS + JWT   | 50,000 rps      |         |            |
| p99 latency (mTLS + JWT)                                          | < 8 ms          |         |            |
| TLS handshake p99 (full chain validation, 4 intermediates)        | < 50 ms         |         |            |
| Hot-reload during sustained wrk2 (`benches/reload.sh`)            | zero failed reqs|         |            |
| RSS at 50k rps idle                                               | < 30 MB         |         |            |
| JWT verify cache hit vs miss speedup                              | >= 10x          |         |            |

## Blog topics surfacing

- (none yet — likely candidates: "SIGUSR1 vs notify on k8s ConfigMap
  mounts", "boxed_body vs collected: when each wins", "aws-lc-rs FIPS
  path via a feature flag")
