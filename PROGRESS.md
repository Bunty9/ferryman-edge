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
- [x] `crates/core/src/config.rs` — `EdgeConfig` (0.2.0): `[mtls]` (alias `[tls]`),
      `[jwt]`, `[limits] tenant_rps` over the core-shaped `ConfigToml`.
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
- [x] `cargo check --workspace` passes locally (verified at end of
      scaffold).
- [x] `cargo run -p ferryman-edge -- --config config.toml`
      binds `:8443`, a curl with valid client cert completes the
      handshake.

## Sprint — Phase 2: real request path under mTLS + JWT

- [x] `serve` accept loop in `crates/server/src/lib.rs`: per-connection
      TLS handshake (10 s timeout, latency histogram), protocol pinned
      from ALPN, HTTP/1 header-read timeout, h2 keep-alive + stream cap,
      accept errors back off instead of exiting, graceful drain on
      SIGTERM/SIGINT.
- [x] Bearer JWT required (401 + `www-authenticate`), per-tenant GCRA
      (429 + `retry-after`), both with metrics; `x-ferryman-tenant`
      stamped from the verified `sub`.
- [x] Explicit circuit-breaker state machine + `ferryman_circuit_state`
      gauge; single-flight half-open probe; state survives route reload.
- [x] Criterion bench `crates/core/benches/jwt_verify.rs` — cache hit
      vs miss.
- [x] `boxed_body` feature streams both directions through a
      `BoxBody` client.
- [x] `benches/reload.sh` zero-failed-request run across SIGUSR1 (curl
      workers; wrk2 cannot do mTLS).
- [x] e2e suite (`crates/server/tests/e2e.rs`) under both feature sets;
      CI mTLS smoke asserts status codes instead of `|| true`.
- [x] Two Opus review passes: fall-through routing, breaker trips caused
      by client body errors or slow uploads, `Connection`-nominated tenant
      strip, XFF spoofing, dot-segment routing, `iss`/`aud`/`nbf`, silent
      post-handshake clients. Fixed; tests cover routing, the tenant
      strip, XFF, oversized chunked upload vs breaker, dot segments, JWT
      claims, and the 10 s idle-connection close. The 30 s timer paths
      (408, slow upload) are untested.
- [x] Docker: the original image built but could not start
      (`GLIBC_2.38 not found`: trixie builder vs cc-debian12 runtime).
      Builder pinned to bookworm; verified 2026-09-30 via the edge-demo
      compose stack (serves mTLS + JWT, SIGUSR1 reload, SIGTERM drain with
      exit 0). `.dockerignore` cut the build context from ~2.4 GB to 417 kB.
- [x] `cargo deny check` clean (4 advisories cleared by `cargo update`,
      `rustls-pemfile` replaced by `rustls-pki-types` PEM API).

## 0.1.2 patch (prepared on branch `edge-0.1.2`, not yet released)

- [x] CI gates (MSRV 1.88, doctests, semver-checks), `SECURITY.md`,
      unused-dependency cleanup.
- [x] Hardened dot-segment path validation (400 `bad path`).
- [x] `Upgrade` (other than h2c) and `CONNECT` answered 501 before lookup.
- [x] `[limits]` table (boot-only) and per-route `health_path` /
      `health_disabled` (reloaded on SIGUSR1); `health_interval_secs = 0`
      rejected.
- [x] JWT public key reloaded on SIGUSR1 (no overlap window).
- [x] Release workflow split into verify, attest, publish, release.
- [x] Version bumped to 0.1.2, CHANGELOG section dated; tag and publish
      are separate, explicit steps.

## Next sprint — Phase 3: numbers + deploy

- [ ] mTLS-capable load generator (e.g. a small hyper/rustls client or
      k6 with client certs) for the 50k rps / p99 < 8 ms targets.
- [ ] TLS handshake p99 with the 4-intermediate chain, client on a separate host.
- [ ] Fly.io 2-region deploy with certs from secrets + reload screencast.
- [x] Reload the JWT key on SIGUSR1 (done in 0.1.2).
- [ ] Optional: reload `tenant_rps` on SIGUSR1 (boot-time only today).
- [ ] Optional: global in-flight body-bytes budget (today bounded per
      connection: 64 streams × 8 MiB).

## Examples

- [x] `examples/edge-demo`: `edge-demo run` checks every feature
      against the real binary (65 checks, ~73 s, mostly the 65 s SSE stream; one body mode).
      Manual walkthrough and docker-compose topology (proxy + 3 backends +
      Prometheus) verified by hand 2026-09-30.
- [x] `examples/embed-core`: ferryman-edge-core in an axum service, 8 tests.

## Releases

- v0.1.0 (2026-09-28): `ferryman-edge-core` and `ferryman-edge` on
  crates.io; GitHub release from tag `v0.1.0`.
- v0.1.1 (2026-09-30): first release through crates.io Trusted Publishing
  (`release.yml`, environment `release`); crates.io records GitHub
  provenance (repo, run id, commit) instead of a user token.

## Done

- Phase 1 scaffold.
- Phase 2 request path (see above).

## Bench numbers (targets per `projects-l3-l4.md` § P4; updated weekly)

| metric                                                            | target          | current                  | as-of      |
|-------------------------------------------------------------------|-----------------|--------------------------|------------|
| Throughput (`wrk2 -c 1000 -t 16 -R 50000 -d 60s`) w/ mTLS + JWT   | 50,000 rps      | not measured (no mTLS load gen) |     |
| p99 latency (mTLS + JWT)                                          | < 8 ms          |                          |            |
| TLS handshake p99 (full chain validation, 4 intermediates)        | < 50 ms         | 119 ms p99 / 37 ms p50, 3 intermediates, server-side; same box as 8 curl clients, so contended | 2026-09-26 |
| Hot-reload during sustained load (`benches/reload.sh`)            | zero failed reqs| 0 / 3725 failed (60 s, 8 workers, 2× SIGUSR1, release) | 2026-09-26 |
| RSS at 50k rps idle                                               | < 30 MB         | 16 MB after the 60 s reload run (not at 50k rps) | 2026-09-26 |
| JWT verify cache hit vs miss speedup                              | >= 10x          | ~220x (0.68 µs vs 150 µs) | 2026-09-26 |

## Blog topics surfacing

- (none yet — likely candidates: "SIGUSR1 vs notify on k8s ConfigMap
  mounts", "boxed_body vs collected: when each wins", "aws-lc-rs FIPS
  path via a feature flag")
