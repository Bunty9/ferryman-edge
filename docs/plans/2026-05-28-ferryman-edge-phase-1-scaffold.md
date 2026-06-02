---
title: ferryman-edge Phase 1 — Scaffold + Compile + mTLS Listener Up
status: draft
date: 2026-05-28
related:
    - ../specs/2026-05-28-ferryman-edge-design.md
    - ../../../projects-l3-l4.md
    - ../../../backend-cloud-roadmap.md
    - ../../../ferryman/docs/plans/2026-05-28-ferryman-phase-1-scaffold.md
---

# ferryman-edge Phase 1 — Scaffold + Compile + mTLS Listener Up

> **Goal:** lay down the workspace, the routing/health/TLS/JWT/ratelimit
> primitives, the container + Fly + CI story, and a `tokio-rustls`
> acceptor so that:
>
>   1. `cargo check --workspace` is green.
>   2. `./scripts/gen-test-certs.sh` produces a full root + 3-intermediate
>      chain plus a server leaf, a client leaf, and an RSA JWT keypair.
>   3. `cargo run -p ferryman-edge-server -- --config config.toml` boots
>      an mTLS listener on `:8443` and a `curl` with a valid client cert
>      completes the handshake and gets back a 404 for unmapped paths.
>
> No real upstream traffic in Phase 1. The full HTTP-layer auth wire-up
> (JWT verify, rate-limit, route, proxy) is gated behind a `todo!()` in
> `tls_serve`. Phase 2 fills it in and runs the wrk2 numbers.

**Spec source:**
[`../specs/2026-05-28-ferryman-edge-design.md`](../specs/2026-05-28-ferryman-edge-design.md).

## File inventory (checklist)

- [x] `Cargo.toml` — workspace root with `crates/core` + `crates/server`
      members. Workspace deps add `rustls` 0.23 (`aws-lc-rs`,
      `default-features = false`), `tokio-rustls` 0.26, `rustls-pemfile`
      2, `rustls-pki-types`, `webpki`, `jsonwebtoken` 9, `moka` 0.12
      (`future`), `governor` 0.7, `url` over P2's pins.
- [x] `rust-toolchain.toml` — stable + rustfmt + clippy.
- [x] `deny.toml` — same license allowlist + advisory deny as P2.
- [x] `.gitignore` — Rust + secrets + `certs/*.pem`/`*.key`/`*.crt`/`*.csr`/`*.srl`
      with a `!certs/.gitkeep` carve-out.
- [x] `config.toml` — `[tls]`, `[jwt]`, `tenant_rps`, two example routes.
- [x] `crates/core/Cargo.toml` + `crates/core/src/lib.rs` — exports
      `route`, `health`, `config`, `tls`, `jwt`, `ratelimit`.
- [x] `crates/core/src/route.rs` — `Upstream`, `RouteTable`, `SharedTable`
      (copied verbatim from P2; ferryman-edge layers atop, does not modify).
- [x] `crates/core/src/health.rs` — `health_loop` (copied verbatim from P2).
- [x] `crates/core/src/config.rs` — `ConfigToml` extended with `TlsToml`,
      `JwtToml`, `tenant_rps`; `build_table` returns the same
      `RouteTable` type as P2.
- [x] `crates/core/src/tls.rs` — `build_mtls_config` + `ReloadingTls`
      verbatim from the P4 spec. SIGUSR1-driven reload.
- [x] `crates/core/src/jwt.rs` — `Claims`, `JwtVerifier` verbatim from
      the P4 spec. moka future-cache, RS256.
- [x] `crates/core/src/ratelimit.rs` — `Limiter`, `build_limiter`, `check`
      verbatim from the P4 spec. Governor keyed GCRA.
- [x] `crates/server/Cargo.toml` + `crates/server/src/main.rs` —
      `tokio-rustls` acceptor wired (with `todo!()` for the per-connection
      auth pipeline), Prometheus exporter listener, spawns `health_loop`
      + `reload::spawn_reload`. Installs the aws-lc-rs default crypto
      provider at startup.
- [x] `crates/server/src/proxy.rs` — `handle` plus `forward_body`
      cfg-gated on `boxed_body`. Default off; Phase-1 keeps the collected
      path under both arms (BoxBody-client refactor is Phase 2).
- [x] `crates/server/src/reload.rs` — SIGUSR1-based routing-table reload;
      defends in docstring against `notify` filesystem watching on k8s.
- [x] `certs/.gitkeep` — keeps the directory in git; everything else is
      gitignored.
- [x] `scripts/gen-test-certs.sh` — root CA + 3 intermediates + server
      leaf + client leaf + RSA JWT keypair via `openssl`. Executable.
- [x] `Dockerfile` — multi-stage `cargo-chef` + distroless `cc-debian12`
      final image (NOT scratch — `aws-lc-rs` needs libc + dynamic loader).
- [x] `fly.toml` — 2-region (`sin` + `iad`); raw TCP service on :8443,
      not behind Fly managed certs (mTLS terminates inside the proxy).
- [x] `.github/workflows/ci.yml` — stable + beta matrix; fmt, clippy,
      nextest, deny, criterion (non-blocking), **mTLS smoke** job that
      runs `gen-test-certs.sh` + boots the binary + `curl --cacert
      --cert --key`.
- [x] `benches/reload.sh` — wrk2 + `kill -USR1` mid-bench, fails if any
      requests were dropped during reload.
- [x] `benches/wrk2.lua` — Authorization header placeholder so the bench
      exercises the JWT verifier + cache.
- [x] `README.md` — problem, ASCII arch diagram, stack table, **Design
      tradeoffs** section defending boxed_body / SIGUSR1 / aws-lc-rs,
      bench targets, license.
- [x] `docs/specs/2026-05-28-ferryman-edge-design.md` — full P4 spec text
      with frontmatter (no `author`).
- [x] `docs/plans/2026-05-28-ferryman-edge-phase-1-scaffold.md` — this
      file.
- [x] `PROGRESS.md` — template from `project-plan.md` § 7 with P4
      bench targets.

## Exit criteria

1. `cargo check --workspace` passes locally with no errors.
2. `./scripts/gen-test-certs.sh` produces a populated `certs/` directory
   containing at minimum `ca.crt`, `server.crt`, `server.key`,
   `client.crt`, `client.key`, `ca-bundle.crt`, `jwt-pub.pem`,
   `jwt-priv.pem`.
3. `cargo run -p ferryman-edge-server -- --config config.toml` boots an
   mTLS listener on `:8443` and a curl with a valid client cert
   (`--cacert certs/ca.crt --cert certs/client.crt --key
   certs/client.key`) completes the TLS handshake. HTTP-layer behaviour
   is Phase 2 — the in-process `todo!()` will panic the worker task on
   the first request after the handshake, which is the intended Phase 1
   surface.

## What's deferred to Phase 2

- Filling in `tls_serve`: wrap `_stream` in `TlsAcceptor::from(_tls.current())`,
  pass through `hyper_util::server::conn::auto::Builder`, wire JWT verify
  + rate-limit check around `proxy::handle`.
- Explicit circuit-breaker state machine (`closed`/`open`/`half_open`) +
  `ferryman_circuit_state` gauge.
- `wrk2` 50k-rps mTLS + JWT bench against a local upstream stub.
- `boxed_body` feature: actually build a separate hyper client pool
  parameterised over `BoxBody<Bytes, hyper::Error>`.
- Fly.io 2-region deploy + reload screencast.
- Criterion harness for `JwtVerifier::verify` cache hit vs miss.
