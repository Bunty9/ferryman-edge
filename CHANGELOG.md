# Changelog

All notable changes to `ferryman-edge-core` and `ferryman-edge` (the proxy).
Both crates share one version. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor bumps may break).

## [Unreleased]

## [0.1.2] — 2026-10-06

### Security
- Harden dot-segment path validation (port of ferryman 0.2.3's check).
  Migration: more request paths that resolve to `.` or `..` segments are now
  answered `400 bad path` before routing. Encoded slashes inside an ordinary
  segment are still allowed. Clients that relied on such paths reaching an
  upstream must change.

### Added
- Config: `[limits]` table (`max_request_body_bytes`, `request_body_timeout_secs`,
  `upstream_timeout_secs`, `tls_handshake_timeout_secs`,
  `first_request_timeout_secs`, `h2_max_concurrent_streams`,
  `shutdown_drain_secs`; defaults unchanged, boot-only) and per-route
  `health_path` / `health_disabled`, via new `parse_config`, `ConfigExt`,
  `Limits`, `RouteExt`, `build_table_ext`, `Upstream::with_health`,
  `Upstream::health_path()`, `Upstream::health_disabled()`, and
  `reload::spawn_jwt_reload`.
  `health_path` changes the probed path; `health_disabled` skips the active
  probe (the breaker is then driven by requests only).
  `health_interval_secs = 0` is now rejected at load (it previously
  panicked the health task).
- `ferryman_edge::serve_with` and `proxy::handle_with` take `Limits`; `serve` and
  `handle` keep the old behaviour via `Limits::default()`. The server applies
  `[limits]` at boot.
- The JWT public key is reloaded on SIGUSR1 (previously only read at boot, so
  IdP key rotation needed a restart). The boot-time path is re-read, the token
  cache is invalidated, and a bad file keeps the old key. Adds
  `JwtVerifier::reload_key`. Single key: no overlap window.
- `SECURITY.md`: supported versions and private vulnerability reporting.

### Changed
- Release workflow split into verify, attest, publish and release jobs:
  the `.crate` files get build provenance (`gh attestation verify`), publish
  skips crates already on crates.io so a failed run can simply be re-run, and
  `contents: write` is held only by the release job. Actions are pinned by
  SHA (also the CI doctest job).
- Dependency cleanup: removed unused `tower`, `tower-http`, `tokio-util`,
  `url`, `thiserror`, `parking_lot`, `tokio-rustls`, `hyper`, `hyper-util`
  and `rustls-pki-types` declarations, plus reqwest's unused `json` feature
  in `ferryman-edge-core`. No behaviour change.
- CI gates: MSRV (1.88) check, doctests, and `cargo-semver-checks` against
  the last crates.io release.
- Docs: corrected the README stack table and comments about the crypto
  provider and upstream HTTP version.

### Fixed
- Upgrade/WebSocket (`Upgrade` other than `h2c`) and `CONNECT` requests now
  get a clear `501` instead of being silently forwarded as plain requests.
  The check runs before route lookup, so unrouted paths also get 501.
  `edge-demo` now runs 56 checks.

## [0.1.1] — 2026-09-30

No code changes in either crate.

### Added
- Reference examples, built and run in CI:
  [`examples/edge-demo`](https://github.com/Bunty9/ferryman-edge/tree/main/examples/edge-demo)
  (the proxy in front of sample services, 55 end-to-end checks, and a
  docker-compose topology with Prometheus) and
  [`examples/embed-core`](https://github.com/Bunty9/ferryman-edge/tree/main/examples/embed-core)
  (ferryman-edge-core inside an axum service).
- Project guide at https://bunty9.github.io/ferryman-edge/ (now the crates'
  homepage).

### Changed
- Releases are published from CI through crates.io Trusted Publishing
  (OIDC); no long-lived API token is used.
- READMEs: install section, crates.io / docs.rs badges.

### Fixed
- Docker image: builder pinned to bookworm to match the distroless runtime's
  glibc; `.dockerignore` keeps `target/` and keys out of the build context.

## [0.1.0] — 2026-09-28

### Added
- mTLS termination on rustls 0.23 + aws-lc-rs; client certs required and
  chained to a configured CA bundle; ALPN h2 / http/1.1.
- RS256 JWT auth with a moka cache; `exp` re-checked on cache hits, `nbf`
  enforced, optional `iss` / `aud`.
- Per-tenant GCRA rate limiting keyed by JWT `sub` (`tenant_rps = 0`
  disables it).
- Segment-boundary longest-prefix routing with a lock-free Closed / Open /
  HalfOpen circuit breaker per upstream and an active health checker.
- SIGUSR1 hot reload of TLS material and routes without dropping
  connections; breaker state kept for unchanged routes.
- Graceful drain on SIGTERM / SIGINT.
- `boxed_body` feature: stream request and response bodies instead of
  collecting them.
- Prometheus metrics (requests, auth failures, rate limiting, TLS
  handshakes, breaker state, upstream health).

[Unreleased]: https://github.com/Bunty9/ferryman-edge/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/Bunty9/ferryman-edge/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Bunty9/ferryman-edge/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Bunty9/ferryman-edge/releases/tag/v0.1.0
