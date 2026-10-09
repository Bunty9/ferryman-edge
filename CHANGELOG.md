# Changelog

All notable changes to `ferryman-edge-core` and `ferryman-edge` (the proxy).
Both crates share one version. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor bumps may break).

## [Unreleased]

### Security
- Strip non-canonical spellings of proxy-asserted headers (forwarding
  headers, `x-real-ip`, `x-ferryman-tenant`) from client requests, so only
  the values the proxy sets reach the upstream.

### Changed (breaking)
- Docker image: a static musl binary in `scratch` running as `65532:65532`
  (was distroless/cc as root). Migration: mounted certs, keys and config
  must be readable by uid 65532 (volume ownership: `chgrp 65532` + `chmod
  0640`, or `chown`), or run the container with `--user`.
- `JwtVerifier::reload_key` returns `Ok(bool)` (whether the key changed).
- TLS provider is ring (was aws-lc-rs), across the proxy, tests and
  examples; `deny.toml` bans aws-lc. Library users install
  `rustls::crypto::ring::default_provider()`. No FIPS build, and the
  post-quantum `X25519MLKEM768` key exchange is no longer offered.
  TLS 1.2 stays enabled.
- Config: `[tls]` is now `[mtls]` (the old name loads with a warning; both
  together is an error). Migration: rename the table.
- Config: top-level `tenant_rps` moves to `[limits] tenant_rps` (old
  spelling loads with a warning).
- Config: `upstream_timeout_secs` and `request_body_timeout_secs` move from
  `[limits]` to the top level (ferryman-core names; old spellings load with
  a warning), joined by `keepalive_timeout_secs` (default 10 s) and
  `request_body_idle_timeout_secs` (default 30 s). The top-level timeouts reload on SIGUSR1,
  except `keepalive_timeout_secs`.
- Config: unknown keys are rejected in every table (0.1.x ignored them, so
  a typo silently kept a default). Migration: fix or remove the key the
  error names.
- HTTP/1 keep-alive idle timeout is `keepalive_timeout_secs`;
  `first_request_timeout_secs` now bounds only the first request, and on
  HTTP/1 the first-request window is the smaller of the two. Migration: if
  you raised `first_request_timeout_secs`, also set top-level
  `keepalive_timeout_secs` to the same value (a warning says so at load).
- Library: `parse_config`, `ConfigExt`, `RouteExt`, `build_table_ext` and
  `TlsToml` are replaced by `EdgeConfig::parse` (returning
  `Result<EdgeConfig, ConfigError>`, which wraps `ferryman_core::Error` as
  `ConfigError::Core`) and `MtlsToml`; `Limits` loses
  `upstream_timeout_secs` / `request_body_timeout_secs` and gains
  `tenant_rps`.
- Routing, circuit breaker, health checks and the core config now come
  from `ferryman-core` 0.3 (edge's copies are deleted).
  `ferryman-edge-core` no longer exports `route`, `health`, `RouteTable`,
  `Upstream`, `SharedTable`, `health_loop`, `build_table`, `ConfigToml` or
  `RouteToml`; it re-exports the crate as `ferryman_edge_core::ferryman_core`.
  Migration: `ferryman_edge_core::X` becomes
  `ferryman_edge_core::ferryman_core::X`; `build_table(&cfg.core)` becomes
  `build_table(cfg.core, prev)`; `Upstream::new(uri, cooldown)` becomes the
  fallible `Upstream::new(uri, BreakerConfig)` (cooldown at least 1 ms);
  `mark_success` / `mark_failed` / `is_routable` become `try_acquire` plus
  `record_success` / `record_failure` / `release` on the Admission ticket;
  `RouteTable::lookup` returns a `Route` (`.upstream`, `.rewrite_host`) and
  ignores breaker state. `proxy::handle` admits through
  `Upstream::try_acquire` and reports through the ticket.
- Breaker: one per upstream `host:port`, shared by the routes that use it
  (was one per rule). It opens after `failure_threshold` (new key, default
  3) consecutive upstream failures. A late result of an ordinary request
  can no longer close an open circuit.
- Health checks: any status below 500 counts as up (was 2xx only); probes
  run concurrently. Migration: an upstream whose health path answers 4xx
  while broken needs a real health endpoint, or `health_disabled = true`.
  Health probes no longer speak TLS: an `https://` upstream is rejected at
  load (forwarding never supported https). Migration: point the route at
  the upstream's `http://` address.
- Route prefixes match a normalised path (`%XX` of unreserved characters
  decoded, other escapes' hex uppercased, `//` merged; still
  case-sensitive), so `/%73vc-a/x` and `//svc-a/x` now reach `/svc-a`. The
  upstream receives the raw path.
- Paths that an upstream reading `%2F` / `%5C` / `\` as `/`, or dropping
  `;params`, would send to a different route than the proxy chose get
  `400 bad path` (`/api%2Fsecret` with a `/` catch-all next to `/api`),
  checked right after the dot-segment check. Migration: send plain `/`
  separators; an encoded slash that does not change the route
  (`group%2Fproject`) still passes.
- Config validation (from core): duplicate prefixes; prefixes not in
  normalised form or containing `;`, `\`, `%2F` or `%5C`; upstreams with a
  path, query or `https://` scheme; and routes sharing an upstream with
  different `cooldown_secs` / `health_path` / `health_disabled` are
  rejected. Core keys edge does not implement yet are rejected when set
  (today only `trusted_proxies`: edge always replaces forwarding headers).
  Migration: write each prefix in the normalised form the error prints;
  point `https://` upstreams at their `http://` address; remove
  `trusted_proxies`; give routes on one `host:port` the same
  `cooldown_secs`, `health_path` and `health_disabled`.
- Reload carries breaker state by upstream `host:port`, so an open
  circuit stays open across SIGUSR1 even when its routes change.
- The `upstream` metric label is core's normalised `host:port` (lowercase,
  default port filled in: `http://localhost` is `localhost:80`).
  `ferryman_upstream_alive` now follows the circuit state (1 = closed) and
  is written for `health_disabled` upstreams too. Migration: update
  dashboards and alerts that match the old label or treat
  `ferryman_upstream_alive` as the last probe result.
- Bodies always stream: the buffering (default) mode and the `boxed_body`
  feature are removed. `proxy::Body` is `BoxBody<Bytes, BoxErr>` and
  `UpstreamClient` is `Client<HttpConnector, proxy::RequestBody>`.
- No request-body cap by default (was 8 MiB). `[limits]
  max_request_body_bytes` is optional and has no upper bound; when set,
  over-cap uploads get 413. Migration: set it to keep a cap.
- `upstream_timeout_secs` runs from the end of the upload to the response
  head only; the response body has no deadline (a broken body still counts
  against the breaker, unless the client had stalled its upload or its
  reads for at least θ = min(1 s, idle gap / 2), floored at 100 ms; a
  forwarded 502–504 after such an upload stall is not blamed either, and
  an upload stall counts if it happened at any point of the request).
  Blaming a broken response body is a deliberate difference from
  ferryman, which never blames after the response head. Known limits,
  where the upstream is still blamed: its own read/write timeout is under
  θ; or it has a total request or response deadline (Go `http.Server`
  `ReadTimeout`/`WriteTimeout`) that a slow but steady client exceeds,
  since every gap is under θ. Uploads have their own idle (30 s) and total
  deadlines and get 408. The total default (`request_body_timeout_secs`)
  rises from 30 s to 300 s.
- The upstream sees the client's `Host` (h2 `:authority` included), not
  the upstream authority, plus `x-forwarded-host` with the same value; a
  client-sent `x-forwarded-host` is dropped. Migration: set
  `rewrite_host = true` on routes whose upstream needs its own authority
  as Host.
- Requests with an unusable `Host` are answered `400 bad host` before
  routing: duplicate or empty `Host`, `*`, userinfo, a path, a comma,
  non-ASCII bytes, an invalid port, or HTTP/1.1 with neither `Host` nor
  an absolute-form target. `Connection: host` no longer removes `Host`.

### Added
- Per-route `rewrite_host` (same key and meaning as ferryman-core 0.3).
- Release binaries for Linux musl (x86_64, aarch64) and macOS (x86_64,
  aarch64) with `SHA256SUMS` and build provenance; each Linux binary passes
  an mTLS + JWT smoke test before packaging. `cargo binstall ferryman-edge`.
  `ferryman-edge-server --version`.

### Fixed
- A 502–504 response whose body then breaks counts once against the
  breaker, not twice.
- One 502 no longer blackholes a route for a whole cooldown (breaker
  threshold 1 → 3).
- Upstreams without a `/health` route (most third-party apps) no longer
  flap between 503 and 200.
- A client that takes the half-open probe and then hangs up, resets its h2
  stream or fails its upload no longer holds the probe slot for a whole
  cooldown: the admission is released and the next request probes (at most
  once per cooldown, so a burst of aborts cannot turn into a probe flood).
- A gateway upstream answering 502–504 because its backend gave up on a
  client's stalled upload no longer counts against the breaker.
- A long or slow streamed response (SSE, LLM, download) is no longer cut
  at 30 s and no longer opens the route's breaker for every tenant.

### Changed
- SIGUSR1 leaves the JWT key and token cache alone when the PEM file is
  byte-for-byte unchanged (it used to flush the cache on every reload).
- `metrics-exporter-prometheus` without its push-gateway client;
  `reqwest` (now only via ferryman-core's health checker) without TLS
  (health probes are plain HTTP). `webpki-roots` and the CDLA-Permissive-2.0 licence allowance are
  gone.
- `edge-demo` uses committed test-only RSA keys for its JWT issuer
  instead of generating them.

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
