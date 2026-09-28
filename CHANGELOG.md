# Changelog

All notable changes to `ferryman-edge-core` and `ferryman-edge-server`.
Both crates share one version. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor bumps may break).

## [Unreleased]

## [0.1.0] — first release

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
