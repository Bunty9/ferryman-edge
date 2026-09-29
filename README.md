# ferryman-edge

> Programmable mTLS L7 reverse proxy in Rust — extends [`ferryman`](../ferryman/)
> (P2) with rustls 0.23 + aws-lc-rs mTLS termination, in-line RS256 JWT
> validation with an LRU verification cache, per-tenant GCRA rate
> limiting, and a SIGUSR1-driven hot-reload that flips cert chains and
> routing tables without dropping live connections. Pingora-class chops at
> miniature scale.

[![ci](https://github.com/Bunty9/ferryman-edge/actions/workflows/ci.yml/badge.svg)](https://github.com/Bunty9/ferryman-edge/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/ferryman-edge.svg)](https://crates.io/crates/ferryman-edge)
[![docs.rs](https://img.shields.io/docsrs/ferryman-edge)](https://docs.rs/ferryman-edge)
[![guide](https://img.shields.io/badge/guide-mdBook-blue.svg)](https://bunty9.github.io/ferryman-edge/)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

<!-- ANCHOR: overview -->
## The problem

Real edge proxies do **mTLS termination**, **JWT validation in-line**,
**per-route rate limiting**, and **cert hot-reload** — and they make
defensible decisions on body buffering, HTTP/2 stream control, and
connection pooling. `ferryman-edge` is the project that gets the
Cloudflare Pingora team to reply.

## Architecture (delta on top of P2)

```
                Client (with mTLS cert)
                       |
                       v
              +--------+---------+
              | rustls TLS+mTLS  |  cert reload via SIGUSR1
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

## Stack

| Layer                 | Crate / Tool                                              |
| --------------------- | --------------------------------------------------------- |
| Async runtime         | `tokio` 1.47 (full)                                       |
| HTTP server           | `hyper` 1.5 + `hyper-util` + `tower-http`                 |
| TLS / mTLS            | `rustls` 0.23 (`aws-lc-rs` provider) + `tokio-rustls` 0.26 + `rustls-pemfile` 2 + `rustls-pki-types` |
| AuthN                 | `jsonwebtoken` 9 + `moka` 0.12 (`future` cache, 10k × 5min) |
| Rate limit            | `governor` 0.7 (keyed GCRA)                               |
| Config / hot-swap     | `serde` + `toml` 0.8 + `arc-swap`; reload via `SIGUSR1`   |
| Observability         | `tracing` + `metrics-exporter-prometheus` 0.16            |
| CLI                   | `clap` 4                                                  |
| Container build       | `cargo-chef` multi-stage; **distroless** final (NOT scratch — aws-lc-rs needs libc) |
| Deploy                | Fly.io 2-region (`sin` + `iad`)                           |
| CI                    | GHA (stable + beta) + `cargo-deny` + `cargo-nextest` + criterion (non-blocking) + mTLS smoke |

Pinned versions live in [`Cargo.toml`](https://github.com/Bunty9/ferryman-edge/blob/main/Cargo.toml).

<!-- ANCHOR_END: overview -->

## Install

```bash
cargo install ferryman-edge      # installs the `ferryman-edge-server` binary
```

The reusable pieces (TLS reload, JWT verifier, rate limiter, routing +
circuit breaker) are published separately as
[`ferryman-edge-core`](https://crates.io/crates/ferryman-edge-core).

## Examples

- [`examples/edge-demo`](https://github.com/Bunty9/ferryman-edge/tree/main/examples/edge-demo)
  runs the proxy in front of sample services and exercises every feature
  end to end: mTLS, JWT claims, tenant propagation, routing, body limits,
  rate limiting, circuit breaking, hot reload of routes and certificates,
  metrics, and graceful shutdown. One command: `examples/edge-demo/run.sh`.
- [`examples/embed-core`](https://github.com/Bunty9/ferryman-edge/tree/main/examples/embed-core)
  adds mTLS, JWT auth and per-tenant rate limiting to your own axum
  service with `ferryman-edge-core`, no proxy hop.

## Quick start

```bash
# 1. Generate a test mTLS chain (root + 3 intermediates + server + 1 client + RSA JWT keypair).
./scripts/gen-test-certs.sh

# 2. Build + run against the example config (mTLS terminate on :8443).
cargo run -p ferryman-edge -- --config config.toml

# 3. Call with a valid client cert + an RS256 JWT signed by certs/jwt-priv.pem:
curl -i --cacert certs/ca.crt \
        --cert   certs/client.crt \
        --key    certs/client.key \
        -H "Authorization: Bearer $(scripts/mint-jwt.sh tenant-a 3600)" \
        https://localhost:8443/svc-a/hello

# 4. Hot-reload cert + routing table atomically:
kill -USR1 $(pidof ferryman-edge-server)
```

Configuration reference, reload, metrics and troubleshooting:
[`docs/operations.md`](./docs/operations.md).

<!-- ANCHOR: design -->
## Request pipeline

Every request passes the same gates, in order:

| Gate | Reject with | Metric |
| --- | --- | --- |
| TLS handshake, client cert must chain to `client_ca_path` (10 s timeout) | connection closed | `ferryman_tls_handshake_failures_total`, `ferryman_tls_handshake_seconds` |
| `Authorization: Bearer <RS256 JWT>`: `exp` (also on cache hits), `nbf`, and `iss`/`aud` when configured | `401` + `www-authenticate: Bearer` | `ferryman_auth_failures_total{reason}` |
| Per-tenant GCRA limit keyed by `sub` (`tenant_rps`, `0` disables) | `429` + `retry-after: 1` | `ferryman_ratelimited_total` |
| No `.` / `..` path segments (incl. `%2e`) | `400` | `ferryman_requests_total{status}` |
| Longest-prefix route on a path-segment boundary; no fall-through to a shorter prefix | `404` no route, `503` breaker open | |
| Body ≤ 8 MiB | `413` | |
| Client body read within 30 s (collected mode; read before route lookup) | `408` slow client, `400` body error | |
| Upstream round trip within 30 s, counted from when the body is ready (plus the response body in collected mode) | `502` transport/response-body error, `504` timeout | `ferryman_request_duration_seconds{upstream}` (success path) |

On the way through, the proxy strips hop-by-hop headers (both directions,
including any named in `Connection`), then stamps `x-ferryman-tenant: <sub>`
(any client-supplied value is dropped first). It rewrites `Host` to the
upstream, replaces `x-forwarded-for` with the peer IP (dropping client-sent
`Forwarded` / `X-Real-IP`), sets `x-forwarded-proto: https`, and downgrades
the outbound request to HTTP/1.1. Inbound protocol is pinned from ALPN
(`h2` or `http/1.1`). A connection with no request within 10 s of the
handshake is closed (this also covers a stalled h2 preface); h2 connections
then get keep-alive pings and a 64-stream cap.

Each upstream has a Closed / Open / HalfOpen circuit breaker
(`ferryman_circuit_state{upstream}`: 0/1/2; `cooldown_secs` must be ≥ 1).
A transport error, a 502–504, or a timeout opens it — under `boxed_body` a
timeout only counts if the client had finished uploading; after `cooldown_secs` exactly one request is let through
as the probe. A plain `500` does not trip it, and neither does a failure
caused by the client's own body (size cap, disconnect). The active health
checker (`GET <upstream>/health` every `health_interval_secs`) opens and
closes it too. A route reload keeps breaker state for rules whose prefix,
upstream, and cooldown are unchanged.

SIGTERM / SIGINT stop accepting and drain in-flight connections for up to
25 s. SIGUSR1 reloads TLS material and the routing table; the JWT settings
and `tenant_rps` are read once at boot.

Set `[jwt] issuer` and `audience` for anything beyond local dev — without
them, any token signed by the issuer key is accepted, whichever service it
was minted for.

## Design tradeoffs

P4 makes three decisions worth defending in a hiring loop.

### (a) `boxed_body` is off by default

Cargo feature `boxed_body` swaps the upstream client to
`http_body_util::BoxBody` and streams request and response bodies. With it
off, the proxy collects each body once into a `Full<Bytes>` before
forwarding. Both builds enforce the 8 MiB request cap; under streaming, a
chunked upload with no `Content-Length` that exceeds it is cut mid-stream
and answered `413`, without counting against the upstream's breaker.
Streaming mode has no separate body-read deadline: a slow upload runs
inside the upstream's 30 s budget and ends as `504`.

Estimates from the design spec (not yet measured here): `boxed` adds ~200 µs per request at 10 MB; `collected`
adds ~80 µs at 1 KB but allocates ~`req_size`. For an internal proxy
fronting JSON APIs under ~256 KB the collected path wins on code
complexity, allocator pressure (because the JSON allocator already paid
the cost), and steady-state latency. Pingora picks streaming for
general-purpose CDN traffic where payloads skew big and bimodal; that
calculus inverts for an internal API edge. Flip the feature on (`cargo
build --features boxed_body`) when your p99 latency tells you the
collect-first cost dominates.

### (b) SIGUSR1 reload over filesystem-watch

P2 (`ferryman`) reloads its routing table via `notify` filesystem events.
P4 deliberately swaps to `SIGUSR1` because:

* k8s mounts ConfigMaps via a symlink-swap dance. `notify` reports this
  as a chain of remove + create events on the *symlink target*, not the
  watched path. Without per-platform special-casing the watcher silently
  misses the reload — a worst-case failure mode for a security-sensitive
  hot-swap of TLS material.
* Editors emit a parade of `Modify` events for in-place writes that have
  no business triggering a reload (cursor moves, autosave drafts).
* `SIGUSR1` is one POSIX call with predictable semantics across every
  deploy target. The operator runs `kill -USR1 $(pidof ferryman-edge-server)`
  after `kubectl rollout restart` of the ConfigMap, or wires it into
  cert-manager's renewal hook.

Both cert reload (`tls::ReloadingTls`) and route reload
(`server/src/reload.rs`) share the same signal — one trigger swaps both
surfaces atomically from the operator's perspective.

### (c) rustls + aws-lc-rs over OpenSSL

* **Pure-Rust audit story.** rustls is the only TLS stack with a clean
  memory-safety argument all the way to the cipher implementations
  (`aws-lc-rs` is the AWS-libcrypto Rust binding; ring is the historical
  alternative). For an edge proxy that terminates customer-data TLS, that
  argument matters more than the C/Go ecosystem's parity.
* **FIPS path.** `aws-lc-rs` has a FIPS-mode build via the same crate.
  No swap-out at deploy time, no separate provider — flip a feature flag
  and recompile. OpenSSL FIPS 3.0 modules ship, but the build process is
  brittle and OS-distribution-specific.
* **Cost.** Distroless final image instead of scratch (`aws-lc-rs` needs
  libc + dynamic loader). ~12 MB extra over a musl/scratch build. Worth
  it for the audit + FIPS leverage.

## Benchmarks

```bash
# JWT verify: cache hit vs miss (criterion).
cargo bench -p ferryman-edge-core --bench jwt_verify

# Zero-loss reload check: curl workers (fresh mTLS handshake per request)
# while SIGUSR1 fires at 50% and 75% of the run. Needs the server up and
# an upstream answering /svc-a/echo.
./benches/reload.sh 60 8
```

wrk/wrk2 cannot present a TLS client certificate, so `benches/wrk2.lua`
only works against a listener without mTLS; the 50k rps target below needs
an mTLS-capable load generator and is not measured yet.

| Metric | Target | Measured |
| --- | --- | --- |
| JWT verify, cache hit vs miss | ≥ 10× | 0.68 µs vs 150 µs (~220×), criterion, dev laptop |
| Hot reload under load | zero failed reqs | 3725 / 3725 OK across 2× SIGUSR1 (60 s, 8 workers, release) |
| Throughput @ mTLS + JWT | 50,000 rps | — |
| p99 latency | < 8 ms | — |
| TLS handshake p99 (full chain validation) | < 50 ms | 119 ms, but client and server shared one box (contended) |

<!-- ANCHOR_END: design -->

## Repository layout

```
ferryman-edge/
  Cargo.toml                       # workspace
  config.toml                      # example: TLS paths, JWKS, 2 upstreams, rps cap
  crates/
    core/                          # tls, jwt, ratelimit, route, health, config (+ jwt_verify bench)
    server/                        # accept loop + auth middleware (lib), proxy, reload, e2e tests
  certs/                           # generated, gitignored (see scripts/gen-test-certs.sh)
  scripts/
    gen-test-certs.sh              # root + 3 intermediates + server + client + JWT keypair
    mint-jwt.sh                    # RS256 token signed by certs/jwt-priv.pem (openssl only)
  benches/
    wrk2.lua                       # throughput script (non-mTLS listeners only)
    reload.sh                      # zero-loss reload check (curl workers + kill -USR1)
  Dockerfile                       # cargo-chef multi-stage, distroless final
  fly.toml                         # Fly.io 2-region (sin + iad)
  deny.toml                        # cargo-deny config
  rust-toolchain.toml              # stable channel
  .github/workflows/ci.yml         # fmt + clippy + nextest + deny + criterion + mTLS smoke
  docs/
    operations.md                  # config reference, reload, metrics, troubleshooting
    publishing.md                  # crates.io release plan + checklist
  examples/
    edge-demo/                     # run the proxy: PKI, tokens, config, backends, 11 scenarios
    embed-core/                    # ferryman-edge-core inside your own axum service
  book/                            # mdBook site (GitHub Pages); includes README, docs/, CHANGELOG
    specs/2026-05-28-ferryman-edge-design.md
    plans/2026-05-28-ferryman-edge-phase-1-scaffold.md
  PROGRESS.md
  CHANGELOG.md
```

## Roadmap

Phase 1 (scaffold) and Phase 2 (mTLS + JWT + rate limit on the real
request path, circuit breaker, streaming `boxed_body`, e2e tests) are
done. Open: mTLS-capable throughput numbers against the 50k rps / p99
targets, and the Fly.io 2-region deploy. See [`PROGRESS.md`](./PROGRESS.md).

## License <a id="license"></a>

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](./LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
