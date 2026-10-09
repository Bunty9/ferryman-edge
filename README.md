# ferryman-edge

> Programmable mTLS L7 reverse proxy in Rust — extends [`ferryman`](../ferryman/)
> (P2) with rustls 0.23 + ring mTLS termination, in-line RS256 JWT
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
              | ferryman-core    |  routing table, breaker,
              | 0.3 RouteTable   |  health checks
              +--------+---------+
                       |
                       v
              +--------+---------+
              | hyper client     |  pool: 1 conn per upstream * N
              | HTTP/2 multiplex |
              +--------+---------+
                       |
                       v
                  upstream svc
```

## Stack

| Layer                 | Crate / Tool                                              |
| --------------------- | --------------------------------------------------------- |
| Async runtime         | `tokio` 1.47 (full)                                       |
| HTTP server           | `hyper` 1.5 + `hyper-util`                                |
| TLS / mTLS            | `rustls` 0.23 (`ring` provider) + `tokio-rustls` 0.26 |
| AuthN                 | `jsonwebtoken` 9 + `moka` 0.12 (`future` cache, 10k × 5min) |
| Rate limit            | `governor` 0.7 (keyed GCRA)                               |
| Routing / breaker     | `ferryman-core` 0.3 (prefix table, Admission-ticket breaker, health checks, core config) |
| Config / hot-swap     | `serde` + `toml` 0.8 + `arc-swap`; reload via `SIGUSR1`   |
| Observability         | `tracing` + `metrics-exporter-prometheus` 0.16            |
| CLI                   | `clap` 4                                                  |
| Container build       | `cargo-chef` multi-stage; static musl binary in a `scratch` final image, running as `65532:65532` |
| Deploy                | Fly.io 2-region (`sin` + `iad`)                           |
| CI                    | GHA (stable + beta) + `cargo-deny` + `cargo-nextest` + criterion (non-blocking) + mTLS smoke |

Pinned versions live in [`Cargo.toml`](https://github.com/Bunty9/ferryman-edge/blob/main/Cargo.toml).

<!-- ANCHOR_END: overview -->

## Install

Prebuilt binaries (static Linux musl x86_64/aarch64; macOS x86_64/aarch64,
which link the system libSystem) are attached to every GitHub release with `SHA256SUMS` and build
provenance (`gh attestation verify <file> --repo Bunty9/ferryman-edge`):

```bash
cargo binstall ferryman-edge     # or: cargo install ferryman-edge
docker build -t ferryman-edge .  # static binary in scratch, runs as 65532
```

All three give you the `ferryman-edge-server` binary. Verify a download
with `sha256sum -c SHA256SUMS --ignore-missing` (or `shasum -a 256 -c` on
macOS) and `gh attestation verify`.

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
| TLS handshake, client cert must chain to `client_ca_path` (10 s by default; `tls_handshake_timeout_secs`) | connection closed | `ferryman_tls_handshake_failures_total`, `ferryman_tls_handshake_seconds` |
| `Authorization: Bearer <RS256 JWT>`: `exp` (also on cache hits), `nbf`, and `iss`/`aud` when configured | `401` + `www-authenticate: Bearer` | `ferryman_auth_failures_total{reason}` |
| Per-tenant GCRA limit keyed by `sub` (`[limits] tenant_rps`, `0` disables) | `429` + `retry-after: 1` | `ferryman_ratelimited_total` |
| No `.` / `..` path segments (incl. `%2e`), and no ambiguous route: a path that an upstream reading `%2F` / `%5C` / `\` as `/` or dropping `;params` would send to a different route (`/api%2Fsecret` next to a `/` catch-all) | `400` bad path | `ferryman_requests_total{status}` |
| One valid `Host` (or a request-target authority); HTTP/1.1 needs one | `400` bad host | `ferryman_requests_total{status}` |
| Not a protocol upgrade: `Upgrade` other than `h2c`, or `CONNECT` (checked before route lookup, so unrouted paths get it too) | `501` | `ferryman_requests_total{status}` |
| Longest-prefix route on a path-segment boundary, matched on a normalised path (`%XX` of unreserved characters decoded, `//` merged; the upstream still gets the raw path); no fall-through to a shorter prefix | `404` no route | |
| Breaker admission (`Upstream::try_acquire`) | `503` circuit open | |
| Body ≤ `max_request_body_bytes` if set (no cap by default; declared Content-Length checked before routing, chunked bodies mid-stream) | `413` | |
| Upload: ≤ 30 s between body frames, ≤ 300 s total (`request_body_idle_timeout_secs` / `request_body_timeout_secs`) | `408` slow client, `400` body error | |
| Upstream response head within 30 s of the end of the upload (`upstream_timeout_secs`); the response body then streams with no deadline | `502` transport error, `504` timeout | `ferryman_request_duration_seconds{upstream}` (success path) |

On the way through, the proxy strips hop-by-hop headers (both directions,
including any named in `Connection`), then stamps `x-ferryman-tenant: <sub>`
(any client-supplied value is dropped first). It keeps the client's `Host` (h2 `:authority` included) and sets
`x-forwarded-host` to it, dropping any client-sent value (per-route
`rewrite_host = true` sends the upstream authority instead), replaces `x-forwarded-for` with the peer IP (dropping client-sent
`Forwarded` / `X-Real-IP`), sets `x-forwarded-proto: https`, and downgrades
the outbound request to HTTP/1.1. Inbound protocol is pinned from ALPN
(`h2` or `http/1.1`). A connection with no request within 10 s (default;
`first_request_timeout_secs`) of the
handshake is closed (this also covers a stalled h2 preface); h2 connections
then get keep-alive pings and a 64-stream cap.

Each upstream `host:port` has one Closed / Open / HalfOpen circuit breaker
from ferryman-core 0.3, shared by every route that uses it
(`ferryman_circuit_state{upstream}`: 0/1/2; `cooldown_secs` must be ≥ 1).
It opens after `failure_threshold` (default 3) consecutive upstream
failures: transport errors, 502–504, timeouts. After `cooldown_secs`
exactly one request is let through as the probe; its result decides, and a
late result of an ordinary request can no longer close an open circuit. A
response that has started streaming never counts against the breaker however
long it lasts; only an error from the upstream body does (ferryman itself
never blames after the response head; edge does on purpose). A plain `500`
does not count, and neither does a failure caused by the client's own body
(size cap, disconnect, stall), even if the upstream had already answered.
A request that ends without a verdict on the upstream (client body error,
hang-up, h2 stream reset) hands its admission back: an abandoned half-open
probe is re-armed at once, at most once per cooldown. An upstream that hangs
up after the client stalled its upload, or paused reading the response, for
at least θ = min(1 s, `request_body_idle_timeout_secs` / 2, at least
100 ms) is not blamed either, nor is a forwarded 502–504 (a gateway whose
backend gave up on the stalled upload); an upload stall counts if it
happened at any point of the request, as in ferryman. An upstream that
fails while the client sends or reads without such a pause generally is
blamed. Known limits, where the upstream is
blamed for what the client did: its own read or write timeout is under θ;
or it has a total request or response deadline (e.g. Go `http.Server`
`ReadTimeout` / `WriteTimeout`) that a slow but steady client exceeds, since
every gap is under θ and the stall exemption does not apply. The active
health checker (`GET <upstream>/health` every `health_interval_secs`, all
upstreams concurrently; per-route `health_path` / `health_disabled` change
or skip the probe) opens and closes it too: any status below 500 counts as
up. A route reload keeps breaker state per upstream `host:port`, so an open
circuit stays open even when its routes change.

SIGTERM / SIGINT stop accepting and drain in-flight connections for up to
25 s by default (`shutdown_drain_secs`). SIGUSR1 reloads TLS material, the
routing table (including per-route `health_path` / `health_disabled`) and
the JWT public key (read from the boot-time path; the token cache is
cleared). `[limits]`, `issuer` / `audience`,
`health_interval_secs` and `keepalive_timeout_secs` are read once at boot.

Every route shares one mTLS + JWT + rate-limit policy; prefixes are
routing, not access control. Matching is case-sensitive, so an upstream that
folds case (`/API/x`) can still see a path the proxy routed elsewhere.

Set `[jwt] issuer` and `audience` for anything beyond local dev — without
them, any token signed by the issuer key is accepted, whichever service it
was minted for.

## Design tradeoffs

P4 makes three decisions worth defending in a hiring loop.

### (a) Bodies always stream

Requests and responses stream frame by frame; nothing is buffered. An
SSE or LLM response, a large download and a 50 MiB upload all pass with
constant memory. The breaker judges an upstream on its response head:
the deadline runs from the end of the upload to the head, so a long
stream is never cut and never opens the circuit. 0.1.x buffered by
default (the `boxed_body` feature streamed); buffering cut every stream
at 30 s and opened the breaker for all tenants on a slow body, so it is
gone.

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

### (c) rustls + ring over OpenSSL and aws-lc-rs

* **Pure-Rust audit story.** rustls with ring keeps the TLS stack in
  Rust plus ring's small, audited assembly.
* **Static builds.** ring builds for musl with only `musl-gcc`, which
  gives the static release binaries and the `scratch` image. aws-lc-rs
  needs a C toolchain (and CMake on some targets) per target and would
  keep the image on glibc/distroless.
* **Cost.** No FIPS build and no post-quantum `X25519MLKEM768` key
  exchange by default (rustls offers it only with aws-lc-rs). An opt-in
  `tls-aws-lc` feature may be added on request.

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
  Dockerfile                       # cargo-chef multi-stage, static musl in scratch
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
request path, circuit breaker, streaming bodies, e2e tests) are
done. Open: mTLS-capable throughput numbers against the 50k rps / p99
targets, and the Fly.io 2-region deploy. See [`PROGRESS.md`](./PROGRESS.md).

## License <a id="license"></a>

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](./LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
