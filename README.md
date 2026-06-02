# ferryman-edge

> Programmable mTLS L7 reverse proxy in Rust — extends [`ferryman`](../ferryman/)
> (P2) with rustls 0.23 + aws-lc-rs mTLS termination, in-line RS256 JWT
> validation with an LRU verification cache, per-tenant GCRA rate
> limiting, and a SIGUSR1-driven hot-reload that flips cert chains and
> routing tables without dropping live connections. Pingora-class chops at
> miniature scale.

[![ci](https://img.shields.io/badge/ci-pending-lightgrey.svg)](./.github/workflows/ci.yml)
[![crates.io](https://img.shields.io/badge/crates.io-pending-lightgrey.svg)](#)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

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

Pinned versions live in [`Cargo.toml`](./Cargo.toml).

## Quick start

```bash
# 1. Generate a test mTLS chain (root + 3 intermediates + server + 1 client + RSA JWT keypair).
./scripts/gen-test-certs.sh

# 2. Build + run against the example config (mTLS terminate on :8443).
cargo run -p ferryman-edge-server -- --config config.toml

# 3. Call with a valid client cert:
curl -i --cacert certs/ca.crt \
        --cert   certs/client.crt \
        --key    certs/client.key \
        https://localhost:8443/svc-a/hello

# 4. Hot-reload cert + routing table atomically:
kill -USR1 $(pidof ferryman-edge-server)
```

## Design tradeoffs

P4 makes three decisions worth defending in a hiring loop.

### (a) `boxed_body` is off by default

Cargo feature `boxed_body` streams the request body to the upstream via
`http_body_util::BoxBody`. With it off, the proxy collects the body once
into a `Full<Bytes>` before forwarding.

Numbers from spec: `boxed` adds ~200 µs per request at 10 MB; `collected`
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

## Bench targets (per `projects-l3-l4.md` § P4)

```bash
# Sustain 50k rps with mTLS + JWT enabled.
wrk2 -c 1000 -t 16 -R 50000 -d 60s \
     -s benches/wrk2.lua \
     https://localhost:8443/svc-a/echo

# Zero-loss reload bench: sustains wrk2 while flipping SIGUSR1 mid-run.
./benches/reload.sh 60 50000
```

| Metric                                                            | Target          |
| ----------------------------------------------------------------- | --------------- |
| Throughput @ mTLS + JWT                                           | 50,000 rps      |
| p99 latency                                                       | < 8 ms          |
| TLS handshake p99 (full chain validation)                         | < 50 ms         |
| Cert chain depth in bench                                         | 4 intermediates |
| Hot-reload during sustained wrk2                                  | zero failed reqs|

## Repository layout

```
ferryman-edge/
  Cargo.toml                       # workspace
  config.toml                      # example: TLS paths, JWKS, 2 upstreams, rps cap
  crates/
    core/                          # tls, jwt, ratelimit, route, health, config
    server/                        # tokio-rustls acceptor, proxy handler, SIGUSR1 reload
  certs/                           # generated, gitignored (see scripts/gen-test-certs.sh)
  scripts/
    gen-test-certs.sh              # root + 3 intermediates + server + client + JWT keypair
  benches/
    wrk2.lua                       # throughput target script
    reload.sh                      # zero-loss reload bench (wrk2 + kill -USR1)
  Dockerfile                       # cargo-chef multi-stage, distroless final
  fly.toml                         # Fly.io 2-region (sin + iad)
  deny.toml                        # cargo-deny config
  rust-toolchain.toml              # stable channel
  .github/workflows/ci.yml         # fmt + clippy + nextest + deny + criterion + mTLS smoke
  docs/
    specs/2026-05-28-ferryman-edge-design.md
    plans/2026-05-28-ferryman-edge-phase-1-scaffold.md
  PROGRESS.md
```

## Roadmap

Phase 1 (scaffold + `cargo check` green + first handshake accepted on
:8443) is the current sprint — see
[`docs/plans/2026-05-28-ferryman-edge-phase-1-scaffold.md`](./docs/plans/2026-05-28-ferryman-edge-phase-1-scaffold.md).
Phase 2 wires the `tokio-rustls` acceptor + JWT/ratelimit middleware
into the request path and takes wrk2 numbers. Subsequent phases harden
the cert-rotation story and ship the Fly.io demo. See
[`PROGRESS.md`](./PROGRESS.md).

## License <a id="license"></a>

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](./LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
