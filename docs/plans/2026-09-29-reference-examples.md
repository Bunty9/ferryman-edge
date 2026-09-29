# Reference Examples Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship runnable, CI-checked examples that show every ferryman-edge
feature end to end, so someone adopting the crates can copy a working setup
instead of reverse-engineering the tests.

**Architecture:** Two example crates under `examples/`, both workspace
members with `publish = false` so CI compiles, lints and runs them.

- `examples/edge-demo` covers the **operator** path. It runs the real
  `ferryman-edge-server` binary in front of sample upstream services:
  - a `backend` binary: the upstream reference, showing how a service
    consumes `x-ferryman-tenant`;
  - an `edge-demo` driver: generates the PKI and tokens, writes the config,
    spawns everything, and walks through every feature with narrated
    assertions;
  - a docker-compose topology with Prometheus.
- `examples/embed-core` covers the **library** path. It protects your own
  axum service with `ferryman-edge-core`: mTLS via `ReloadingTls`, JWT
  middleware via `JwtVerifier`, and a per-tenant limiter.

**Tech Stack:** Rust 1.88, tokio, hyper 1 / hyper-util, axum 0.8, rustls
0.23 + aws-lc-rs, tokio-rustls, rcgen 0.13 (`aws_lc_rs` feature),
jsonwebtoken 9, reqwest 0.12 (rustls), Docker Compose v2, Prometheus.

**Spec:** user request 2026-09-29 — "a working example setup of the
ferryman-edge crate in action, implement full feature end to end in the
example so it can serve as a strong reference for someone implementing the
package in their project". Feature list = README "Request pipeline" +
`docs/operations.md`.

## Global Constraints

- MSRV `1.88` (inherited via `rust-version.workspace = true`).
- Every example crate: `publish = false`; license/edition inherited from the workspace.
- Depend on the repo crates by `path` **and** `version = "0.1"`, so a reader can
  delete `path = …` and have a crates.io dependency.
- Unix-only (the proxy uses SIGUSR1/SIGTERM); say so in the READMEs.
- `edge-demo run` must not use fixed ports: bind `127.0.0.1:0` to pick free
  ports. Only docker-compose uses fixed ports.
- Generated key material goes to a gitignored directory
  (`examples/edge-demo/.demo/` by default). Never commit keys.
- `edge-demo run` finishes in under 60 s and exits non-zero on any failed
  check. It kills every child process on success, failure and panic.
- The only new external crates are `axum 0.8` and `rcgen 0.13`
  (already a dev-dep). Everything else is already in the workspace. No
  `nix`/`libc`: signal children with `kill -<SIG> <pid>` via
  `std::process::Command`.
  *Deviation (accepted in review):* `aws-lc-rs` (already in the tree via rustls) is a direct dep of edge-demo for RSA-2048 keygen, because rcgen can't generate RSA keys; `pem` encodes them.
- `cargo fmt`, clippy `-D warnings` (both feature sets), `cargo test
  --workspace`, and `cargo deny check` stay green.
- Commits authored by `Bunty9 <Bunty9@users.noreply.github.com>`, no AI
  attribution trailers.

## Review Focus

1. **Port reuse on restart.** The breaker scenario kills a backend and
   restarts it on the same port. Expect the restart to succeed even with
   the old socket in TIME_WAIT (bind with `SO_REUSEADDR`, which tokio's
   `TcpListener::bind` sets on Unix) and the breaker to close within one
   health interval. Test: the scenario asserts 200 within 10 s of restart.
2. **Scenarios bleeding into each other through the rate limiter.** With
   `tenant_rps = 5`, reusing one `sub` across scenarios gives spurious 429s.
   Every scenario mints its own `sub`, and only the rate-limit scenario
   bursts. Test: a full `run` passes three times in a row.
3. **Children left behind** after a failed assertion or Ctrl-C. Expect no
   orphaned proxy/backend processes. Test: a `Drop` guard kills children,
   and `run` checks `pidof ferryman-edge-server` is empty at the end.
4. **Proxy binary not found or stale.** A reader runs `cargo run -p
   ferryman-edge-demo` without building the proxy. Expect a clear error
   naming the build command, not a spawn failure. Test: `locate_binary`
   unit test for the error path.
5. **Reload is asynchronous.** SIGUSR1 returns before the swap. Expect
   post-reload checks to poll with a deadline, not sleep a fixed time.
   Test: both reload checks use `eventually(deadline, …)`.

---

## File Structure

```
Cargo.toml                                # + members examples/*, + axum/rcgen workspace deps
.gitignore                                # + examples/edge-demo/.demo/
examples/
  README.md                               # index: which example for which reader
  edge-demo/
    Cargo.toml                            # package ferryman-edge-demo, bins backend + edge-demo
    README.md                             # manual walkthrough (curl) + automated run
    run.sh                                # cargo build proxy+demo, exec edge-demo run
    src/bin/backend.rs                    # sample upstream (axum)
    src/bin/edge-demo/main.rs             # CLI: setup | token | run
    src/bin/edge-demo/pki.rs              # rcgen CA, server/client leaves, JWT RSA keys
    src/bin/edge-demo/tokens.rs           # mint JWTs (iss/aud/sub/exp/nbf variants)
    src/bin/edge-demo/proxy_config.rs     # write ferryman.toml for a given topology
    src/bin/edge-demo/procs.rs            # locate binaries, spawn, wait-ready, signal, Drop kill
    src/bin/edge-demo/client.rs           # reqwest builders (mTLS identity), peer-cert fetch
    src/bin/edge-demo/scenarios.rs        # the walkthrough: one fn per feature, narrated checks
    compose/docker-compose.yml            # proxy + 3 backends + prometheus
    compose/Dockerfile.backend            # backend image
    compose/prometheus.yml
    compose/ferryman.toml                 # container-network config
  embed-core/
    Cargo.toml                            # package ferryman-edge-embed-example
    README.md
    src/lib.rs                            # AppState, router(), auth middleware, serve_tls()
    src/main.rs                           # boot from env/args, SIGUSR1 + shutdown wiring
    tests/embed.rs                        # rcgen certs + reqwest: 200 / 401 / 429 / no-cert / reload
book/src/examples.md                      # {{#include ../../examples/README.md}}
.github/workflows/ci.yml                  # + job "examples": build proxy, run edge-demo
```

---

### Task 0: Workspace scaffolding (lead, no subagent)

**Files:** Modify `Cargo.toml`, `.gitignore`. Create `examples/README.md`,
skeleton `examples/edge-demo/Cargo.toml`, `examples/embed-core/Cargo.toml`
with minimal `src` so the workspace builds.

- [ ] Add `"examples/edge-demo", "examples/embed-core"` to `[workspace] members`;
  add `axum = "0.8"` and `rcgen = { version = "0.13", default-features = false, features = ["aws_lc_rs", "pem"] }` to `[workspace.dependencies]`.
- [ ] `.gitignore`: `examples/edge-demo/.demo/`.
- [ ] Stub crates (`fn main() {}` / empty lib) → `cargo check --workspace` green.
- [ ] `cargo publish --workspace --dry-run` still only packages the two real crates.
- [ ] Commit `examples: scaffold edge-demo and embed-core workspace members`.

### Task 1: `backend` — sample upstream service

**Files:** `examples/edge-demo/src/bin/backend.rs`.

**Produces:** a binary `backend --name <svc> --bind <addr>`. It prints
`backend <name> listening on <addr>` on stdout once bound (the ready
signal for `procs`). Endpoints:

| Route | Behaviour |
| --- | --- |
| `GET /health` | `200 ok` |
| `GET /*/slow?ms=N` | sleeps N ms (cap 10 000), then echoes |
| any other path, any method | `200` JSON echo: `{"service","method","path","tenant","host","forwarded_for","forwarded_proto","body_bytes"}` |

`tenant` comes from `x-ferryman-tenant`. The request body is streamed and
counted (`body_bytes`), never buffered whole. The module doc explains the
trust model: this header is only trustworthy because the backend listens
where only the proxy can reach it.

- [ ] Implement with axum 0.8 (`Router::fallback` for the echo; body via
  `axum::body::Body::into_data_stream` counted chunk by chunk).
- [ ] Graceful shutdown on SIGTERM/SIGINT.
- [ ] Smoke by hand: `cargo run -p ferryman-edge-demo --bin backend -- --name orders --bind 127.0.0.1:9101`, then `curl -s localhost:9101/orders/1 -H 'x-ferryman-tenant: t'` shows `"tenant":"t"`.

### Task 2: `edge-demo` — setup and token subcommands

**Files:** `src/bin/edge-demo/{main,pki,tokens,proxy_config,procs,client}.rs`.

**Interfaces (produced):**

```rust
// pki.rs
pub struct Pki { pub dir: PathBuf }                  // files below live in dir
impl Pki {
    pub fn generate(dir: &Path) -> anyhow::Result<Pki>;
    //   ca.crt ca.key                 root CA (basicConstraints CA, keyUsage certSign)
    //   server.crt server.key         leaf, SAN localhost + 127.0.0.1, serverAuth
    //   client.crt client.key         leaf, clientAuth, signed by ca
    //   rogue-ca.crt rogue-client.crt rogue-client.key   untrusted chain
    //   jwt-signing.key (PKCS#8) jwt-signing.pub (SPKI)   RSA-2048 issuer key
    //   jwt-other.key                 RSA key the proxy does NOT trust
    pub fn rotate_server_cert(&self) -> anyhow::Result<()>; // new leaf, same CA
}
// tokens.rs
pub const ISSUER: &str = "https://issuer.demo.local";
pub const AUDIENCE: &str = "ferryman-edge";
pub struct TokenSpec { pub sub: String, pub ttl_secs: i64, pub iss: Option<String>, pub aud: Option<String>, pub nbf_offset: Option<i64>, pub other_key: bool }
impl TokenSpec { pub fn valid(sub: &str) -> Self; }
pub fn mint(pki: &Pki, spec: &TokenSpec) -> anyhow::Result<String>;
// proxy_config.rs
pub struct Topology { pub routes: Vec<(String, SocketAddr, Option<u64>)>, pub tenant_rps: u32, pub health_interval_secs: u64, pub default_cooldown_secs: u64 }
pub fn write(pki: &Pki, topo: &Topology, path: &Path) -> anyhow::Result<()>; // absolute cert paths, [jwt] issuer+audience set
// procs.rs
pub fn locate_binary(name: &str) -> anyhow::Result<PathBuf>; // env FERRYMAN_EDGE_BIN / BACKEND_BIN, sibling of current_exe, then PATH; error says how to build
pub struct Child { pub name: String, pub pid: u32, /* std::process::Child, log path */ }
impl Child { pub fn signal(&self, sig: &str) -> anyhow::Result<()>; pub fn kill(&mut self); pub fn wait_exit(&mut self, within: Duration) -> anyhow::Result<std::process::ExitStatus>; }
impl Drop for Child { /* kill + reap */ }
pub fn spawn_backend(name: &str, addr: SocketAddr, logs: &Path) -> anyhow::Result<Child>;           // waits for the "listening" line
pub fn spawn_proxy(config: &Path, bind: SocketAddr, metrics: SocketAddr, logs: &Path) -> anyhow::Result<Child>; // waits for TCP accept on bind
pub fn free_port() -> anyhow::Result<SocketAddr>;
pub async fn eventually<F, Fut>(deadline: Duration, what: &str, f: F) -> anyhow::Result<()> where F: FnMut() -> Fut, Fut: Future<Output = anyhow::Result<bool>>;
// client.rs
pub fn mtls_client(pki: &Pki, http1_only: bool) -> anyhow::Result<reqwest::Client>;   // trusts ca.crt, presents client identity
pub fn client_without_cert(pki: &Pki) -> anyhow::Result<reqwest::Client>;
pub fn rogue_client(pki: &Pki) -> anyhow::Result<reqwest::Client>;
pub async fn peer_cert_sha256(pki: &Pki, addr: SocketAddr) -> anyhow::Result<String>; // tokio-rustls handshake, hex SHA-256 of leaf
pub async fn raw_http1(pki: &Pki, addr: SocketAddr, request: &[u8]) -> anyhow::Result<String>; // mTLS, ALPN http/1.1, returns the status line
```

CLI (`clap`):
- `edge-demo setup [--dir DIR]` writes the PKI and a `ferryman.toml` for fixed
  local ports (proxy 8443, metrics 9090, orders 9101, inventory 9102,
  payments 9103), then prints the exact commands for the README's manual
  walkthrough.
- `edge-demo token [--dir DIR] --sub S [--ttl SECS] [--aud A] [--iss I]`
  prints a token.
- `edge-demo run [--dir DIR] [--keep]` runs Task 3.

- [ ] Unit tests (in-file): `pki::generate` → `rustls` server config builds
  (`ferryman_edge_core::build_mtls_config` on the written files succeeds);
  `tokens::mint(valid)` verifies with `JwtVerifier::new(pub).with_issuer(ISSUER).with_audience(AUDIENCE)`;
  the `other_key`, wrong-aud and expired variants fail verification;
  `locate_binary("definitely-not-here")` error text contains `cargo build -p ferryman-edge`.
- [ ] `cargo run -p ferryman-edge-demo --bin edge-demo -- setup` then run the
  proxy by hand with the generated config; curl with the printed command → 200.

### Task 3: `edge-demo run` — the narrated end-to-end walkthrough

**Files:** `src/bin/edge-demo/scenarios.rs`, wiring in `main.rs`, `run.sh`,
`README.md`.

Topology for `run`: backends `orders`, `inventory` and `payments` on free
ports. Proxy config: routes `/orders → orders`, `/inventory → inventory
(cooldown 2)`; `payments` is added only by the reload scenario.
`tenant_rps = 5`, `health_interval_secs = 1`, `default_cooldown_secs = 2`.
Output format: `▶ <scenario>` then `  ✓ <check>` / `  ✗ <check>: <why>`,
ending with `N checks passed`. Every scenario uses its own `sub`.

Scenarios and exact expectations (these are the acceptance tests):

1. **mTLS.** A valid client cert over h2 gets 200 (`resp.version() ==
   HTTP_2`); `--http1.1` gets 200. No client cert → request error
   (handshake). A cert from the rogue CA → request error.
2. **JWT.**
   - No `Authorization` → 401 with `www-authenticate: Bearer`.
   - Garbage token → 401.
   - Expired (ttl −120 s, beyond the 60 s leeway) → 401.
   - Wrong `aud` → 401; wrong `iss` → 401; `nbf` +600 s → 401.
   - Signed by `jwt-other.key` → 401.
   - Valid → 200.
3. **Identity propagation.** The echo's `tenant == sub`, even when the
   client sends `x-ferryman-tenant: admin` or `Connection: x-ferryman-tenant`
   over HTTP/1.1. `host == <orders addr>`. `forwarded_for == "127.0.0.1"`
   even when the client sends `x-forwarded-for: 6.6.6.6`.
   `forwarded_proto == "https"`.
4. **Routing.**
   - `/orders/42` → service `orders`; `/inventory/sku-1` → `inventory`.
   - `/ordersX` → 404 (segment boundary); `/nope` → 404.
   - `/orders/../inventory` → 400. Send it as a raw HTTP/1.1 request over
     tokio-rustls (`client::raw_http1`): reqwest's `url` crate normalises
     both `..` and `%2e%2e` (WHATWG) before sending.
5. **Bodies.** A POST of 64 KiB JSON has echo `body_bytes == 65536`. A
   6 MiB upload → 200 with `body_bytes == 6291456`. 9 MiB with
   Content-Length → 413.
6. **Rate limiting.** A new `sub`, 5 sequential requests → all 200. The 6th
   immediately → 429 with `retry-after: 1`. A different `sub` → 200 at the
   same moment.
7. **Circuit breaker + health.**
   - Kill `inventory`. The next `/inventory/x` → 502 or 503. Within 5 s
     `/inventory/x` → 503. `/orders/x` stays 200 throughout.
   - The metrics show `ferryman_circuit_state{upstream="<inventory addr>"} 1`.
   - Restart `inventory` on the same port → `eventually(10 s)`
     `/inventory/x` → 200, and the gauge returns to `0`.
8. **Hot reload — routes.** `/payments/p1` → 404. Rewrite the config with
   `/payments → payments` and send SIGUSR1 → `eventually(5 s)`
   `/payments/p1` → 200 from service `payments`. `/orders` is still fine.
9. **Hot reload — certificate.**
   - `peer_cert_sha256` before; `Pki::rotate_server_cert()`; SIGUSR1.
   - `eventually(5 s)` the fingerprint differs; a request on a fresh
     client → 200.
   - A reqwest client built *before* the rotation still gets 200.
10. **Metrics.** `GET http://<metrics>/metrics` contains
    `ferryman_requests_total`, `ferryman_auth_failures_total{reason="missing"}`,
    `ferryman_ratelimited_total`, `ferryman_tls_handshake_seconds`,
    `ferryman_circuit_state` and `ferryman_upstream_alive`. Print the
    `ferryman_requests_total` lines.
11. **Graceful shutdown.** Start `GET /orders/slow?ms=1500`; after 200 ms send
    SIGTERM → the slow request returns 200; the proxy exits with status 0
    within 30 s; a new connection is refused.

- [ ] Implement `scenarios.rs` as one `async fn` per scenario, taking
  `&mut Demo` (PKI, clients, children, addrs). Assertion helper
  `check(name, cond, detail)` records pass/fail and keeps going within a
  scenario. `run` exits 1 if anything failed.
- [ ] `run` prints the location of the proxy log and keeps `.demo/` for
  inspection (`--keep` also leaves the processes running for manual poking,
  until Ctrl-C).
- [ ] `run.sh`: `cargo build -p ferryman-edge -p ferryman-edge-demo "$@" && exec target/debug/edge-demo run`.
  Pass `--release` or `--features ferryman-edge/boxed_body` through.
- [ ] README walkthrough:
  1. what you'll see;
  2. `./run.sh`;
  3. the manual path: `edge-demo setup`, three `backend` commands, the
     proxy command, then one curl per feature, mirroring the scenarios;
  4. "Adapting this to your project": replace the PKI with your CA,
     `jwks_path` with your IdP's key, set `issuer`/`audience`, backends
     read `x-ferryman-tenant` and only listen on a private network;
  5. streaming mode (`--features ferryman-edge/boxed_body`).
- [ ] Verify: `examples/edge-demo/run.sh` passes 3× in a row; so does
  `run.sh --features ferryman-edge/boxed_body`; and `pidof
  ferryman-edge-server` is empty afterwards.

### Task 4: `embed-core` — ferryman-edge-core inside your own axum service

**Files:** `examples/embed-core/{Cargo.toml,README.md,src/lib.rs,src/main.rs,tests/embed.rs}`.

**Produces:**

```rust
pub struct AppState { pub jwt: Arc<JwtVerifier>, pub limiter: Option<Arc<Limiter>> }
pub fn router(state: AppState) -> axum::Router;          // GET /whoami -> {"sub","scope"}; GET /health (no auth)
pub async fn require_jwt(State, Request, Next) -> Response; // 401 + www-authenticate / 429 + retry-after; inserts Claims extension
pub async fn serve_tls(listener: TcpListener, tls: Arc<ReloadingTls>, app: axum::Router, shutdown: impl Future<Output = ()>);
    // accept loop: TlsAcceptor::from(tls.current()) per connection, hyper_util auto builder,
    // TowerToHyperService, GracefulShutdown; client cert is required by build_mtls_config
```

`main.rs`:
- Reads `EMBED_BIND`, `EMBED_CERT`, `EMBED_KEY`, `EMBED_CLIENT_CA`,
  `EMBED_JWT_PUB`, `EMBED_ISSUER`, `EMBED_AUDIENCE`, `EMBED_TENANT_RPS`.
- Installs the aws-lc-rs provider; `ReloadingTls::new` gives SIGUSR1 reload
  for free.
- `spawn_gc` for the limiter; shutdown on SIGTERM/SIGINT.
- The README shows running it against `edge-demo setup` output.

- [ ] Tests (`tests/embed.rs`, rcgen certs in a tempdir, RSA key from rcgen,
  tokens via jsonwebtoken):
  - valid → 200 with the right `sub`;
  - no token → 401 with `www-authenticate`;
  - rps = 2 → third request 429;
  - no client cert → error;
  - `/health` without a token → 200;
  - `tls.reload()` after rotating files → new fingerprint.
- [ ] README: when to embed core instead of running the proxy (a single
  service that wants mTLS + JWT without a hop), and what you give up
  (routing, breaker, a separate trust boundary).

### Task 5: docker-compose topology

**Files:** `examples/edge-demo/compose/{docker-compose.yml,Dockerfile.backend,prometheus.yml,ferryman.toml}`, README section.

Topology:
- `edge` is built from the repo `Dockerfile`. It publishes `8443`; `9090`
  stays internal. It mounts `../.demo` read-only at `/app/certs` and
  `compose/ferryman.toml` at `/app/config.toml`.
- `orders`, `inventory` and `payments` are built from `Dockerfile.backend`
  and not published, so only `edge` can reach them.
- `prometheus` scrapes `edge:9090` and publishes `9091` for the UI.

- [ ] `edge-demo setup` also writes the certs where compose expects them
  (server cert SAN includes `localhost`).
- [ ] Verify: `docker compose up -d --build`, curl through `:8443` with the
  demo client cert → 200, `docker compose kill -s SIGUSR1 edge` works,
  Prometheus target is `up`, `docker compose down`. This also closes the
  open "Docker image unverified" item in PROGRESS.md.

### Task 6: CI, book, docs (lead)

- [ ] `ci.yml` job `examples` (needs `test`): `cargo build -p ferryman-edge -p
  ferryman-edge-demo`, then `target/debug/edge-demo run`. Also run it
  with `--features ferryman-edge/boxed_body` (matrix). Upload
  `examples/edge-demo/.demo/*.log` on failure.
- [ ] `book/src/examples.md` includes `examples/README.md`; add it to `SUMMARY.md`.
  Relative links in `examples/README.md` must be absolute (book rule).
- [ ] README: an "Examples" section linking both; CLAUDE.md layout + "examples are
  part of the workspace; keep `edge-demo run` green"; PROGRESS entry.

### Task 7: Review (opus) and fixes

- [ ] A fresh reviewer on the most capable model, reading as "a developer
  adopting ferryman-edge". Is each example correct, idiomatic and
  copyable? Does every README command work verbatim? Are there scenario
  assertions that could pass for the wrong reason? Any security
  anti-patterns a reader would copy (trusting headers, keys in the repo,
  `danger_accept_invalid_certs`)?
- [ ] Fix findings, re-run the full gate and `run.sh` ×3, commit, push, confirm CI.

## Execution

User asked for subagents. Task 0 and Task 6 are done by the lead. Task 1–3
is one Sonnet agent: tightly coupled, one coherent crate. Task 4 is a
parallel Sonnet agent: independent crate. Task 5 is a Haiku agent after
Task 1 lands. Task 7 is Opus.
