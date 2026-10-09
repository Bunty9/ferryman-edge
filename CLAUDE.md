# ferryman-edge

mTLS-terminating L7 reverse proxy in Rust: rustls 0.23 (ring) mTLS,
in-line RS256 JWT auth (moka cache), per-tenant governor rate limit,
per-upstream circuit breaker, SIGUSR1 hot reload. Behaviour and config are
documented in `README.md` and `docs/operations.md`; `PROGRESS.md` tracks
what is done and measured.

## Commands

cargo lives in `~/.cargo/bin` (not on the default PATH in some shells).

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo bench -p ferryman-edge-core --bench jwt_verify
```

CI runs all of these (nextest instead of `cargo test`) plus an mTLS smoke
job.

Manual end-to-end: `scripts/gen-test-certs.sh`, run the server with
`config.toml`, serve an upstream on :8001 that answers `/health`, then
`curl` with `certs/client.{crt,key}` and `$(scripts/mint-jwt.sh)`.
`benches/reload.sh [secs] [workers]` checks zero failed requests across
SIGUSR1 reloads.

## Layout

- `crates/core` — primitives, no HTTP serving: `route.rs` (RouteTable +
  lock-free breaker), `jwt.rs`, `ratelimit.rs`, `tls.rs` (ReloadingTls),
  `health.rs`, `config.rs`. JWT test keys in `crates/core/tests/fixtures`.
- `crates/server/src/lib.rs` — accept loop (`serve` / `serve_with`) and
  auth middleware; `proxy.rs` — per-request forwarding; `reload.rs` —
  SIGUSR1 route + JWT key reload; `main.rs` — boot only.
- `examples/edge-demo` (`ferryman-edge-demo`, publish = false): `backend`
  sample upstream + `edge-demo` driver (`setup` | `token` | `run`). `run`
  spawns the real proxy binary and checks every feature; CI runs it. `examples/embed-core`: ferryman-edge-core in an axum
  service. Behaviour changes to the request path must keep
  `cargo build -p ferryman-edge -p ferryman-edge-demo && target/debug/edge-demo run`
  green; update its scenarios and README when behaviour changes.
- `crates/server/tests/e2e.rs` — in-process end-to-end tests with
  rcgen-generated chains; drive `serve` directly, use `ReloadingTls::reload()`
  rather than signals (signals are process-wide).

## Invariants — keep these when changing the request path

- Hop-by-hop headers are stripped in `lib.rs` *before* `x-ferryman-tenant`
  is stamped; otherwise `Connection: x-ferryman-tenant` deletes it.
- The 400 bad-path and 501 upgrade/CONNECT checks run in `proxy::handle_checked`
  (called by `handle` and `handle_with`)
  *before* `RouteTable::lookup` (a request that returns without reporting
  back would leak the half-open probe slot). `Upgrade` is stripped as
  hop-by-hop, so `lib.rs` computes `proxy::wants_upgrade` before stripping
  and passes it to `handle_checked`; `h2c` is exempt.
- Only upstream-caused failures may count against the breaker: transport
  errors, 502–504 response heads, and the upstream timer (which fires only
  after the upload finished, or when hyper stopped reading the body while
  the client was not stalling). Client-side failures (body cap 413,
  idle/total upload deadline 408, disconnect 400) and anything that happens
  after the response head (a long or broken response body) must not, or any
  tenant can open a route's breaker for everyone. They must not call
  `mark_success` either, or a client could close an open breaker by
  aborting an upload.
- Bodies stream; nothing is buffered. Every rejection that needs no
  upstream (400 bad path, 501 upgrade, 413 declared Content-Length, 404)
  happens before `RouteTable::lookup`, because lookup may admit the request
  as the breaker's single half-open probe. A probe that then fails on the
  client's side reports nothing; the breaker re-arms a stale probe after
  one cooldown.
- `lookup` never falls through to a shorter prefix when the matching
  upstream isn't routable; it returns `None` (503).
- Outbound requests are downgraded to HTTP/1.1; hyper-util rejects
  h2-versioned requests on HTTP/1 upstream connections.
- Metric labels stay bounded: `status`, upstream `host:port`, fixed
  `reason` values. Never label by tenant or path.
- `x-forwarded-for` is replaced with the peer IP, not appended.

## Gotchas

- `pgrep -x ferryman-edge-server` never matches (15-char kernel `comm`);
  use `pidof`. Never `pkill -f` from a shell whose command line contains
  the pattern — it kills that shell.
- `tokio::select!` `if` guards are evaluated once on entry, not when a
  branch fires; re-check state inside the branch.
- jsonwebtoken 9 only checks `iss`/`aud` when present unless they are in
  `required_spec_claims` (`with_issuer`/`with_audience` handle this).
- Dockerfile builder and distroless runtime must share a Debian release
  (glibc); both are bookworm.
- Running the server in the background from a tool call: redirect its
  stdout/stderr to a file, or a trailing `| tail` waits forever.

## Documentation site

`book/` is an mdBook published to https://bunty9.github.io/ferryman-edge/ by
`.github/workflows/docs.yml` on pushes touching docs. It `{{#include}}`s
`README.md` (via the `<!-- ANCHOR: overview/design -->` comment pairs —
keep them), `docs/operations.md`, `docs/publishing.md` and `CHANGELOG.md`,
so edit those files, not copies. Links inside included regions must be
absolute or they break in the book. Build locally with
`mdbook build book` (output `book/book/`, gitignored).

## Releasing

Both crates share one version. Publishing is done by
`.github/workflows/release.yml` (jobs verify, attest, publish, release; the
publish job is idempotent, so a failed run is recovered by re-running it)
on a `v*` tag push, through crates.io Trusted Publishing (OIDC; environment
`release`); there is no registry token secret. The crates.io
trusted-publisher config pins the workflow filename `release.yml` and
environment `release` — renaming either breaks publishing. Pushing a `v*`
tag publishes irreversibly: never push one without an explicit request. `cargo publish --workspace --dry-run` is
safe. When bumping, change `[workspace.package] version` and the
`version` on server's `ferryman-edge-core` dependency together, and add a
`## [X.Y.Z]` section to `CHANGELOG.md` (the verify job requires it and
uses it as the GitHub release notes). Checklist: `docs/publishing.md`.

## Commits

Author is `Bunty9 <Bunty9@users.noreply.github.com>`; no AI attribution
trailers in commits or PRs (see `~/.claude/CLAUDE.md`).
