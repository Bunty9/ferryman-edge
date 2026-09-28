# ferryman-edge

mTLS-terminating L7 reverse proxy in Rust: rustls 0.23 (aws-lc-rs) mTLS,
in-line RS256 JWT auth (moka cache), per-tenant governor rate limit,
per-upstream circuit breaker, SIGUSR1 hot reload. Behaviour and config are
documented in `README.md` and `docs/operations.md`; `PROGRESS.md` tracks
what is done and measured.

## Commands

cargo lives in `~/.cargo/bin` (not on the default PATH in some shells).

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features ferryman-edge/boxed_body -- -D warnings
cargo test --workspace
cargo test --workspace --features ferryman-edge/boxed_body
cargo deny check
cargo bench -p ferryman-edge-core --bench jwt_verify
```

CI runs all of these (nextest instead of `cargo test`) plus an mTLS smoke
job. Always check both feature sets: `boxed_body` changes the body type and
the error paths in `crates/server/src/proxy.rs`.

Manual end-to-end: `scripts/gen-test-certs.sh`, run the server with
`config.toml`, serve an upstream on :8001 that answers `/health`, then
`curl` with `certs/client.{crt,key}` and `$(scripts/mint-jwt.sh)`.
`benches/reload.sh [secs] [workers]` checks zero failed requests across
SIGUSR1 reloads.

## Layout

- `crates/core` — primitives, no HTTP serving: `route.rs` (RouteTable +
  lock-free breaker), `jwt.rs`, `ratelimit.rs`, `tls.rs` (ReloadingTls),
  `health.rs`, `config.rs`. JWT test keys in `crates/core/tests/fixtures`.
- `crates/server/src/lib.rs` — accept loop (`serve`) and auth middleware;
  `proxy.rs` — per-request forwarding; `reload.rs` — SIGUSR1 route reload;
  `main.rs` — boot only.
- `crates/server/tests/e2e.rs` — in-process end-to-end tests with
  rcgen-generated chains; drive `serve` directly, use `ReloadingTls::reload()`
  rather than signals (signals are process-wide).

## Invariants — keep these when changing the request path

- Hop-by-hop headers are stripped in `lib.rs` *before* `x-ferryman-tenant`
  is stamped; otherwise `Connection: x-ferryman-tenant` deletes it.
- Only upstream-caused failures may call `Upstream::mark_failed`: transport
  errors, 502–504, response-body errors, and timeouts after the upload
  finished. Client-side failures (body cap, disconnect, slow upload, 408)
  must not, or any tenant can open a route's breaker for everyone.
- The client body is read (under its own deadline) before
  `RouteTable::lookup`, because lookup may admit the request as the
  breaker's single half-open probe, and that probe must report back.
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

Both crates share one version; publish core before server
(`cargo publish --workspace` orders it). Full checklist and open decisions
in `docs/publishing.md`. Never run a real `cargo publish` without an
explicit request — it is irreversible. `cargo publish --workspace
--dry-run` is safe. When bumping, change `[workspace.package] version`
and the `version` on server's `ferryman-edge-core` dependency together,
and update `CHANGELOG.md`.

## Commits

Author is `Bunty9 <Bunty9@users.noreply.github.com>`; no AI attribution
trailers in commits or PRs (see `~/.claude/CLAUDE.md`).
