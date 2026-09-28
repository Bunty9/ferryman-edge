# Publishing to crates.io

Two crates, one shared version (`[workspace.package] version`):

| Crate | What users get | Depends on |
| --- | --- | --- |
| `ferryman-edge-core` | library: TLS reload, JWT verifier, rate limiter, routing + breaker | — |
| `ferryman-edge` | `cargo install ferryman-edge` → `ferryman-edge-server` binary, plus the (unstable) `serve` library | `ferryman-edge-core` (same version) |

Publish order is always core first, then server. `cargo publish --workspace`
does this automatically.

## What's already set up

- Metadata inherited from `[workspace.package]`: `license = "MIT OR
  Apache-2.0"`, `authors`, `repository`, `homepage`, `keywords`,
  `categories`, `rust-version = "1.88"`.
- License texts: `LICENSE-APACHE` / `LICENSE-MIT` at the root, symlinked into
  each crate so they land in each package.
- READMEs: server uses the root `README.md`; core has
  `crates/core/README.md`. crates.io rewrites relative links against the
  GitHub repository.
- `exclude = ["tests/", "benches/"]` in both crates. The tests and benches
  need repo-level fixtures, including test-only private keys that secret
  scanners would flag in a published crate; they run in CI from the repo.
  The packages contain only `src/`, the manifest, README and licenses.
- The server's path dependency on core carries `version = "0.1.0"`, which
  is what crates.io uses.
- `cargo publish --workspace --dry-run` passes: both crates package and
  build in isolation, with server resolved against core through a temporary
  registry, which is how crates.io will resolve it.

## Status

v0.1.0 of both crates is published (2026-09-28). The first publish hit
crates.io's new-crate rate limit (429, "published too many new crates in a
short period"); new crates refill about one per 10 minutes. Publishing
core and then the proxy needed two waits. Later version bumps of existing
crates use a separate, looser limit.

## Decisions taken

- Names: `ferryman-edge-core` (library) and `ferryman-edge` (proxy). The
  proxy's binary stays `ferryman-edge-server`, so Docker, CI, `pidof` and
  the docs keep working.
- The proxy crate's library API (`serve`, `AppState`, `proxy`, `reload`) is
  documented as not semver-stable; it exists for the binary and its tests.

## Release checklist

```bash
export PATH=$HOME/.cargo/bin:$PATH

# 1. Clean tree on main, CI green for HEAD.
git status --short && gh run list --limit 1

# 2. Bump [workspace.package] version AND the version on the
#    ferryman-edge-core dependency in crates/server/Cargo.toml.
#    Move CHANGELOG "Unreleased" entries under the new version.

# 3. Full local gate (both feature sets).
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features ferryman-edge/boxed_body -- -D warnings
cargo test --workspace
cargo test --workspace --features ferryman-edge/boxed_body
cargo deny check

# 4. Inspect what ships, then rehearse.
cargo package -p ferryman-edge-core --list
cargo package -p ferryman-edge --list
cargo publish --workspace --dry-run

# 5. Commit, tag, push.
git commit -am "release: vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --follow-tags

# 6. Publish (irreversible: a version can be yanked, never deleted or reused).
cargo publish --workspace
```

After publishing:

- Check <https://docs.rs/ferryman-edge-core> and
  <https://docs.rs/ferryman-edge> build. docs.rs builds
  `aws-lc-sys`; if it fails there, add
  `[package.metadata.docs.rs]` settings rather than changing the TLS
  provider.
- `cargo install ferryman-edge` on a clean machine and run the
  README quick start.
- Add the crates.io and docs.rs badges back to `README.md`.
- Create a GitHub release from the tag with the CHANGELOG section.

## If something goes wrong

- Bad release: `cargo yank --version X.Y.Z ferryman-edge` (and core
  if needed), fix, publish X.Y.Z+1. Yanking stops new lockfiles from
  picking it; it does not delete it.
- Core published but server failed: fix server and publish only it
  (`cargo publish -p ferryman-edge`); don't re-bump core.
- Leaked secret in a package: yank it, rotate the secret, and contact
  crates.io support — yanked crates stay downloadable.

## Later: automate

Once releases become routine, a tag-triggered GitHub Actions job running
`cargo publish --workspace` with a scoped crates.io token (secret
`CARGO_REGISTRY_TOKEN`, `publish-update` scope limited to these two crates)
removes the local token from the loop. Not set up yet.
