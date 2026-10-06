# Publishing to crates.io

Two crates, one shared version (`[workspace.package] version`):

| Crate | What users get | Depends on |
| --- | --- | --- |
| `ferryman-edge-core` | library: TLS reload, JWT verifier, rate limiter, routing + breaker | — |
| `ferryman-edge` | `cargo install ferryman-edge` → `ferryman-edge-server` binary, plus the (unstable) `serve` library | `ferryman-edge-core` (same version) |

Publish order is always core first, then server (the release workflow
publishes each crate with `cargo publish -p`; locally
`cargo publish --workspace` does it in order).

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

v0.1.1 (2026-09-30) was the first release published by the release
workflow through Trusted Publishing. Nothing was published from a laptop.

## Decisions taken

- Names: `ferryman-edge-core` (library) and `ferryman-edge` (proxy). The
  proxy's binary stays `ferryman-edge-server`, so Docker, CI, `pidof` and
  the docs keep working.
- The proxy crate's library API (`serve`, `AppState`, `proxy`, `reload`) is
  documented as not semver-stable; it exists for the binary and its tests.

## How releases are published: Trusted Publishing

Starting with 0.1.1, releases are published by CI, not from a laptop. Pushing a
`v*` tag runs
[`.github/workflows/release.yml`](https://github.com/Bunty9/ferryman-edge/blob/main/.github/workflows/release.yml):

1. **verify** (`contents: read`): the tag must point at a commit on `main`
   and equal the workspace version, and `CHANGELOG.md` must have a
   non-empty section for that version (its text becomes the release
   notes). Tests run in both body modes, then
   `cargo package -p ferryman-edge-core -p ferryman-edge --locked` packages
   and builds both crates in isolation. The two `.crate` files and the
   release notes are uploaded as artifacts.
2. **attest** (`id-token: write`, `attestations: write`, `contents: read`;
   no checkout, no cargo): build provenance for the `.crate` files.
   `publish` needs it, so nothing is published without an attestation.
3. **publish** (GitHub environment `release`, which only accepts `v*`
   tags; `id-token: write`, `contents: read`):
   `rust-lang/crates-io-auth-action` swaps the job's GitHub OIDC token for
   a crates.io token that lives 30 minutes and is revoked when the job
   ends. Then, for `ferryman-edge-core` and then `ferryman-edge`: skip the
   crate if `crates.io/api/v1/crates/<name>/<version>` already exists,
   if it returns 404 run `cargo publish -p <name> --locked --no-verify`, and
   fail on any other status (429, 5xx). `--no-verify` is safe because verify
   already built the same commit, and it keeps dependency build scripts out
   of the job holding the crates.io token. This is idempotent, so
   re-running the job after a partial failure just finishes the job.
4. **release** (`contents: write` only; no checkout, no cargo): creates the
   GitHub release from the CHANGELOG section and attaches the `.crate`
   files (on a re-run it uploads the files to the existing release).

`contents: write` and `id-token: write` are never in the same job, the
workflow's top-level `permissions` is empty, every action is pinned by
commit SHA, and checkouts use `persist-credentials: false`. There is no
`workflow_dispatch` trigger and no binaries: a manual run has no tag to
verify, and prebuilt binaries wait for the 0.2.0 ring switch (aws-lc-rs
needs a C toolchain per cross target).

### Verifying provenance

The attested files are the `.crate` files built by `verify` and attached to
the GitHub release. Check one against this repository's workflow:

```bash
gh release download vX.Y.Z --repo Bunty9/ferryman-edge --pattern '*.crate'
gh attestation verify ferryman-edge-X.Y.Z.crate --repo Bunty9/ferryman-edge
```

`cargo publish` repackages from the same commit, so the crates.io download
should be byte-identical, but only the release asset is attested.
Compare with `sha256sum` against
`https://static.crates.io/crates/<name>/<name>-X.Y.Z.crate` if it matters.

The trust is configured on both sides:

| Where | Setting |
| --- | --- |
| crates.io, each crate → Settings → Trusted Publishing | owner `Bunty9`, repository `ferryman-edge`, workflow `release.yml`, environment `release` |
| GitHub → Settings → Environments → `release` | deployment tags: `v*` only |

Renaming `release.yml`, or the environment, breaks publishing until the
crates.io config is updated to match. No `CARGO_REGISTRY_TOKEN` secret
exists or is needed.

## Release checklist

```bash
export PATH=$HOME/.cargo/bin:$PATH

# 1. Clean tree on main, CI green for HEAD.
git status --short && gh run list --limit 1

# 2. Bump [workspace.package] version AND the version on the
#    ferryman-edge-core dependency in crates/server/Cargo.toml.
#    Move CHANGELOG "Unreleased" entries under a "## [X.Y.Z] — date" heading
#    and add the compare link at the bottom.

# 3. Local gate (CI repeats it; this just saves a round trip).
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo publish --workspace --dry-run

# 4. Commit and push; wait for CI on main to go green.
git commit -am "release: vX.Y.Z" && git push origin main

# 5. Tag and push the tag. This publishes: irreversible, since a version
#    can be yanked but never deleted or reused.
git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

After publishing:

- Check <https://docs.rs/ferryman-edge-core> and
  <https://docs.rs/ferryman-edge> build. docs.rs builds
  `aws-lc-sys`; if it fails there, add
  `[package.metadata.docs.rs]` settings rather than changing the TLS
  provider.
- `cargo install ferryman-edge` on a clean machine and run the
  README quick start.

## If something goes wrong

- **The verify job fails** (e.g. tag/version mismatch): nothing was
  published. Delete the tag (`git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z`),
  fix, and tag again.
- **The publish job fails after core went out** (a crates.io outage, a
  rate limit, or an API error such as HTTP 429/5xx on the existence check):
  use "Re-run failed jobs" on the run. The publish step skips crates
  already on crates.io and publishes the rest; re-running is safe. Don't
  re-bump the version. The `.crate` and release-notes artifacts are kept
  for 7 days, so re-run `publish` / `release` within that window; after
  that, push a new patch version instead.
- **The release job fails:** same, "Re-run failed jobs"; it creates the
  release, or uploads to the one that already exists.
- **Bad release:** `cargo yank --version X.Y.Z ferryman-edge` (and core
  if needed), fix, and release X.Y.Z+1. Yanking stops new lockfiles from
  picking it up; it does not delete it.
- **Leaked secret in a package:** yank it, rotate the secret, and contact
  crates.io support — yanked crates stay downloadable.
