#!/usr/bin/env bash
# Build the proxy and the demo, then run the end-to-end walkthrough.
# Extra args go to `cargo build`, e.g. `./run.sh --release`.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

cargo build -p ferryman-edge -p ferryman-edge-demo "$@"
profile=debug
for arg in "$@"; do [ "$arg" = "--release" ] && profile=release; done
exec "target/$profile/edge-demo" run
