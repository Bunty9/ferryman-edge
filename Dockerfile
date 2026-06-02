# syntax=docker/dockerfile:1.7
#
# ferryman-edge multi-stage build.
#
# Unlike P2 (FROM scratch + musl), P4 lands on distroless because rustls'
# `aws-lc-rs` provider transitively pulls aws-lc-sys, which needs a working
# libc + dynamic loader. Distroless ships those without the rest of a
# Debian userland.

# ---- Stage 1: chef base (cargo-chef for layer-cacheable builds) -------------
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

# ---- Stage 2: planner (compute the recipe of dependencies) ------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Stage 3: builder (cook deps, then build the actual workspace) ----------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin ferryman-edge-server

# ---- Stage 4: distroless runtime --------------------------------------------
# `distroless/cc-debian12` carries glibc + libstdc++ which aws-lc-rs needs.
# Not scratch — rustls' aws-lc-rs provider links libc and the dynamic loader.
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/ferryman-edge-server /usr/local/bin/ferryman-edge-server
COPY config.toml /app/config.toml
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/ferryman-edge-server"]
CMD ["--config", "/app/config.toml"]
