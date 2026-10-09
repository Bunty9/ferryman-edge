# syntax=docker/dockerfile:1.7
#
# ferryman-edge multi-stage build.
#
# Unlike P2 (FROM scratch + musl), this builds a glibc binary and runs on
# distroless, which ships libc + the dynamic loader without the rest of a
# Debian userland. TLS is ring, so a musl/scratch image is possible later.

# ---- Stage 1: chef base (cargo-chef for layer-cacheable builds) -------------
# Builder and runtime must share a Debian release: a binary linked against
# a newer glibc (e.g. trixie's 2.41) fails to start on distroless
# cc-debian12 (2.36) with "GLIBC_2.38 not found". Bump both together.
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
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
# `distroless/cc-debian12` carries glibc + libstdc++ for the dynamic binary.
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/ferryman-edge-server /usr/local/bin/ferryman-edge-server
COPY config.toml /app/config.toml
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/ferryman-edge-server"]
CMD ["--config", "/app/config.toml"]
