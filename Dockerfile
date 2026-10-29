# syntax=docker/dockerfile:1.7
#
# ferryman-edge: static musl binary in `scratch`, running as 65532:65532.
# ring (the only TLS provider) needs just musl-gcc, so no libc or loader
# ships in the image. Native builds only: an amd64 host builds linux/amd64,
# an arm64 host builds linux/arm64 (musl-gcc targets the host arch).

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app
ARG TARGETARCH
# rust-toolchain.toml pins `channel = "stable"`, which is not the toolchain
# this base image ships. Install that one and select it with RUSTUP_TOOLCHAIN,
# so the musl target is added to the toolchain cargo actually runs.
ENV RUSTUP_TOOLCHAIN=stable \
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CC_aarch64_unknown_linux_musl=musl-gcc
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac > /rust_target.txt \
    && rustup toolchain install stable --profile minimal --target "$(cat /rust_target.txt)" \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --target "$(cat /rust_target.txt)" --recipe-path recipe.json
COPY . .
# Copy to a fixed path: COPY --from cannot expand $(cat /rust_target.txt).
RUN cargo build --release --locked --target "$(cat /rust_target.txt)" --bin ferryman-edge-server \
    && mkdir -p /out \
    && cp "target/$(cat /rust_target.txt)/release/ferryman-edge-server" /out/

FROM scratch AS runtime
WORKDIR /app
COPY --from=builder /out/ferryman-edge-server /usr/local/bin/ferryman-edge-server
COPY config.toml /app/config.toml
# Non-root (Kubernetes Restricted PSS). Mounted certs, keys and config must
# be readable by this uid; 8443 and 9090 need no privileges.
USER 65532:65532
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/ferryman-edge-server"]
CMD ["--config", "/app/config.toml"]
