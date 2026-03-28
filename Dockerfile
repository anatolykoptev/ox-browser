# syntax=docker/dockerfile:1.4

# Stage 1: Chef
FROM rust:1.93-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends cmake make g++ perl libclang-dev clang mold && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=mold"
WORKDIR /app

# Stage 2: Planner
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin ox-browser && \
    cp target/release/ox-browser /binary

# Stage 4: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl ffmpeg chromium \
    && rm -rf /var/lib/apt/lists/*
ENV CHROME_PATH=/usr/bin/chromium
COPY --from=builder /binary /usr/local/bin/ox-browser

WORKDIR /app
ENV RUST_LOG=info
EXPOSE 8901

ENTRYPOINT ["ox-browser"]
CMD ["serve", "--config", "/app/config.toml"]
