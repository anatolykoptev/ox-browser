# Stage 1: Chef — compute recipe
FROM rust:1.93-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends cmake make g++ perl libclang-dev && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Planner — generate recipe.json
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder — cached dependency build + final build
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin ox-browser

# Stage 4: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ox-browser /usr/local/bin/ox-browser

ENV RUST_LOG=info
EXPOSE 8901

ENTRYPOINT ["ox-browser"]
CMD ["serve", "--port", "8901"]
