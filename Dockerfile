# ---------- BUILD STAGE ----------
FROM rust:1.75 as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml .
COPY Cargo.lock . 2>/dev/null || true

# Create dummy src to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release
RUN rm -rf src

# Copy actual source
COPY src ./src
COPY Templates ./Templates
COPY Rocket.toml .

RUN cargo build --release

# ---------- RUNTIME STAGE ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/auto-protokoll /app/auto-protokoll
COPY Templates ./Templates
COPY Rocket.toml .

ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8000

EXPOSE 8000

CMD ["./auto-protokoll"]
