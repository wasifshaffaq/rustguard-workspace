# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:slim AS builder

# Install build deps
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies first (layer caching trick)
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN cargo build --release 2>/dev/null; rm -rf src/

# Now copy real source
COPY src ./src
COPY static ./static

# Force rebuild of our code (not deps)
RUN touch src/main.rs
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# If you want cargo check to work in the web UI, add the Rust toolchain:
# RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
# ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY --from=builder /app/target/release/cpp2rust-debugger .
COPY --from=builder /app/static ./static

EXPOSE 8080

ENV PORT=8080

CMD ["./cpp2rust-debugger"]
