FROM rust:1.83-slim-bookworm as builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y build-essential pkg-config libssl-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install diesel_cli --version 2.2.12 --no-default-features --features postgres

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 libpq5 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel
COPY --from=builder /app/target/release/mci .

COPY migrations ./migrations
COPY diesel.toml ./diesel.toml

RUN chmod +x scripts/generate_certs.sh && ./scripts/generate_certs.sh
COPY certs ./certs

EXPOSE 7687

CMD ["./mci"]
