FROM rust:1.83-slim-bookworm as builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install diesel_cli --no-default-features --features postgres

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 libpq5 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel
COPY --from=builder /app/target/release/mci .
COPY migrations ./migrations
COPY diesel.toml ./diesel.toml
COPY certs certs

EXPOSE 8080

CMD ["./mci"]
