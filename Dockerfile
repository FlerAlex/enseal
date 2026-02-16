FROM rust:1-slim AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --no-default-features --features server

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/enseal /usr/local/bin/enseal

EXPOSE 4443

ENTRYPOINT ["enseal", "serve"]
CMD ["--port", "4443"]
