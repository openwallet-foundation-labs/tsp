FROM rust:1.85 AS builder
WORKDIR /app
COPY ./ ./
RUN cargo build --release --bin demo-intermediary --bin demo-server

FROM debian AS intermediary
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/demo-intermediary ./
EXPOSE 3001
ENTRYPOINT [ "./demo-intermediary" ]

FROM debian AS server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/demo-server ./
EXPOSE 3000
ENTRYPOINT [ "./demo-server" ]