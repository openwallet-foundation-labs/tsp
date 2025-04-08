FROM rust:1.85 AS builder
WORKDIR /app
COPY ./ ./
ARG FEATURE_FLAGS=""
RUN cargo build --release --bin demo-intermediary --bin demo-server --bin did-web --features=$FEATURE_FLAGS

FROM debian AS intermediary
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/demo-intermediary ./
EXPOSE 3001
ENTRYPOINT [ "./demo-intermediary" ]

FROM debian AS server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
RUN mkdir "data"
COPY --from=builder /app/target/release/demo-server ./
EXPOSE 3000
ENTRYPOINT [ "./demo-server" ]

FROM debian AS did-web
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
RUN mkdir "data"
COPY --from=builder /app/target/release/did-web ./
EXPOSE 3000
ENTRYPOINT [ "./did-web" ]