FROM rust AS builder
WORKDIR /app
COPY ./ ./
RUN cargo build --release --bin demo-intermediary

FROM debian AS runner
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/demo-intermediary ./
EXPOSE 3001
ENTRYPOINT [ "./demo-intermediary", "p.teaspoon.world" ]
