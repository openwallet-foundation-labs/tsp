FROM rust:1.88-bookworm

ARG GUNGRAUN_RUNNER_VERSION=0.17.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install --locked gungraun-runner --version ${GUNGRAUN_RUNNER_VERSION}

WORKDIR /work

# `bash -l` may reset PATH via `/etc/profile` and hide cargo. Keep it simple and rely on the base
# image PATH (includes `/usr/local/cargo/bin`).
CMD ["bash", "-c", "cargo bench -p tsp_sdk --bench guardrail --features \"resolve,bench-callgrind\" && cargo bench -p tsp_sdk --bench guardrail_hpke --no-default-features --features \"resolve,bench-callgrind\" && cargo bench -p tsp_sdk --bench guardrail_pq --no-default-features --features \"pq,resolve,bench-callgrind\""]
