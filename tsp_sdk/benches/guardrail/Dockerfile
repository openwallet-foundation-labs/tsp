FROM rust:1.88-bookworm

ARG IAI_CALLGRIND_RUNNER_VERSION=0.16.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install --locked iai-callgrind-runner --version ${IAI_CALLGRIND_RUNNER_VERSION}

WORKDIR /work

# `bash -l` may reset PATH via `/etc/profile` and hide cargo. Keep it simple and rely on the base
# image PATH (includes `/usr/local/cargo/bin`).
CMD ["bash", "-c", "cargo bench -p tsp_sdk --bench guardrail_report"]
