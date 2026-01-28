#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOCKFILE="${ROOT_DIR}/Cargo.lock"
DOCKERFILE="${ROOT_DIR}/tsp_sdk/benches/guardrail/Dockerfile"
IMAGE="tsp-sdk-guardrail-bench:local"

if [[ ! -f "${LOCKFILE}" ]]; then
  echo "missing Cargo.lock at ${LOCKFILE}" >&2
  exit 1
fi

IAI_CALLGRIND_VERSION="$(
  awk '
    $0=="[[package]]"{inpkg=1; name=""; ver=""; next}
    inpkg && $1=="name" && $3=="\"iai-callgrind\""{name="iai-callgrind"; next}
    inpkg && name=="iai-callgrind" && $1=="version"{gsub(/"/,"",$3); print $3; exit}
  ' "${LOCKFILE}"
)"

if [[ -z "${IAI_CALLGRIND_VERSION}" ]]; then
  echo "failed to detect iai-callgrind version from Cargo.lock" >&2
  exit 1
fi

docker build \
  -f "${DOCKERFILE}" \
  --build-arg "IAI_CALLGRIND_RUNNER_VERSION=${IAI_CALLGRIND_VERSION}" \
  -t "${IMAGE}" \
  "${ROOT_DIR}"

docker run --rm \
  --security-opt seccomp=unconfined \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/tmp/cargo \
  -e RUSTUP_HOME=/usr/local/rustup \
  -v "${ROOT_DIR}:/work" \
  -w /work \
  "${IMAGE}"
