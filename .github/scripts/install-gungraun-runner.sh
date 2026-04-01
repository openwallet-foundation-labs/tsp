#!/usr/bin/env bash
set -euo pipefail

manifest_path="${1:-tsp_sdk/Cargo.toml}"

version="$(
  sed -nE 's/^[[:space:]]*gungraun[[:space:]]*=[[:space:]]*\{[[:space:]]*version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${manifest_path}" | head -n1
)"

if [[ -z "${version}" ]]; then
  echo "failed to detect gungraun version from ${manifest_path}" >&2
  exit 1
fi

install_requirement="${version}"
if [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.].*)?$ ]]; then
  install_requirement="^${version}"
fi

cargo install gungraun-runner --force --version "${install_requirement}"
