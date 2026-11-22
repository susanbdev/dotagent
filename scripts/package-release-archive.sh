#!/usr/bin/env bash
# Compatibility entry point for CI and local release archive packaging.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for arg in "$@"; do
    if [[ "${arg}" == --repo-root ]]; then
        exec cargo run --quiet --locked --release --manifest-path "${repo}/Cargo.toml" \
            -p dotagent-compiler -- package-release-archive "$@"
    fi
done
exec cargo run --quiet --locked --release --manifest-path "${repo}/Cargo.toml" \
    -p dotagent-compiler -- package-release-archive --repo-root "${repo}" "$@"
