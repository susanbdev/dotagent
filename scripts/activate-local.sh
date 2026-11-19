#!/usr/bin/env bash
# Deterministically installs `agent-guard` + `dotagent-compiler`, disables Git hooks
# globally across the board, and deploys canonical zero-trust harness configs.
# Never touches /tmp or cache directories; preserves git user.name and user.email.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOTAGENT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_WORKSPACE="${1:-${HOME}}"
BIN_DIR="${HOME}/.local/bin"

mkdir -p "${BIN_DIR}" "${HOME}/.local/state/agent-guard/sessions"
chmod 700 "${HOME}/.local/state/agent-guard" "${HOME}/.local/state/agent-guard/sessions"

# 0. Pre-build bootstrap audit: reject build-tool RCE traps BEFORE invoking Cargo
audit_prebuild_traps() {
    local scan_dir="${DOTAGENT_ROOT}"
    while true; do
        for cargo_cfg in "${scan_dir}/.cargo/config" "${scan_dir}/.cargo/config.toml"; do
            if [[ -L "${cargo_cfg}" || -L "${scan_dir}/.cargo" ]]; then
                echo "[activate-local] HARD DENY: symlinked .cargo config at ${cargo_cfg}" >&2
                exit 2
            fi
            if [[ -f "${cargo_cfg}" ]] && grep -Eiq '(rustc-wrapper|workspace-wrapper|linker\s*=|runner\s*=|\brustc\s*=)' "${cargo_cfg}"; then
                echo "[activate-local] HARD DENY: dangerous Cargo wrapper/linker/runner in ${cargo_cfg}" >&2
                exit 2
            fi
        done
        if [[ "${scan_dir}" == "/" || "${scan_dir}" == "${HOME}" ]]; then
            break
        fi
        local parent_dir
        parent_dir="$(dirname "${scan_dir}")"
        if [[ "${parent_dir}" == "${scan_dir}" ]]; then
            break
        fi
        scan_dir="${parent_dir}"
    done

    if [[ -L "${DOTAGENT_ROOT}/AGENTS.md" ]]; then
        echo "[activate-local] HARD DENY: root AGENTS.md must not be a symlink" >&2
        exit 2
    fi
    if [[ -L "${DOTAGENT_ROOT}/.gitattributes" ]] || ([[ -f "${DOTAGENT_ROOT}/.gitattributes" ]] && grep -Eiq '(filter\s*=|diff\s*=|merge\s*=|textconv\s*=)' "${DOTAGENT_ROOT}/.gitattributes"); then
        echo "[activate-local] HARD DENY: dangerous .gitattributes driver in ${DOTAGENT_ROOT}/.gitattributes" >&2
        exit 2
    fi
    for yarn_cfg in "${DOTAGENT_ROOT}/.yarnrc" "${DOTAGENT_ROOT}/.yarnrc.yml" "${DOTAGENT_ROOT}/.yarnrc.yaml"; do
        if [[ -L "${yarn_cfg}" ]] || ([[ -f "${yarn_cfg}" ]] && grep -Eiq 'yarnPath' "${yarn_cfg}"); then
            echo "[activate-local] HARD DENY: dangerous yarnPath override in ${yarn_cfg}" >&2
            exit 2
        fi
    done
}

audit_prebuild_traps

# Scrub untrusted compiler/wrapper/linker/dynamic-loader/git env overrides BEFORE invoking Cargo
unset RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTDOC RUSTDOCFLAGS \
    RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL \
    LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
while IFS= read -r env_name; do
    case "${env_name}" in
        CARGO_BUILD_*|CARGO_TARGET_*|CARGO_ALIAS_*|CARGO_REGISTRIES_*|CARGO_SOURCE_*)
            unset "${env_name}"
            ;;
    esac
done < <(compgen -e)

# 1. Build static release binaries and install with read-execute-only VFS mode (0555)
cargo build --release --manifest-path "${DOTAGENT_ROOT}/Cargo.toml" --offline 2>/dev/null \
    || cargo build --release --manifest-path "${DOTAGENT_ROOT}/Cargo.toml"
for bin_name in agent-guard dotagent-compiler swarm-tool; do
    if [[ -e "${BIN_DIR}/${bin_name}" ]]; then
        chmod u+w "${BIN_DIR}/${bin_name}" 2>/dev/null || true
    fi
    install -m 0555 "${DOTAGENT_ROOT}/target/release/${bin_name}" "${BIN_DIR}/${bin_name}"
done

# Install unified `dotagent` CLI (falling back to `agent-guard` multicall binary under minimal test shims)
if [[ -e "${BIN_DIR}/dotagent" ]]; then
    chmod u+w "${BIN_DIR}/dotagent" 2>/dev/null || true
fi
if [[ -f "${DOTAGENT_ROOT}/target/release/dotagent" ]]; then
    install -m 0555 "${DOTAGENT_ROOT}/target/release/dotagent" "${BIN_DIR}/dotagent"
else
    install -m 0555 "${DOTAGENT_ROOT}/target/release/agent-guard" "${BIN_DIR}/dotagent"
fi

if [[ -f "${DOTAGENT_ROOT}/target/release/dotagent-harness" ]]; then
    if [[ -e "${BIN_DIR}/dotagent-harness" ]]; then
        chmod u+w "${BIN_DIR}/dotagent-harness" 2>/dev/null || true
    fi
    install -m 0555 "${DOTAGENT_ROOT}/target/release/dotagent-harness" "${BIN_DIR}/dotagent-harness"
fi

# 2. Verify compiled bundles match golden SHA-256 manifest
"${BIN_DIR}/dotagent-compiler" verify "${DOTAGENT_ROOT}"

# 3. Delegate non-destructive deployment (.dotagent.bak backups, JSON preference merging,
#    zsh/bash PATH setup, 19-key Git lockdown, pinned GUI hooks, 0444 plane, & live audit-repo)
"${BIN_DIR}/agent-guard" activate \
    --dotagent-root "${DOTAGENT_ROOT}" \
    --workspace "${TARGET_WORKSPACE}" \
    --bin-dir "${BIN_DIR}"

