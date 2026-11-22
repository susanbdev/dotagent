#!/usr/bin/env bash
# Deterministically installs `agent-guard` + `dotagent-compiler`, disables Git hooks
# globally across the board, and deploys canonical zero-trust harness configs.
# Never touches /tmp or cache directories; preserves git user.name and user.email.

set -euo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOTAGENT_ROOT="$(cd -P -- "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
TARGET_WORKSPACE=""
PREBUILT_DIR=""
PREBUILT_SUMS=""

# Usage: activate-local.sh [workspace] [--from-prebuilt <dir> --prebuilt-sums <file>]
#   --from-prebuilt <dir>   skip `cargo build` and install release binaries found in <dir>/bin
#                           (for example an extracted release archive).
#   --prebuilt-sums <file>  REQUIRED with --from-prebuilt: sha256sum-format lines
#                           "<hex>  bin/<name>" (paths relative to <dir>). Every binary is hashed
#                           and compared before anything is installed. The caller is responsible
#                           for obtaining this file from a source it verified (for example a
#                           signed SHA256SUMS or an attested release archive).
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-prebuilt)
            if [[ $# -lt 2 ]]; then
                echo "[activate-local] usage: --from-prebuilt <dir>" >&2
                exit 2
            fi
            if [[ -L "$2" || ! -d "$2" ]]; then
                echo "[activate-local] HARD DENY: --from-prebuilt '$2' must be a regular directory" >&2
                exit 2
            fi
            PREBUILT_DIR="$(cd -P -- "$2" && pwd)"
            shift 2
            ;;
        --prebuilt-sums)
            if [[ $# -lt 2 ]]; then
                echo "[activate-local] usage: --prebuilt-sums <file>" >&2
                exit 2
            fi
            PREBUILT_SUMS="$2"
            shift 2
            ;;
        -*)
            echo "[activate-local] unrecognized option '$1'" >&2
            exit 2
            ;;
        *)
            if [[ -n "${TARGET_WORKSPACE}" ]]; then
                echo "[activate-local] only one workspace argument is allowed" >&2
                exit 2
            fi
            TARGET_WORKSPACE="$1"
            shift
            ;;
    esac
done
TARGET_WORKSPACE="${TARGET_WORKSPACE:-${HOME}}"
if [[ -n "${PREBUILT_DIR}" && -z "${PREBUILT_SUMS}" ]]; then
    echo "[activate-local] HARD DENY: --from-prebuilt requires --prebuilt-sums <file>" >&2
    exit 2
fi
if [[ -z "${PREBUILT_DIR}" && -n "${PREBUILT_SUMS}" ]]; then
    echo "[activate-local] --prebuilt-sums is only valid with --from-prebuilt" >&2
    exit 2
fi

check_nonsymlink_dir_chain() {
    local target="$1" rest cur="" seg
    case "${target}" in
        /*) ;;
        *)
            echo "[activate-local] HARD DENY: '${target}' must be an absolute path" >&2
            exit 2
            ;;
    esac
    rest="${target#/}"
    while [[ -n "${rest}" ]]; do
        if [[ "${rest}" == *"/"* ]]; then
            seg="${rest%%/*}"
            rest="${rest#*/}"
        else
            seg="${rest}"
            rest=""
        fi
        [[ -z "${seg}" ]] && continue
        if [[ "${seg}" == "." || "${seg}" == ".." ]]; then
            echo "[activate-local] HARD DENY: '${target}' must not contain '.' or '..' segments" >&2
            exit 2
        fi
        cur="${cur}/${seg}"
        if [[ -L "${cur}" ]] || [[ -e "${cur}" && ! -d "${cur}" ]]; then
            echo "[activate-local] HARD DENY: '${cur}' must not be a symlink or non-directory" >&2
            exit 2
        fi
    done
}

for dir_chk in "${BIN_DIR}" "${HOME}/.local/state/agent-guard/sessions"; do
    check_nonsymlink_dir_chain "${dir_chk}"
done
mkdir -p "${BIN_DIR}" "${HOME}/.local/state/agent-guard/sessions"
for dir_chk in "${BIN_DIR}" "${HOME}/.local/state/agent-guard/sessions"; do
    check_nonsymlink_dir_chain "${dir_chk}"
done
chmod 700 "${HOME}/.local/state/agent-guard" "${HOME}/.local/state/agent-guard/sessions"

# 0. Pre-build bootstrap audit: reject build-tool RCE traps BEFORE invoking Cargo
audit_cargo_config() {
    local config_path="$1" directives="$2" grep_status=0
    if [[ -L "${config_path}" ]]; then
        echo "[activate-local] HARD DENY: symlinked Cargo config at ${config_path}" >&2
        exit 2
    fi
    if [[ -f "${config_path}" ]]; then
        grep -Eiq -- "${directives}" "${config_path}" || grep_status=$?
        case "${grep_status}" in
            0)
                echo "[activate-local] HARD DENY: dangerous Cargo directive in ${config_path}" >&2
                exit 2
                ;;
            1) ;;
            *)
                echo "[activate-local] HARD DENY: failed to inspect Cargo config at ${config_path}" >&2
                exit 2
                ;;
        esac
    fi
}

audit_prebuild_traps() {
    local scan_dir="${DOTAGENT_ROOT}" cargo_cfg tc_cfg
    local directives='rustc-wrapper|workspace-wrapper|linker[[:space:]]*=|runner[[:space:]]*=|(^|[^[:alnum:]_-])rustc[[:space:]]*='
    if [[ -z "${PREBUILT_DIR}" ]]; then
        directives="${directives}|rustc_wrapper|rustflags|rustdocflags|credential-provider"
        directives="${directives}|^[[:space:]]*\[+[[:space:]]*[\"']?(alias|env|target)[\"']?[[:space:]]*(\.|\])"
        directives="${directives}|^[[:space:]]*[\"']?(alias|env|target)[\"']?[[:space:]]*\."
    fi
    while true; do
        if [[ -L "${scan_dir}/.cargo" ]]; then
            echo "[activate-local] HARD DENY: symlinked Cargo configuration directory at ${scan_dir}/.cargo" >&2
            exit 2
        fi
        for cargo_cfg in "${scan_dir}/.cargo/config" "${scan_dir}/.cargo/config.toml"; do
            audit_cargo_config "${cargo_cfg}" "${directives}"
        done
        if [[ -z "${PREBUILT_DIR}" ]]; then
            for tc_cfg in "${scan_dir}/rust-toolchain" "${scan_dir}/rust-toolchain.toml"; do
                if [[ -L "${tc_cfg}" ]]; then
                    echo "[activate-local] HARD DENY: symlinked rust-toolchain at ${tc_cfg}" >&2
                    exit 2
                fi
                if [[ "${scan_dir}" == "${DOTAGENT_ROOT}" && -f "${tc_cfg}" ]]; then
                    echo "[activate-local] HARD DENY: repo rust-toolchain override at ${tc_cfg}" >&2
                    exit 2
                fi
            done
        fi
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

    if [[ -z "${PREBUILT_DIR}" ]]; then
        local cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
        if [[ "${cargo_home}" != /* ]]; then
            cargo_home="${DOTAGENT_ROOT}/${cargo_home}"
        fi
        if [[ -L "${cargo_home}" ]]; then
            echo "[activate-local] HARD DENY: symlinked CARGO_HOME at ${cargo_home}" >&2
            exit 2
        fi
        for cargo_cfg in "${cargo_home}/config" "${cargo_home}/config.toml"; do
            audit_cargo_config "${cargo_cfg}" "${directives}"
        done
    fi

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

install_sealed_bin() {
    local src="$1" dst="$2" tmp
    if [[ -L "${dst}" ]] || [[ -e "${dst}" && ! -f "${dst}" ]]; then
        echo "[activate-local] HARD DENY: refusing symlink or non-regular target at ${dst}" >&2
        exit 2
    fi
    tmp="${dst%/*}/.${dst##*/}.tmp.$$"
    rm -f "${tmp}"
    install -m 0555 "${src}" "${tmp}"
    mv -f "${tmp}" "${dst}"
}

# 1. Build static release binaries and install with read-execute-only VFS mode (0555)
if [[ -n "${PREBUILT_DIR}" ]]; then
    BIN_SRC="${PREBUILT_DIR}/bin"
    if [[ -L "${BIN_SRC}" || ! -d "${BIN_SRC}" ]]; then
        echo "[activate-local] HARD DENY: '${BIN_SRC}' must be a regular directory" >&2
        exit 2
    fi
    for bin_name in agent-guard agent-guard-sh dotagent-compiler swarm-tool dotagent dotagent-harness; do
        if [[ -L "${BIN_SRC}/${bin_name}" ]]; then
            echo "[activate-local] HARD DENY: prebuilt binary '${bin_name}' is a symlink in ${BIN_SRC}" >&2
            exit 2
        fi
    done
    for bin_name in agent-guard agent-guard-sh dotagent-compiler swarm-tool dotagent; do
        if [[ ! -f "${BIN_SRC}/${bin_name}" ]]; then
            echo "[activate-local] HARD DENY: prebuilt binary '${bin_name}' missing in ${BIN_SRC}" >&2
            exit 2
        fi
    done
    if [[ -L "${PREBUILT_SUMS}" || ! -f "${PREBUILT_SUMS}" ]]; then
        echo "[activate-local] HARD DENY: --prebuilt-sums must be a regular file" >&2
        exit 2
    fi
    verified_count=0
    for bin_name in agent-guard agent-guard-sh dotagent-compiler swarm-tool dotagent dotagent-harness; do
        [[ -f "${BIN_SRC}/${bin_name}" ]] || continue
        if command -v sha256sum >/dev/null 2>&1; then
            actual_sha="$(sha256sum -- "${BIN_SRC}/${bin_name}")"
        else
            actual_sha="$(shasum -a 256 -- "${BIN_SRC}/${bin_name}")"
        fi
        actual_sha="${actual_sha%% *}"
        actual_sha="${actual_sha#\\}"
        if ! grep -Fxq "${actual_sha}  bin/${bin_name}" "${PREBUILT_SUMS}"; then
            echo "[activate-local] HARD DENY: SHA-256 of prebuilt '${bin_name}' is not listed in ${PREBUILT_SUMS}" >&2
            exit 2
        fi
        verified_count=$((verified_count + 1))
    done
    echo "[activate-local] verified ${verified_count} prebuilt binaries against ${PREBUILT_SUMS}" >&2
else
    BIN_SRC="${DOTAGENT_ROOT}/target/release"
    (
        cd -P -- "${DOTAGENT_ROOT}"
        cargo build --release --manifest-path "${DOTAGENT_ROOT}/Cargo.toml" --offline 2>/dev/null \
            || cargo build --release --manifest-path "${DOTAGENT_ROOT}/Cargo.toml"
    )
fi
for bin_name in agent-guard dotagent-compiler swarm-tool; do
    install_sealed_bin "${BIN_SRC}/${bin_name}" "${BIN_DIR}/${bin_name}"
done
if [[ -f "${BIN_SRC}/agent-guard-sh" ]]; then
    install_sealed_bin "${BIN_SRC}/agent-guard-sh" "${BIN_DIR}/agent-guard-sh"
else
    install_sealed_bin "${BIN_SRC}/agent-guard" "${BIN_DIR}/agent-guard-sh"
fi

# Install unified `dotagent` CLI (falling back to `agent-guard` multicall binary under minimal test shims)
if [[ -f "${BIN_SRC}/dotagent" ]]; then
    install_sealed_bin "${BIN_SRC}/dotagent" "${BIN_DIR}/dotagent"
else
    install_sealed_bin "${BIN_SRC}/agent-guard" "${BIN_DIR}/dotagent"
fi

if [[ -f "${BIN_SRC}/dotagent-harness" ]]; then
    install_sealed_bin "${BIN_SRC}/dotagent-harness" "${BIN_DIR}/dotagent-harness"
fi

# 2. Verify compiled bundles match golden SHA-256 manifest
"${BIN_DIR}/dotagent-compiler" verify "${DOTAGENT_ROOT}"

# 3. Delegate non-destructive deployment (.dotagent.bak backups, JSON preference merging,
#    zsh/bash PATH setup, 19-key Git lockdown, pinned GUI hooks, 0444 plane, & live audit-repo)
"${BIN_DIR}/agent-guard" activate \
    --dotagent-root "${DOTAGENT_ROOT}" \
    --workspace "${TARGET_WORKSPACE}" \
    --bin-dir "${BIN_DIR}"

