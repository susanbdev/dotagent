#!/usr/bin/env bash
# Zero-Trust GitHub Organization & User Governance Provisioner (`susanbdev/dotagent`)
#
# Idempotently configures GitHub Organizations (e.g. `susanbdev`) and User accounts
# (e.g. `susanbeasles`) with:
#   1. SHA-pinned GitHub-owned Actions + read-only default workflow permissions
#   2. Linear squash-only PR merges + automatic head-branch cleanup
#   3. Active `dotagent-zero-trust-main` branch rulesets (`bypass_actors: []`, block
#      force-push/delete, require review-thread resolution, Copilot review on push, and
#      all 9 required status checks including `Ring-0 & Copilot Gate`)
#   4. Standardized `dotagent-friction` & AgentPI risk-telemetry labels
#
# Usage:
#   ./scripts/setup-github-org-governance.sh --owner susanbdev --dry-run
#   ./scripts/setup-github-org-governance.sh --owner susanbdev --verify
#   ./scripts/setup-github-org-governance.sh --owner susanbdev --all-fleet --apply
#   ./scripts/setup-github-org-governance.sh --owner susanbdev --owner susanbeasles --apply

set -euo pipefail

# Operator-only: refuse to run (and never compile anything) inside AI agent harnesses or
# sandboxed guard workers. This mirrors `verify_feedback_operator_or_ci_loop` in the binary.
for marker in AGENT_GUARD_IN_SANDBOX AGENT_GUARD_WORKER_LOCK AGENT_GUARD_ROLE CLAUDECODE \
    CLAUDE_CODE_ENTRYPOINT CURSOR_TRACE_ID CURSOR_AGENT CODEX_SANDBOX CODEX_ENV_SANDBOX \
    GEMINI_CLI ANTIGRAVITY_AGENT; do
    marker_val="${!marker:-}"
    marker_lc="$(printf '%s' "${marker_val}" | tr '[:upper:]' '[:lower:]')"
    if [[ -n "${marker_val}" && "${marker_val}" != "0" && "${marker_lc}" != "false" ]]; then
        echo "[setup-github-org-governance] HARD DENY: operator-only script; '${marker}' is set (AI agent harness detected)" >&2
        exit 2
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOTAGENT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

check_cargo_cfg_file() {
    local cargo_cfg="$1"
    local cargo_dir
    cargo_dir="$(dirname "${cargo_cfg}")"
    if [[ -L "${cargo_cfg}" || -L "${cargo_dir}" ]]; then
        echo "[setup-github-org-governance] HARD DENY: symlinked .cargo config at ${cargo_cfg}" >&2
        exit 2
    fi
    # POSIX ERE only (portable to BSD grep): matches bare, quoted, dotted (`build.rustc-wrapper`,
    # `env.FOO`) and table (`[env]`, `[target.x]`) forms plus escaped-unicode obfuscation.
    if [[ -f "${cargo_cfg}" ]] && grep -Eiq \
        -e '(^|[^a-z0-9_-])"?(rustc[-_]wrapper|rustc[-_]workspace[-_]wrapper|rustc|rustdoc|linker|runner|rustflags|rustdocflags|credential-provider|ld_preload)"?[[:space:]]*=' \
        -e '^[[:space:]]*\[[[:space:]]*"?(env|alias|target|host)"?[[:space:]]*([].]|$)' \
        -e '(^|[^a-z0-9_-])"?env"?[[:space:]]*\.' \
        -e '\\[uU][0-9a-fA-F]{4,8}' \
        "${cargo_cfg}"; then
        echo "[setup-github-org-governance] HARD DENY: dangerous Cargo wrapper/linker/runner/env trap in ${cargo_cfg}" >&2
        exit 2
    fi
}

audit_prebuild_traps() {
    local scan_dir="${DOTAGENT_ROOT}"
    while true; do
        check_cargo_cfg_file "${scan_dir}/.cargo/config"
        check_cargo_cfg_file "${scan_dir}/.cargo/config.toml"
        if [[ "${scan_dir}" == "/" ]]; then
            break
        fi
        local parent_dir
        parent_dir="$(dirname "${scan_dir}")"
        if [[ "${parent_dir}" == "${scan_dir}" ]]; then
            break
        fi
        scan_dir="${parent_dir}"
    done

    local cargo_home_dir="${CARGO_HOME:-${HOME}/.cargo}"
    check_cargo_cfg_file "${cargo_home_dir}/config"
    check_cargo_cfg_file "${cargo_home_dir}/config.toml"

    if [[ -L "${DOTAGENT_ROOT}/AGENTS.md" ]]; then
        echo "[setup-github-org-governance] HARD DENY: root AGENTS.md must not be a symlink" >&2
        exit 2
    fi
    if [[ -L "${DOTAGENT_ROOT}/.gitattributes" ]] || ([[ -f "${DOTAGENT_ROOT}/.gitattributes" ]] && grep -Eiq '(filter|diff|merge|textconv)[[:space:]]*=' "${DOTAGENT_ROOT}/.gitattributes"); then
        echo "[setup-github-org-governance] HARD DENY: dangerous .gitattributes driver in ${DOTAGENT_ROOT}/.gitattributes" >&2
        exit 2
    fi
    for rt_cfg in "${DOTAGENT_ROOT}/rust-toolchain" "${DOTAGENT_ROOT}/rust-toolchain.toml"; do
        if [[ -L "${rt_cfg}" ]] || ([[ -f "${rt_cfg}" ]] && grep -Eiq 'path[[:space:]]*=' "${rt_cfg}"); then
            echo "[setup-github-org-governance] HARD DENY: dangerous rust-toolchain path override in ${rt_cfg}" >&2
            exit 2
        fi
    done
}

audit_prebuild_traps

unset RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTDOC RUSTDOCFLAGS \
    RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL \
    LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
while IFS= read -r env_name; do
    case "${env_name}" in
        CARGO_BUILD_*|CARGO_TARGET_*|CARGO_ALIAS_*|CARGO_REGISTRIES_*|CARGO_SOURCE_*|CARGO_ENV_*)
            unset "${env_name}"
            ;;
    esac
done < <(compgen -e)

OWNERS=()
EXTRA_ARGS=()
MODE_FLAG="--dry-run"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --owner|--org)
            if [[ $# -lt 2 ]]; then
                echo "[setup-github-org-governance] missing value for $1" >&2
                exit 2
            fi
            OWNERS+=("$2")
            shift 2
            ;;
        --dry-run|--verify|--apply)
            MODE_FLAG="$1"
            shift
            ;;
        --repo|--repos)
            if [[ $# -lt 2 ]]; then
                echo "[setup-github-org-governance] missing value for $1" >&2
                exit 2
            fi
            EXTRA_ARGS+=("$1" "$2")
            shift 2
            ;;
        --all-fleet|--all|--json)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--owner <org_or_user>]... [--repo <name> | --repos <csv> | --all-fleet] [--dry-run | --verify | --apply] [--json]"
            exit 0
            ;;
        *)
            echo "[setup-github-org-governance] unrecognized flag '$1'" >&2
            exit 2
            ;;
    esac
done

if [[ ${#OWNERS[@]} -eq 0 ]]; then
    OWNERS=("susanbdev")
fi

trusted_install() {
    local path="$1" parent mode resolved
    [[ -f "${path}" && -x "${path}" && ! -L "${path}" ]] || return 1
    parent="$(cd -P -- "$(dirname -- "${path}")" && pwd)" || return 1
    case "${parent}/" in
        "${DOTAGENT_ROOT}/"*) return 1 ;;
    esac
    resolved="${parent}/${path##*/}"
    path="${resolved}"
    while :; do
        mode="$(stat -L -c '%a' "${path}" 2>/dev/null || stat -L -f '%Lp' "${path}")" || return 1
        [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#${mode} & 8#022) == 0 )) || return 1
        [[ "${path}" == / ]] && break
        path="$(dirname -- "${path}")"
    done
    printf '%s\n' "${resolved}"
}

DOTAGENT_BIN=""
for candidate in /usr/local/bin/dotagent /usr/bin/dotagent; do
    if DOTAGENT_BIN="$(trusted_install "${candidate}")"; then
        break
    fi
done
if [[ -z "${DOTAGENT_BIN}" && -n "${HOME:-}" ]]; then
    DOTAGENT_BIN="$(trusted_install "${HOME}/.local/bin/dotagent")" || DOTAGENT_BIN=""
fi
if [[ -z "${DOTAGENT_BIN}" ]]; then
    echo "[setup-github-org-governance] HARD DENY: install a trusted dotagent release before configuring GitHub" >&2
    exit 2
fi

OVERALL_RC=0
for owner in "${OWNERS[@]}"; do
    if ! "${DOTAGENT_BIN}" fleet configure-github --owner "${owner}" "${MODE_FLAG}" "${EXTRA_ARGS[@]}"; then
        OVERALL_RC=2
    fi
done

exit "${OVERALL_RC}"
