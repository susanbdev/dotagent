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

# 1. Build static release binaries and install with read-execute-only VFS mode (0555)
cargo build --release --manifest-path "${DOTAGENT_ROOT}/Cargo.toml"
for bin_name in agent-guard dotagent-compiler; do
    if [[ -e "${BIN_DIR}/${bin_name}" ]]; then
        chmod u+w "${BIN_DIR}/${bin_name}" 2>/dev/null || true
    fi
    install -m 0555 "${DOTAGENT_ROOT}/target/release/${bin_name}" "${BIN_DIR}/${bin_name}"
done

# Ensure ~/.local/bin is on PATH for non-login shells if not already configured
if [[ -f "${HOME}/.bashrc" ]] && ! grep -q '\.local/bin' "${HOME}/.bashrc"; then
    printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "${HOME}/.bashrc"
fi

# 2. Verify compiled bundles match golden SHA-256 manifest
"${BIN_DIR}/dotagent-compiler" verify "${DOTAGENT_ROOT}"

# 3. Apply and verify ALL 19 global Git hardening keys (preserving user.name / user.email and credential helpers)
REQUIRED_GIT_SETTINGS=(
    "core.hooksPath:/dev/null"
    "core.attributesFile:/dev/null"
    "core.fsmonitor:false"
    "core.pager:cat"
    "core.symlinks:false"
    "core.autocrlf:input"
    "core.protectHFS:true"
    "core.protectNTFS:true"
    "gc.auto:0"
    "protocol.allow:never"
    "protocol.https.allow:always"
    "protocol.file.allow:never"
    "protocol.ext.allow:never"
    "protocol.git.allow:never"
    "submodule.recurse:false"
    "submodule.fetchJobs:0"
    "transfer.fsckObjects:true"
    "fetch.fsckObjects:true"
    "receive.fsckObjects:true"
)

for entry in "${REQUIRED_GIT_SETTINGS[@]}"; do
    key="${entry%%:*}"
    expected="${entry#*:}"
    current="$(git config --global --get "${key}" 2>/dev/null || true)"
    if [[ "${current}" != "${expected}" ]]; then
        git config --global "${key}" "${expected}"
    fi
    verified="$(git config --global --get "${key}" 2>/dev/null || true)"
    if [[ "${verified}" != "${expected}" ]]; then
        echo "[activate-local] HARD DENY: failed to enforce git config --global ${key}=${expected} (got '${verified}')" >&2
        exit 2
    fi
done

# 4. Install Gemini / Antigravity global constitution & hook wiring
# Use `cp -f` so FUSE/virtiofs persistent ~/.gemini mounts that disallow chmod succeed cleanly.
mkdir -p "${HOME}/.gemini"
cp -f "${DOTAGENT_ROOT}/dist/gemini/GEMINI.md" "${HOME}/.gemini/GEMINI.md"
cp -f "${DOTAGENT_ROOT}/dist/gemini/settings.json" "${HOME}/.gemini/settings.json"

# 5. Deploy root AGENTS.md + harness hooks + research-airlock subagent
#    Source repo keeps 0644 for git workflows; deployed runtime workspace gets VFS read-only 0444!
deploy_harness_bundle() {
    local root="$1"
    local mode="$2"
    mkdir -p "${root}/.claude/agents" "${root}/.cursor" "${root}/.codex"
    local targets=(
        "${root}/AGENTS.md"
        "${root}/.ignore"
        "${root}/.cursorignore"
        "${root}/.claude/settings.json"
        "${root}/.claude/agents/research-airlock.md"
        "${root}/.cursor/hooks.json"
        "${root}/.codex/config.toml"
    )
    for t in "${targets[@]}"; do
        if [[ -e "${t}" ]]; then
            chmod u+w "${t}" 2>/dev/null || true
        fi
    done
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/AGENTS.md" "${root}/AGENTS.md"
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/.ignore" "${root}/.ignore"
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/cursor/.cursorignore" "${root}/.cursorignore"
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/claude/settings.json" "${root}/.claude/settings.json"
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/claude/agents/research-airlock.md" "${root}/.claude/agents/research-airlock.md"
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/cursor/hooks.json" "${root}/.cursor/hooks.json"
    install -m "${mode}" "${DOTAGENT_ROOT}/dist/codex/config.toml" "${root}/.codex/config.toml"
}

deploy_harness_bundle "${DOTAGENT_ROOT}" "0644"
if [[ "${TARGET_WORKSPACE}" != "${DOTAGENT_ROOT}" ]]; then
    deploy_harness_bundle "${TARGET_WORKSPACE}" "0444"
fi

# 6. Run live self-audit
"${BIN_DIR}/agent-guard" audit-repo "${DOTAGENT_ROOT}"
echo "[activate-local] Zero-trust guards (0555), read-only control plane (0444), pre-buffer ASCII sanitizer, tiny step compaction, and global git lockdown active."
