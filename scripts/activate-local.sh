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

# 3. Apply global Git hardening (preserving user.name / user.email and credential helpers)
if ! grep -q 'attributesFile = /dev/null' "${HOME}/.gitconfig" 2>/dev/null; then
    git config --global core.hooksPath /dev/null
    git config --global core.attributesFile /dev/null
    git config --global core.fsmonitor false
    git config --global core.pager cat
    git config --global core.symlinks false
    git config --global core.autocrlf input
    git config --global core.protectHFS true
    git config --global core.protectNTFS true
    git config --global gc.auto 0
    git config --global protocol.allow never
    git config --global protocol.https.allow always
    git config --global protocol.file.allow never
    git config --global protocol.ext.allow never
    git config --global protocol.git.allow never
    git config --global submodule.recurse false
    git config --global submodule.fetchJobs 0
    git config --global transfer.fsckObjects true
    git config --global fetch.fsckObjects true
    git config --global receive.fsckObjects true
fi

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
