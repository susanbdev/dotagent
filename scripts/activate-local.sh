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

# 1. Build static release binaries if not already up-to-date
cargo build --release --manifest-path "${DOTAGENT_ROOT}/Cargo.toml"
install -m 0755 "${DOTAGENT_ROOT}/target/release/agent-guard" "${BIN_DIR}/agent-guard"
install -m 0755 "${DOTAGENT_ROOT}/target/release/dotagent-compiler" "${BIN_DIR}/dotagent-compiler"

# Ensure ~/.local/bin is on PATH for non-login shells if not already configured
if [[ -f "${HOME}/.bashrc" ]] && ! grep -q '\.local/bin' "${HOME}/.bashrc"; then
    printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "${HOME}/.bashrc"
fi

# 2. Verify compiled bundles match golden SHA-256 manifest
"${BIN_DIR}/dotagent-compiler" verify "${DOTAGENT_ROOT}"

# 3. Apply global Git hardening (preserving user.name / user.email)
git config --global core.hooksPath /dev/null
git config --global core.fsmonitor false
git config --global core.pager cat
git config --global core.symlinks false
git config --global core.autocrlf input
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

# 4. Install Gemini / Antigravity global constitution & hook wiring
# Use `cp -f` so FUSE/virtiofs persistent ~/.gemini mounts that disallow chmod succeed cleanly.
mkdir -p "${HOME}/.gemini"
cp -f "${DOTAGENT_ROOT}/dist/gemini/GEMINI.md" "${HOME}/.gemini/GEMINI.md"
cp -f "${DOTAGENT_ROOT}/dist/gemini/settings.json" "${HOME}/.gemini/settings.json"

# 5. Deploy root AGENTS.md + harness hooks into dotagent itself and TARGET_WORKSPACE
deploy_harness_bundle() {
    local root="$1"
    mkdir -p "${root}/.claude" "${root}/.cursor" "${root}/.codex"
    install -m 0644 "${DOTAGENT_ROOT}/dist/AGENTS.md" "${root}/AGENTS.md"
    install -m 0644 "${DOTAGENT_ROOT}/dist/.ignore" "${root}/.ignore"
    install -m 0644 "${DOTAGENT_ROOT}/dist/cursor/.cursorignore" "${root}/.cursorignore"
    install -m 0644 "${DOTAGENT_ROOT}/dist/claude/settings.json" "${root}/.claude/settings.json"
    install -m 0644 "${DOTAGENT_ROOT}/dist/cursor/hooks.json" "${root}/.cursor/hooks.json"
    install -m 0644 "${DOTAGENT_ROOT}/dist/codex/config.toml" "${root}/.codex/config.toml"
}

deploy_harness_bundle "${DOTAGENT_ROOT}"
if [[ "${TARGET_WORKSPACE}" != "${DOTAGENT_ROOT}" ]]; then
    deploy_harness_bundle "${TARGET_WORKSPACE}"
fi

# 6. Run live self-audit
"${BIN_DIR}/agent-guard" audit-repo "${DOTAGENT_ROOT}"
echo "[activate-local] Zero-trust guards, global git lockdown (core.hooksPath=/dev/null), and harness configs active."
