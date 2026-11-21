#!/usr/bin/env bash
# Self-test suite for `susanbdev/dotagent` automated CI & delivery scripts.
# Creates ephemeral local Git repositories strictly inside `./target/delivery-test-*`
# (never touching `/tmp`) and verifies fail-closed exit codes and JSON outputs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERIFY_SCRIPT="${REPO_ROOT}/scripts/verify-pr-authority.sh"
SETUP_MQ_SCRIPT="${REPO_ROOT}/scripts/setup-github-merge-queue.sh"

TEST_ROOT="${REPO_ROOT}/target/delivery-test-$$-${RANDOM}"
mkdir -p "${TEST_ROOT}"
cleanup() {
    rm -rf "${TEST_ROOT}"
}
trap cleanup EXIT

export GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME="dotagent-test"
export GIT_AUTHOR_EMAIL="test@dotagent.local"
export GIT_COMMITTER_NAME="dotagent-test"
export GIT_COMMITTER_EMAIL="test@dotagent.local"

fail() {
    echo "[test-delivery-scripts] FAIL: $*" >&2
    exit 1
}

assert_exit_code() {
    local expected="$1"
    shift
    local actual=0
    "$@" >/dev/null 2>&1 || actual=$?
    if [[ "${actual}" -ne "${expected}" ]]; then
        fail "expected exit ${expected}, got ${actual} for: $*"
    fi
}

# Build ephemeral fixture repository inside target/delivery-test-*
FIXTURE_REPO="${TEST_ROOT}/repo"
mkdir -p "${FIXTURE_REPO}/scripts" \
         "${FIXTURE_REPO}/tests" \
         "${FIXTURE_REPO}/crates/agent-guard/src" \
         "${FIXTURE_REPO}/crates/dotagent-harness/tests"

git -C "${FIXTURE_REPO}" init -b main >/dev/null
cat > "${FIXTURE_REPO}/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
EOF
cat > "${FIXTURE_REPO}/crates/agent-guard/src/cmd_policy.rs" <<'EOF'
pub fn check_cmd() -> bool { true }
EOF
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v2", kind = "cmd", payload = "ls /tmp", expected_code = 2 }
]
EOF
cp "${REPO_ROOT}/scripts/allowed_hardware_signers" "${FIXTURE_REPO}/scripts/allowed_hardware_signers"

git -C "${FIXTURE_REPO}" add .
git -C "${FIXTURE_REPO}" commit -m "chore: base commit" >/dev/null
BASE_SHA="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"

# Case 1: Deleting 1 corpus vector MUST exit 2
git -C "${FIXTURE_REPO}" checkout -b case-delete-corpus "${BASE_SHA}" >/dev/null 2>&1
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 }
]
EOF
git -C "${FIXTURE_REPO}" commit -am "bad: delete corpus vector" >/dev/null
HEAD_DEL="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_DEL}")
echo "[test-delivery-scripts] ok 1 - deleting 1 corpus vector exits 2"

# Case 2: Weakening expected_code from 2 -> 0 or editing cmd_policy.rs with < 2 new vectors MUST exit 2
git -C "${FIXTURE_REPO}" checkout -b case-insufficient-ratchet "${BASE_SHA}" >/dev/null 2>&1
echo "// policy tighten" >> "${FIXTURE_REPO}/crates/agent-guard/src/cmd_policy.rs"
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v2", kind = "cmd", payload = "ls /tmp", expected_code = 2 },
  { id = "v3", kind = "cmd", payload = "cat .env.local", expected_code = 2 }
]
EOF
git -C "${FIXTURE_REPO}" commit -am "bad: only 1 new vector for cmd_policy edit" >/dev/null
HEAD_ONE="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_ONE}")
echo "[test-delivery-scripts] ok 2 - cmd_policy.rs edit with < 2 new vectors exits 2"

# Case 3: cmd_policy.rs edit + >= 2 new deny vectors passes as RING2_ALLOWLISTED + eligible_for_auto_enqueue
git -C "${FIXTURE_REPO}" checkout -b case-ring2-pass "${BASE_SHA}" >/dev/null 2>&1
echo "// policy tighten" >> "${FIXTURE_REPO}/crates/agent-guard/src/cmd_policy.rs"
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v2", kind = "cmd", payload = "ls /tmp", expected_code = 2 },
  { id = "v3", kind = "cmd", payload = "cat .env.local", expected_code = 2 },
  { id = "v4", kind = "cmd", payload = "cat ~/.aws/credentials", expected_code = 2 }
]
EOF
git -C "${FIXTURE_REPO}" commit -am "feat(policy): add 2 new corpus vectors" >/dev/null
HEAD_PASS="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
JSON_OUT="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_PASS}" --json)"
if [[ "${JSON_OUT}" != '{"tier":"ring2","hw_signed":false,"new_corpus_vectors":2,"eligible_for_auto_enqueue":true}' ]]; then
    fail "unexpected JSON summary for Ring-2 pass: ${JSON_OUT}"
fi
echo "[test-delivery-scripts] ok 3 - cmd_policy.rs + 2 new vectors passes RING2_ALLOWLISTED (${JSON_OUT})"

# Case 4: Populated allowed_hardware_signers + touching Cargo.toml without sk-* signature MUST exit 2
git -C "${FIXTURE_REPO}" checkout -b main-with-hw-signer "${BASE_SHA}" >/dev/null 2>&1
cat >> "${FIXTURE_REPO}/scripts/allowed_hardware_signers" <<'EOF'
owner@susanb.dev namespaces="git" sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAID000000000000000000000000000000000000000000AAAABHNzaDo=
EOF
git -C "${FIXTURE_REPO}" commit -am "chore: populate hardware FIDO2 signer" >/dev/null
HW_BASE_SHA="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"

git -C "${FIXTURE_REPO}" checkout -b case-ring0-unsigned "${HW_BASE_SHA}" >/dev/null 2>&1
echo "# ring0 edit" >> "${FIXTURE_REPO}/Cargo.toml"
# Also attempt to wipe allowed_hardware_signers in PR head -- must still fail against BASE_REF trust anchor!
: > "${FIXTURE_REPO}/scripts/allowed_hardware_signers"
git -C "${FIXTURE_REPO}" commit -am "evil: unsigned Cargo.toml + signer wipe" >/dev/null
HEAD_RING0="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${HW_BASE_SHA}" --head "${HEAD_RING0}")
echo "[test-delivery-scripts] ok 4 - touching Cargo.toml without sk-* signature exits 2 (even on signer-wipe attempt)"

# Case 5: Non-hardware ssh-ed25519 key in allowed_hardware_signers MUST exit 2
BAD_SIGNERS="${TEST_ROOT}/bad_signers"
cat > "${BAD_SIGNERS}" <<'EOF'
owner@susanb.dev namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID000000000000000000000000000000000000000000
EOF
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_PASS}" --signers-file "${BAD_SIGNERS}")
echo "[test-delivery-scripts] ok 5 - software ssh-ed25519 key in allowed_hardware_signers exits 2"

# Case 6: Verify setup-github-merge-queue.sh manifest & dry-run when present
if [[ -f "${SETUP_MQ_SCRIPT}" ]]; then
    MANIFEST_JSON="$(bash "${SETUP_MQ_SCRIPT}" --print-app-manifest)"
    python3 -c 'import json, sys; d = json.loads(sys.argv[1]); assert d["default_permissions"]["contents"] == "write" and d["default_permissions"]["pull_requests"] == "write"' "${MANIFEST_JSON}"
    DRY_OUT="$(bash "${SETUP_MQ_SCRIPT}" --owner susanbdev --repo dotagent --promoter-app-id 123456 --dry-run)"
    [[ "${DRY_OUT}" == *"merge_queue"* && "${DRY_OUT}" == *"SQUASH"* ]] || fail "dry-run missing merge_queue payload"
    echo "[test-delivery-scripts] ok 6 - setup-github-merge-queue.sh manifest & dry-run validated"
fi

echo "[test-delivery-scripts] ALL TESTS PASSED"
