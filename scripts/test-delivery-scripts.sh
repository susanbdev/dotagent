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
export GIT_CONFIG_GLOBAL="${TEST_ROOT}/empty.gitconfig"
: > "${GIT_CONFIG_GLOBAL}"
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

VALID_SK_PUBKEY="$(python3 -c 'import base64; kt=b"sk-ssh-ed25519@openssh.com"; app=b"ssh:"; blob=len(kt).to_bytes(4,"big")+kt+(32).to_bytes(4,"big")+(b"\x11"*32)+len(app).to_bytes(4,"big")+app; print(base64.b64encode(blob).decode())')"

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

# Case 2: Duplicating an existing vector twice for cmd_policy.rs edit MUST exit 2 (anti-padding ratchet)
git -C "${FIXTURE_REPO}" checkout -b case-dup-ratchet "${BASE_SHA}" >/dev/null 2>&1
echo "// policy tighten" >> "${FIXTURE_REPO}/crates/agent-guard/src/cmd_policy.rs"
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v2", kind = "cmd", payload = "ls /tmp", expected_code = 2 },
  { id = "v3", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v4", kind = "cmd", payload = "ls /tmp", expected_code = 2 }
]
EOF
git -C "${FIXTURE_REPO}" commit -am "bad: duplicate existing vectors" >/dev/null
HEAD_DUP="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_DUP}")
echo "[test-delivery-scripts] ok 2 - duplicate corpus vector padding exits 2"

# Case 3: cmd_policy.rs edit + >= 2 unique new deny vectors + harness .rs test passes RING2_ALLOWLISTED
git -C "${FIXTURE_REPO}" checkout -b case-ring2-pass "${BASE_SHA}" >/dev/null 2>&1
echo "// policy tighten" >> "${FIXTURE_REPO}/crates/agent-guard/src/cmd_policy.rs"
echo "#[test] fn smoke() {}" > "${FIXTURE_REPO}/crates/dotagent-harness/tests/new_case.rs"
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v2", kind = "cmd", payload = "ls /tmp", expected_code = 2 },
  { id = "v3", kind = "cmd", payload = "cat .env.local", expected_code = 2 },
  { id = "v4", kind = "cmd", payload = "cat ~/.aws/credentials", expected_code = 2 }
]
EOF
git -C "${FIXTURE_REPO}" add .
git -C "${FIXTURE_REPO}" commit -m "feat(policy): add 2 unique corpus vectors" >/dev/null
HEAD_PASS="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
JSON_OUT="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_PASS}" --json)"
[[ "${JSON_OUT}" == '{"tier":"ring2","hw_signed":false,"new_corpus_vectors":2,"eligible_for_auto_enqueue":true}' ]] \
    || fail "unexpected JSON summary for Ring-2 pass: ${JSON_OUT}"
echo "[test-delivery-scripts] ok 3 - cmd_policy.rs + 2 unique vectors passes RING2_ALLOWLISTED (${JSON_OUT})"

# Case 4: Unsigned Ring-0 change fails closed by default even with 0 active signers, AND unsigned sk-* enrollment fails even under --bootstrap-allow-empty-signers
git -C "${FIXTURE_REPO}" checkout -b case-evil-enroll "${BASE_SHA}" >/dev/null 2>&1
printf 'attacker@evil.dev namespaces="git" sk-ssh-ed25519@openssh.com %s\n' "${VALID_SK_PUBKEY}" >> "${FIXTURE_REPO}/scripts/allowed_hardware_signers"
git -C "${FIXTURE_REPO}" commit -am "evil: unsigned attacker sk-* enrollment" >/dev/null
HEAD_EVIL_ENROLL="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_EVIL_ENROLL}" --bootstrap-allow-empty-signers)
echo "[test-delivery-scripts] ok 4 - unsigned sk-* trust-anchor enrollment exits 2 even in bootstrap mode"

# Case 5: Populated allowed_hardware_signers + touching Cargo.toml without sk-* signature MUST exit 2
git -C "${FIXTURE_REPO}" checkout -b main-with-hw-signer "${BASE_SHA}" >/dev/null 2>&1
printf 'owner@susanb.dev namespaces="git" sk-ssh-ed25519@openssh.com %s\n' "${VALID_SK_PUBKEY}" >> "${FIXTURE_REPO}/scripts/allowed_hardware_signers"
git -C "${FIXTURE_REPO}" commit -am "chore: populate hardware FIDO2 signer" >/dev/null
HW_BASE_SHA="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"

git -C "${FIXTURE_REPO}" checkout -b case-ring0-unsigned "${HW_BASE_SHA}" >/dev/null 2>&1
echo "# ring0 edit" >> "${FIXTURE_REPO}/Cargo.toml"
: > "${FIXTURE_REPO}/scripts/allowed_hardware_signers"
git -C "${FIXTURE_REPO}" commit -am "evil: unsigned Cargo.toml + signer wipe" >/dev/null
HEAD_RING0="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${HW_BASE_SHA}" --head "${HEAD_RING0}" --bootstrap-allow-empty-signers)
echo "[test-delivery-scripts] ok 5 - touching Cargo.toml without sk-* signature exits 2"

# Case 5b: Unsigned Ring-2 PR on populated HW_BASE_SHA (leaving allowed_hardware_signers untouched) MUST pass
git -C "${FIXTURE_REPO}" checkout -b case-ring2-on-hw-base "${HW_BASE_SHA}" >/dev/null 2>&1
echo "// ring2 policy tighten" >> "${FIXTURE_REPO}/crates/agent-guard/src/cmd_policy.rs"
cat > "${FIXTURE_REPO}/tests/bypass_corpus.toml" <<'EOF'
vectors = [
  { id = "v1", kind = "cmd", payload = "cat .env", expected_code = 2 },
  { id = "v2", kind = "cmd", payload = "ls /tmp", expected_code = 2 },
  { id = "v3", kind = "cmd", payload = "cat .env.prod", expected_code = 2 },
  { id = "v4", kind = "cmd", payload = "cat ~/.ssh/id_ed25519", expected_code = 2 }
]
EOF
git -C "${FIXTURE_REPO}" commit -am "feat(policy): unsigned Ring-2 PR on populated anchor" >/dev/null
HEAD_R2_HW="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
R2_HW_JSON="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${HW_BASE_SHA}" --head "${HEAD_R2_HW}" --json)"
[[ "${R2_HW_JSON}" == '{"tier":"ring2","hw_signed":false,"new_corpus_vectors":2,"eligible_for_auto_enqueue":true}' ]] \
    || fail "unsigned Ring-2 PR failed on populated base: ${R2_HW_JSON}"
echo "[test-delivery-scripts] ok 5b - unsigned Ring-2 PR passes when populated trust anchor is unchanged"

# Case 6: Trailing-comment sk-* smuggling on software ssh-ed25519 key MUST exit 2
SMUGGLED_SIGNERS="${TEST_ROOT}/smuggled_signers"
cat > "${SMUGGLED_SIGNERS}" <<'EOF'
owner@susanb.dev namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID000000000000000000000000000000000000000000 sk-ssh-ed25519@openssh.com
EOF
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_PASS}" --signers-file "${SMUGGLED_SIGNERS}")
echo "[test-delivery-scripts] ok 6 - trailing-comment software ssh-ed25519 smuggling exits 2"

# Case 7: Empty 0-file diff fails closed by default (and is ineligible under bootstrap)
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${BASE_SHA}" --json)
EMPTY_JSON="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${BASE_SHA}" --bootstrap-allow-empty-signers --json)"
[[ "${EMPTY_JSON}" == '{"tier":"ring0","hw_signed":false,"new_corpus_vectors":0,"eligible_for_auto_enqueue":false}' ]] \
    || fail "empty diff should not be eligible_for_auto_enqueue: ${EMPTY_JSON}"
echo "[test-delivery-scripts] ok 7 - empty diff fails closed by default and disables auto-enqueue"

# Case 8: Verify setup-github-merge-queue.sh manifest & dry-run
MANIFEST_JSON="$(bash "${SETUP_MQ_SCRIPT}" --print-app-manifest)"
python3 -c 'import json, sys; d = json.loads(sys.argv[1]); assert d["default_permissions"]["contents"] == "write" and d["default_permissions"]["pull_requests"] == "write"' "${MANIFEST_JSON}"
DRY_OUT="$(bash "${SETUP_MQ_SCRIPT}" --owner susanbdev --repo dotagent --promoter-app-id 123456 --dry-run)"
[[ "${DRY_OUT}" == *"merge_queue"* && "${DRY_OUT}" == *"15368"* && "${DRY_OUT}" == *"dotagent-release-tags"* ]] \
    || fail "dry-run missing merge_queue / integration_id / tag_ruleset payload"
echo "[test-delivery-scripts] ok 8 - setup-github-merge-queue.sh manifest & dry-run validated"

echo "[test-delivery-scripts] ALL TESTS PASSED"
