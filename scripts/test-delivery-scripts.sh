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

# Case 6: Trailing-token smuggling (5 tokens) on signer line MUST exit 2
SMUGGLED_SIGNERS="${TEST_ROOT}/smuggled_signers"
cat > "${SMUGGLED_SIGNERS}" <<'EOF'
owner@susanb.dev namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID000000000000000000000000000000000000000000 extra-token
EOF
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${HEAD_PASS}" --signers-file "${SMUGGLED_SIGNERS}")
echo "[test-delivery-scripts] ok 6 - 5-token trailing-comment signer smuggling exits 2"

# Case 6b: Standard ssh-ed25519 commit signature (zero sk-* hardware key) passes Ring-0 PR
STD_KEY="${TEST_ROOT}/owner_ed25519"
ssh-keygen -t ed25519 -N "" -C "owner@susanb.dev" -f "${STD_KEY}" >/dev/null 2>&1
STD_PUB_B64="$(awk '{print $2}' "${STD_KEY}.pub")"
git -C "${FIXTURE_REPO}" checkout -b main-with-std-ssh "${BASE_SHA}" >/dev/null 2>&1
printf 'owner@susanb.dev namespaces="git" ssh-ed25519 %s\n' "${STD_PUB_B64}" >> "${FIXTURE_REPO}/scripts/allowed_hardware_signers"
git -C "${FIXTURE_REPO}" commit -am "chore: enroll standard ssh-ed25519 signer" >/dev/null
STD_BASE_SHA="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"

git -C "${FIXTURE_REPO}" checkout -b case-ring0-std-ssh "${STD_BASE_SHA}" >/dev/null 2>&1
git -C "${FIXTURE_REPO}" config gpg.format ssh
git -C "${FIXTURE_REPO}" config user.signingkey "${STD_KEY}"
echo "# ring0 cargo update" >> "${FIXTURE_REPO}/Cargo.toml"
git -C "${FIXTURE_REPO}" commit -S -am "feat: standard ssh-ed25519 signed Ring-0 update" >/dev/null
HEAD_R0_STD="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
R0_STD_JSON="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${STD_BASE_SHA}" --head "${HEAD_R0_STD}" --json)"
[[ "${R0_STD_JSON}" == '{"tier":"ring0","hw_signed":true,"new_corpus_vectors":0,"eligible_for_auto_enqueue":true}' ]] \
    || fail "standard ssh-ed25519 Ring-0 PR failed: ${R0_STD_JSON}"
echo "[test-delivery-scripts] ok 6b - standard ssh-ed25519 commit signature passes Ring-0 PR"

# Case 6c: Human owner GitHub APPROVED PR authority (--pr-approved) passes unsigned Ring-0 PR
git -C "${FIXTURE_REPO}" checkout -b case-ring0-approved "${STD_BASE_SHA}" >/dev/null 2>&1
echo "# approved ring0 edit" >> "${FIXTURE_REPO}/Cargo.toml"
git -C "${FIXTURE_REPO}" commit --no-gpg-sign -am "feat: owner-approved Ring-0 update" >/dev/null
HEAD_R0_APP="$(git -C "${FIXTURE_REPO}" rev-parse HEAD)"
R0_APP_JSON="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${STD_BASE_SHA}" --head "${HEAD_R0_APP}" --pr-approved --json)"
[[ "${R0_APP_JSON}" == '{"tier":"ring0","hw_signed":true,"new_corpus_vectors":0,"eligible_for_auto_enqueue":true}' ]] \
    || fail "owner-approved Ring-0 PR failed: ${R0_APP_JSON}"
echo "[test-delivery-scripts] ok 6c - GitHub APPROVED human-owner PR authority passes Ring-0 PR"

# Case 6d: Enrolled sk-ssh-ed25519@openssh.com commit signature with UP=0 (flags=0) passes Ring-0 PR without touch
SK_UP0_SHA="$(python3 - "${FIXTURE_REPO}" "${TEST_ROOT}" "${BASE_SHA}" <<'PY'
import base64, hashlib, os, subprocess, sys

repo, test_root, base_sha = sys.argv[1:4]
pem = os.path.join(test_root, "sk_ed25519.pem")
subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", pem], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
raw_pub = subprocess.check_output(["openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER"])[-32:]
def sstr(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b
alg = b"sk-ssh-ed25519@openssh.com"
app = b"ssh:delivery-up0"
sk_pub_blob = sstr(alg) + sstr(raw_pub) + sstr(app)
sk_pub_b64 = base64.b64encode(sk_pub_blob).decode("ascii")

subprocess.run(["git", "-C", repo, "checkout", "-b", "main-sk-up0", base_sha], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(os.path.join(repo, "scripts", "allowed_hardware_signers"), "a", encoding="ascii") as fh:
    fh.write(f'owner@susanb.dev namespaces="git" sk-ssh-ed25519@openssh.com {sk_pub_b64}\n')
subprocess.run(["git", "-C", repo, "commit", "--no-gpg-sign", "-am", "chore: enroll sk signer"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sk_base = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()

subprocess.run(["git", "-C", repo, "checkout", "-b", "case-sk-up0", sk_base], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(os.path.join(repo, "Cargo.toml"), "a", encoding="ascii") as fh:
    fh.write("# sk up0 commit\n")
subprocess.run(["git", "-C", repo, "commit", "--no-gpg-sign", "-am", "feat: sk up0 ring0 edit"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
unsigned_commit = subprocess.check_output(["git", "-C", repo, "cat-file", "commit", "HEAD"])
hdr, _, body = unsigned_commit.partition(b"\n\n")
tbs = b"SSHSIG" + sstr(b"git") + sstr(b"") + sstr(b"sha512") + sstr(hashlib.sha512(unsigned_commit).digest())
flags = 0
counter = (3).to_bytes(4, "big")
in_f, sig_f = os.path.join(test_root, "sk_in"), os.path.join(test_root, "sk_sig")
open(in_f, "wb").write(hashlib.sha256(app).digest() + bytes([flags]) + counter + hashlib.sha256(tbs).digest())
subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", pem, "-rawin", "-in", in_f, "-out", sig_f], check=True)
ed_sig = open(sig_f, "rb").read()
sig_blob = sstr(alg) + sstr(ed_sig) + bytes([flags]) + counter
wire = b"SSHSIG" + (1).to_bytes(4, "big") + sstr(sk_pub_blob) + sstr(b"git") + sstr(b"") + sstr(b"sha512") + sstr(sig_blob)
pem_lines = ("-----BEGIN SSH SIGNATURE-----\n" + base64.encodebytes(wire).decode("ascii") + "-----END SSH SIGNATURE-----").splitlines()
gpgsig = b"\n".join((b"gpgsig " + l.encode("ascii")) if i == 0 else (b" " + l.encode("ascii")) for i, l in enumerate(pem_lines))
signed_commit = hdr + b"\n" + gpgsig + b"\n\n" + body
new_oid = subprocess.check_output(["git", "-C", repo, "hash-object", "-t", "commit", "-w", "--stdin"], input=signed_commit).decode("ascii").strip()
print(f"{sk_base}:{new_oid}")
PY
)"
SK_BASE_REF="${SK_UP0_SHA%%:*}"
SK_HEAD_REF="${SK_UP0_SHA##*:}"
R0_SK_UP0_JSON="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${SK_BASE_REF}" --head "${SK_HEAD_REF}" --json)"
[[ "${R0_SK_UP0_JSON}" == '{"tier":"ring0","hw_signed":true,"new_corpus_vectors":0,"eligible_for_auto_enqueue":true}' ]] \
    || fail "sk-ssh-ed25519 UP=0 Ring-0 PR failed: ${R0_SK_UP0_JSON}"
echo "[test-delivery-scripts] ok 6d - sk-ssh-ed25519 UP=0 commit signature passes Ring-0 PR without touch"

# Case 7: Empty 0-file diff fails closed by default (and is ineligible under bootstrap)
(cd "${FIXTURE_REPO}" && assert_exit_code 2 bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${BASE_SHA}" --json)
EMPTY_JSON="$(cd "${FIXTURE_REPO}" && bash "${VERIFY_SCRIPT}" --base "${BASE_SHA}" --head "${BASE_SHA}" --bootstrap-allow-empty-signers --json)"
[[ "${EMPTY_JSON}" == '{"tier":"ring0","hw_signed":false,"new_corpus_vectors":0,"eligible_for_auto_enqueue":false}' ]] \
    || fail "empty diff should not be eligible_for_auto_enqueue: ${EMPTY_JSON}"
echo "[test-delivery-scripts] ok 7 - empty diff fails closed by default and disables auto-enqueue"

# Case 8: Verify the compatible App manifest and ruleset plan.
RULESETS_BIN="${DOTAGENT_RULESETS_BIN:-${CARGO_TARGET_DIR:-${REPO_ROOT}/target}/release/dotagent}"
[[ -x "${RULESETS_BIN}" ]] || fail "build the dotagent release binary or set DOTAGENT_RULESETS_BIN"
RULESETS_BIN="$(cd "$(dirname -- "${RULESETS_BIN}")" && pwd)/$(basename -- "${RULESETS_BIN}")"
mkdir -p "${TEST_ROOT}/bin"
ln -s "${RULESETS_BIN}" "${TEST_ROOT}/bin/dotagent"
WRAPPER_PATH="${TEST_ROOT}/bin:${PATH}"
MANIFEST_JSON="$(PATH="${WRAPPER_PATH}" bash "${SETUP_MQ_SCRIPT}" --owner fixture-org --print-app-manifest)"
NATIVE_MANIFEST="$("${RULESETS_BIN}" github-rulesets --org fixture-org --print-app-manifest)"
[[ -n "${NATIVE_MANIFEST}" && "${MANIFEST_JSON}" == "${NATIVE_MANIFEST}" ]] \
    || fail "compatibility manifest diverged from native manifest"
assert_exit_code 2 env PATH="${WRAPPER_PATH}" bash "${SETUP_MQ_SCRIPT}" --owner 'invalid/owner' --print-app-manifest
assert_exit_code 2 "${RULESETS_BIN}" github-rulesets --org 'invalid/owner' --print-app-manifest
DRY_OUT="$(PATH="${WRAPPER_PATH}" bash "${SETUP_MQ_SCRIPT}" --owner susanbdev --repo dotagent --promoter-app-id 123456 --dry-run)"
CANONICAL_OUT="$("${RULESETS_BIN}" github-rulesets --repo susanbdev/dotagent --promoter-app-id 123456 --dry-run)"
[[ "${DRY_OUT}" == "${CANONICAL_OUT}" ]] || fail "compatibility dry-run diverged from canonical plan"
assert_exit_code 2 bash "${SETUP_MQ_SCRIPT}" --all-fleet --apply
echo "[test-delivery-scripts] ok 8 - promoter App manifest and compatibility ruleset dry-run"

ORG_OUT="$("${RULESETS_BIN}" github-rulesets --org susanbdev --include-repo policy-hub)"
python3 -c 'import json, sys; d = json.loads(sys.argv[1]); sys.exit(d["endpoint"] != "orgs/susanbdev/rulesets" or d["rulesets"][0]["conditions"]["repository_name"]["include"] != ["policy-hub"])' "${ORG_OUT}"
echo "[test-delivery-scripts] ok 9 - offline organization ruleset scope"

echo "[test-delivery-scripts] ALL TESTS PASSED"
