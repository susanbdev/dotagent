#!/usr/bin/env bash
# Deterministic PR Authority & Ring-0 Hardware-Signature Gate (`susanbdev/dotagent`)
# Distinguishes allowlisted Ring-2 PRs (with monotonic `bypass_corpus.toml` ratchet)
# from Ring-0 protected changes requiring an OpenSSH hardware FIDO2 (`sk-*`) commit signature.

set -euo pipefail

BASE_REF=""
HEAD_REF="HEAD"
SIGNERS_FILE=""
ALLOW_MQ_PARENTS="false"
JSON_ONLY="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base) BASE_REF="${2:-}"; shift 2 ;;
        --head) HEAD_REF="${2:-}"; shift 2 ;;
        --signers-file) SIGNERS_FILE="${2:-}"; shift 2 ;;
        --allow-merge-queue-parents) ALLOW_MQ_PARENTS="true"; shift ;;
        --json) JSON_ONLY="true"; shift ;;
        *)
            echo "USAGE_ERROR: unknown argument '$1'" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${BASE_REF}" || -z "${HEAD_REF}" ]]; then
    echo "USAGE_ERROR: --base <git_ref> and --head <git_ref> are required" >&2
    exit 2
fi
git rev-parse --verify "${BASE_REF}^{commit}" >/dev/null 2>&1 || { echo "INVALID_GIT_REF: ${BASE_REF}" >&2; exit 2; }
git rev-parse --verify "${HEAD_REF}^{commit}" >/dev/null 2>&1 || { echo "INVALID_GIT_REF: ${HEAD_REF}" >&2; exit 2; }

WORK_DIR="$(pwd)/target/.authority-verify-$$-${RANDOM}"
mkdir -p "${WORK_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

RAW_SIGNERS="${WORK_DIR}/raw_signers"
CLEAN_SIGNERS="${WORK_DIR}/clean_signers"
if [[ -n "${SIGNERS_FILE}" ]]; then
    [[ -f "${SIGNERS_FILE}" ]] || { echo "SIGNERS_FILE_MISSING: '${SIGNERS_FILE}'" >&2; exit 2; }
    cp "${SIGNERS_FILE}" "${RAW_SIGNERS}"
elif git cat-file -e "${BASE_REF}:scripts/allowed_hardware_signers" 2>/dev/null; then
    git show "${BASE_REF}:scripts/allowed_hardware_signers" > "${RAW_SIGNERS}"
elif [[ -f "scripts/allowed_hardware_signers" ]]; then
    cp "scripts/allowed_hardware_signers" "${RAW_SIGNERS}"
else
    : > "${RAW_SIGNERS}"
fi

ACTIVE_HW_SIGNERS="$(python3 - "${RAW_SIGNERS}" "${CLEAN_SIGNERS}" <<'PY'
import sys
raw_path, clean_path = sys.argv[1], sys.argv[2]
allowed = {"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}
valid = []
with open(raw_path, "r", encoding="utf-8") as fh:
    for lineno, raw in enumerate(fh, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        has_ns = any(p.startswith("namespaces=") and "git" in p for p in parts[1:-2])
        if len(parts) < 4 or not has_ns or not any(p in allowed for p in parts):
            sys.stderr.write(f"NON_HARDWARE_SIGNER_FORBIDDEN: invalid signer on line {lineno}\n")
            sys.exit(2)
        valid.append(line + "\n")
with open(clean_path, "w", encoding="utf-8") as out:
    out.writelines(valid)
print(len(valid))
PY
)"

verify_commit_hw_sig() {
    local commit_ref="$1"
    [[ "${ACTIVE_HW_SIGNERS}" -gt 0 ]] || return 1
    git -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=${CLEAN_SIGNERS}" verify-commit "${commit_ref}" >/dev/null 2>&1 || return 1
    python3 - "${commit_ref}" "${CLEAN_SIGNERS}" "${WORK_DIR}" <<'PY'
import os, subprocess, sys
commit_ref, signers, work_dir = sys.argv[1:4]
raw = subprocess.check_output(["git", "cat-file", "commit", commit_ref])
hdr, sep, body = raw.partition(b"\n\n")
if not sep:
    sys.exit(1)
sig_lines, kept, in_sig = [], [], False
for line in hdr.split(b"\n"):
    if line.startswith(b"gpgsig "):
        in_sig = True
        sig_lines.append(line[7:])
    elif in_sig and line.startswith(b" "):
        sig_lines.append(line[1:])
    else:
        in_sig = False
        kept.append(line)
sig_text = b"\n".join(sig_lines) + b"\n"
if b"-----BEGIN SSH SIGNATURE-----" not in sig_text:
    sys.exit(1)
sig_path, payload_path = os.path.join(work_dir, "head.sig"), os.path.join(work_dir, "head.payload")
open(sig_path, "wb").write(sig_text)
open(payload_path, "wb").write(b"\n".join(kept) + b"\n\n" + body)
principals = subprocess.check_output(
    ["ssh-keygen", "-Y", "find-principals", "-f", signers, "-s", sig_path], stderr=subprocess.DEVNULL
).decode("utf-8", errors="replace").strip().splitlines()
if not principals:
    sys.exit(1)
with open(payload_path, "rb") as pf:
    subprocess.check_call(
        ["ssh-keygen", "-Y", "verify", "-f", signers, "-I", principals[0].strip(), "-n", "git", "-s", sig_path],
        stdin=pf, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
PY
}

TIER="ring2"
POLICY_MODIFIED="false"
while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    case "${path}" in
        crates/agent-guard/src/diagnostics.rs|tests/bypass_corpus.toml) ;;
        crates/agent-guard/src/cmd_policy.rs|crates/agent-guard/src/mcp_policy.rs) POLICY_MODIFIED="true" ;;
        crates/dotagent-harness/tests/*) [[ "${path}" == *".."* ]] && TIER="ring0" ;;
        *) TIER="ring0" ;;
    esac
done < <(git diff --name-only "${BASE_REF}...${HEAD_REF}")

HW_SIGNED="false"
if verify_commit_hw_sig "${HEAD_REF}"; then
    HW_SIGNED="true"
elif [[ "${ALLOW_MQ_PARENTS}" == "true" ]] && git rev-parse --verify -q "${HEAD_REF}^2" >/dev/null 2>&1; then
    MQ_OK="true"; MQ_COUNT=0
    while IFS= read -r msha; do
        [[ -z "${msha}" ]] && continue
        MQ_COUNT=$((MQ_COUNT + 1))
        verify_commit_hw_sig "${msha}^2" || { MQ_OK="false"; break; }
    done < <(git rev-list --first-parent --merges "${BASE_REF}..${HEAD_REF}")
    [[ "${MQ_COUNT}" -gt 0 && "${MQ_OK}" == "true" ]] && HW_SIGNED="true"
fi

NEW_CORPUS_VECTORS="$(python3 - "${BASE_REF}" "${HEAD_REF}" "${HW_SIGNED}" "${POLICY_MODIFIED}" <<'PY'
from collections import Counter
import json, subprocess, sys, tomllib

base_ref, head_ref, hw_s, pol_s = sys.argv[1:5]
hw_signed, policy_mod = (hw_s == "true"), (pol_s == "true")

def load_vecs(ref: str):
    p = subprocess.run(["git", "show", f"{ref}:tests/bypass_corpus.toml"], capture_output=True)
    if p.returncode != 0:
        return None
    try:
        doc = tomllib.loads(p.stdout.decode("utf-8"))
    except Exception as exc:
        sys.stderr.write(f"CORPUS_PARSE_ERROR: {ref}:tests/bypass_corpus.toml: {exc}\n")
        sys.exit(2)
    vecs = doc.get("vectors", doc.get("cases"))
    if not isinstance(vecs, list) or any(not isinstance(v, dict) for v in vecs):
        sys.stderr.write(f"CORPUS_SCHEMA_ERROR: {ref}:tests/bypass_corpus.toml\n")
        sys.exit(2)
    return vecs

base_v, head_v = load_vecs(base_ref), load_vecs(head_ref)
if base_v is not None and head_v is None:
    if not hw_signed:
        sys.stderr.write("CORPUS_RATCHET_VIOLATION: tests/bypass_corpus.toml deleted\n")
        sys.exit(2)
    print(0); sys.exit(0)

bc = Counter(json.dumps(v, sort_keys=True, separators=(",", ":")) for v in (base_v or []))
hc = Counter(json.dumps(v, sort_keys=True, separators=(",", ":")) for v in (head_v or []))
for canon, cnt in bc.items():
    if hc[canon] < cnt and not hw_signed:
        sys.stderr.write(f"CORPUS_RATCHET_VIOLATION: vector deleted or weakened: {canon}\n")
        sys.exit(2)

new_deny = sum(
    cnt for canon, cnt in (hc - bc).items()
    if json.loads(canon).get("expected_code", 2) == 2 and str(json.loads(canon).get("action", "deny")).lower() == "deny"
)
if policy_mod and not hw_signed and new_deny < 2:
    sys.stderr.write(f"CORPUS_RATCHET_VIOLATION: cmd/mcp policy edit requires >= 2 new deny vectors (got {new_deny})\n")
    sys.exit(2)
print(new_deny)
PY
)"

ELIGIBLE="true"
if [[ "${TIER}" == "ring0" && "${HW_SIGNED}" != "true" ]]; then
    ELIGIBLE="false"
    if [[ "${ACTIVE_HW_SIGNERS}" -gt 0 || "${DOTAGENT_ENFORCE_HW_SIGNERS:-0}" == "1" ]]; then
        echo "RING0_HARDWARE_SIGNATURE_REQUIRED: Ring-0 paths modified without valid sk-* hardware commit signature" >&2
        exit 2
    fi
    echo "[verify-pr-authority] BOOTSTRAP_NOTICE: Ring-0 paths modified with 0 active sk-* signers; auto-enqueue disabled" >&2
fi

SUMMARY="$(printf '{"tier":"%s","hw_signed":%s,"new_corpus_vectors":%d,"eligible_for_auto_enqueue":%s}' "${TIER}" "${HW_SIGNED}" "${NEW_CORPUS_VECTORS}" "${ELIGIBLE}")"
[[ "${JSON_ONLY}" == "true" ]] || echo "[verify-pr-authority] PASS: ${SUMMARY}" >&2
printf '%s\n' "${SUMMARY}"
