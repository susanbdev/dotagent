#!/usr/bin/env bash
# Deterministic PR Authority & Ring-0 Signature/Approval Gate (`susanbdev/dotagent`)
# Distinguishes allowlisted Ring-2 PRs (with unique monotonic `bypass_corpus.toml` ratchet)
# from Ring-0 protected changes authorized via OpenSSH (`ssh-ed25519`, `ecdsa-sha2-nistp256`,
# or `sk-*`) commit signatures or GitHub `APPROVED` human-owner PR authority.

set -euo pipefail

BASE_REF=""; HEAD_REF="HEAD"; SIGNERS_FILE=""; ALLOW_MQ_PARENTS="false"; BOOTSTRAP_EMPTY="false"; BOOTSTRAP_SIGNER=""; PR_APPROVED="false"; JSON_ONLY="false"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base|--head|--signers-file|--bootstrap-signer)
            [[ "$1" == "--base" ]] && BASE_REF="${2:-}"
            [[ "$1" == "--head" ]] && HEAD_REF="${2:-}"
            [[ "$1" == "--signers-file" ]] && SIGNERS_FILE="${2:-}"
            [[ "$1" == "--bootstrap-signer" ]] && BOOTSTRAP_SIGNER="${2:-}"
            shift 2 ;;
        --allow-merge-queue-parents) ALLOW_MQ_PARENTS="true"; shift ;;
        --bootstrap-allow-empty-signers) BOOTSTRAP_EMPTY="true"; shift ;;
        --pr-approved|--owner-approved) PR_APPROVED="true"; shift ;;
        --json) JSON_ONLY="true"; shift ;;
        *) echo "USAGE_ERROR: unknown argument '$1'" >&2; exit 2 ;;
    esac
done
[[ -n "${BASE_REF}" && -n "${HEAD_REF}" ]] || { echo "USAGE_ERROR: --base and --head required" >&2; exit 2; }
for r in "${BASE_REF}" "${HEAD_REF}"; do git rev-parse --verify "${r}^{commit}" >/dev/null 2>&1 || { echo "INVALID_GIT_REF: ${r}" >&2; exit 2; }; done

WORK_DIR="$(pwd)/target/.authority-verify-$$-${RANDOM}"
mkdir -p "${WORK_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

RAW_SIGNERS="${WORK_DIR}/raw_signers"; CLEAN_SIGNERS="${WORK_DIR}/clean_signers"
: > "${RAW_SIGNERS}"
if [[ -n "${SIGNERS_FILE}" ]]; then
    [[ -f "${SIGNERS_FILE}" && ! -L "${SIGNERS_FILE}" ]] || { echo "SIGNERS_FILE_INVALID: '${SIGNERS_FILE}'" >&2; exit 2; }
    cp "${SIGNERS_FILE}" "${RAW_SIGNERS}"
else
    if git cat-file -e "${BASE_REF}:scripts/allowed_hardware_signers" 2>/dev/null; then
        git show "${BASE_REF}:scripts/allowed_hardware_signers" >> "${RAW_SIGNERS}"
        printf '\n' >> "${RAW_SIGNERS}"
    fi
    if git cat-file -e "${BASE_REF}:config/allowed_human_signers" 2>/dev/null; then
        git show "${BASE_REF}:config/allowed_human_signers" >> "${RAW_SIGNERS}"
        printf '\n' >> "${RAW_SIGNERS}"
    fi
fi

RESULT_JSON="$(python3 - "${BASE_REF}" "${HEAD_REF}" "${RAW_SIGNERS}" "${CLEAN_SIGNERS}" "${WORK_DIR}" "${ALLOW_MQ_PARENTS}" "${BOOTSTRAP_EMPTY}" "${BOOTSTRAP_SIGNER}" "${DOTAGENT_ENFORCE_HW_SIGNERS:-0}" "${PR_APPROVED}" <<'PY'
import base64, json, os, re, subprocess, sys, tomllib

base_ref, head_ref, raw_signers, clean_signers, work_dir, allow_mq_s, boot_empty_s, boot_signer, enforce_s, pr_approved_s = sys.argv[1:11]
allow_mq, boot_empty, enforce_hw = (allow_mq_s == "true"), (boot_empty_s == "true"), (enforce_s == "1")
pr_approved = (pr_approved_s == "true")
allowed_kt = {
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
allowed_opts = {
    'namespaces="git"',
    'namespaces="git",no-touch-required',
    'no-touch-required,namespaces="git"',
}
principal_re = re.compile(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$")
# Spec Ring-2 allowlist permits only top-level harness .rs tests; nested or non-.rs paths escalate to Ring-0
harness_rs_re = re.compile(r"^crates/dotagent-harness/tests/[A-Za-z0-9_.-]+\.rs$")

def die(msg: str):
    sys.stderr.write(msg + "\n"); sys.exit(2)

def openssh_supports_no_touch_opt() -> bool:
    probe_path = os.path.join(work_dir, "probe_no_touch_signers")
    with open(probe_path, "w", encoding="ascii") as fh:
        fh.write(
            'probe@dotagent.local namespaces="git",no-touch-required sk-ssh-ed25519@openssh.com '
            "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIONErNAQxLFUrTlkW6aphr1CYrio2kjFDCAGaZAW15GeAAAAE3NzaDpnaXRodWItcGVyc29uYWw=\n"
        )
    res = subprocess.run(
        ["ssh-keygen", "-Y", "match-principals", "-I", "probe@dotagent.local", "-f", probe_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        os.remove(probe_path)
    except OSError:
        pass
    return res.returncode == 0

def parse_signers_text(text: str, label: str, include_no_touch: bool = False, preserve_raw_opts: bool = False) -> list[str]:
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 4:
            die(f"SIGNER_ENTRY_FORBIDDEN: {label} line {lineno} must have exactly 4 tokens")
        principal, opts, key_type, pubkey_b64 = parts
        if not principal_re.fullmatch(principal) or opts not in allowed_opts or key_type not in allowed_kt:
            die(f"SIGNER_ENTRY_FORBIDDEN: {label} line {lineno} failed principal/namespace/key-type validation")
        try:
            blob = base64.b64decode(pubkey_b64, validate=True)
            klen = int.from_bytes(blob[:4], "big") if len(blob) >= 4 else -1
            wire_kt = blob[4 : 4 + klen].decode("ascii") if 0 < klen <= len(blob) - 4 else ""
        except Exception:
            wire_kt = ""
        if wire_kt != key_type:
            die(f"SIGNER_ENTRY_FORBIDDEN: {label} line {lineno} wire key type '{wire_kt}' != '{key_type}'")
        if preserve_raw_opts:
            canon_opts = ",".join(sorted(o for o in opts.split(",") if o))
        elif include_no_touch and key_type.startswith("sk-"):
            canon_opts = 'namespaces="git",no-touch-required'
        else:
            canon_opts = 'namespaces="git"'
        out.append(f"{principal} {canon_opts} {key_type} {pubkey_b64}\n")
    return out

emit_no_touch = openssh_supports_no_touch_opt()
valid_signers = parse_signers_text(
    open(raw_signers, "r", encoding="utf-8").read(),
    "allowed_signers",
    include_no_touch=emit_no_touch,
)
if not valid_signers and boot_signer.strip():
    valid_signers = parse_signers_text(boot_signer, "--bootstrap-signer", include_no_touch=emit_no_touch)
open(clean_signers, "w", encoding="utf-8").writelines(valid_signers)
active_signers = len(valid_signers)

def verify_commit_ssh_sig(commit_ref: str) -> bool:
    if active_signers == 0 or subprocess.run(["git", "-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={clean_signers}", "verify-commit", commit_ref], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        return False
    hdr, sep, body = subprocess.check_output(["git", "cat-file", "commit", commit_ref]).partition(b"\n\n")
    if not sep: return False
    sig_lines, kept, in_sig, sig_headers = [], [], False, 0
    for line in hdr.split(b"\n"):
        if line.startswith(b"gpgsig-"): return False
        if line.startswith(b"gpgsig "): sig_headers += 1; in_sig = True; sig_lines.append(line[7:])
        elif in_sig and line.startswith(b" "): sig_lines.append(line[1:])
        else: in_sig = False; kept.append(line)
    sig_text = b"\n".join(sig_lines) + b"\n"
    if sig_headers != 1 or b"-----BEGIN SSH SIGNATURE-----" not in sig_text: return False
    sig_path, payload_path = os.path.join(work_dir, "head.sig"), os.path.join(work_dir, "head.payload")
    open(sig_path, "wb").write(sig_text); open(payload_path, "wb").write(b"\n".join(kept) + b"\n\n" + body)
    fp = subprocess.run(["ssh-keygen", "-Y", "find-principals", "-f", clean_signers, "-s", sig_path], capture_output=True)
    if fp.returncode != 0: return False
    for princ in fp.stdout.decode("utf-8", errors="replace").splitlines():
        if princ.strip() and subprocess.run(["ssh-keygen", "-Y", "verify", "-f", clean_signers, "-I", princ.strip(), "-n", "git", "-s", sig_path], stdin=open(payload_path, "rb"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
    return False

def load_vecs(ref: str):
    p = subprocess.run(["git", "show", f"{ref}:tests/bypass_corpus.toml"], capture_output=True)
    if p.returncode != 0:
        return None
    try:
        doc = tomllib.loads(p.stdout.decode("utf-8"))
    except Exception as exc:
        die(f"CORPUS_PARSE_ERROR: {ref}:tests/bypass_corpus.toml: {exc}")
    vecs = doc.get("vectors", doc.get("cases"))
    if not set(doc.keys()) <= {"vectors", "cases"} or not isinstance(vecs, list) or any(not isinstance(v, dict) for v in vecs):
        die(f"CORPUS_SCHEMA_ERROR: {ref}:tests/bypass_corpus.toml")
    return vecs

def vec_identity(v: dict) -> str:
    if "kind" in v or "payload" in v:
        k, pl = v.get("kind"), v.get("payload")
        if k not in {"cmd", "read_path", "write_path", "glob", "content", "mcp"} or not isinstance(pl, str) or not pl.strip():
            die(f"CORPUS_SCHEMA_ERROR: invalid kind/payload in {v}")
        return f"kp:{k}:{pl}"
    cmd = v.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        die(f"CORPUS_SCHEMA_ERROR: missing payload/command in {v}")
    return f"cmd:{cmd}"

def evaluate_range(b_ref: str, h_ref: str):
    mb_p = subprocess.run(["git", "merge-base", "--", b_ref, h_ref], capture_output=True, text=True)
    mb = mb_p.stdout.strip() if mb_p.returncode == 0 else ""
    if not mb:
        die(f"NO_MERGE_BASE: {b_ref} and {h_ref}")
    sig_ok = verify_commit_ssh_sig(h_ref)
    for anchor_rel in ("scripts/allowed_hardware_signers", "config/allowed_human_signers"):
        bs_p = subprocess.run(["git", "show", f"{mb}:{anchor_rel}"], capture_output=True, text=True)
        mb_signers = parse_signers_text(bs_p.stdout, f"{mb}:{anchor_rel}", preserve_raw_opts=True) if bs_p.returncode == 0 else []
        hs_p = subprocess.run(["git", "show", f"{h_ref}:{anchor_rel}"], capture_output=True, text=True)
        head_signers = parse_signers_text(hs_p.stdout, f"{h_ref}:{anchor_rel}", preserve_raw_opts=True) if hs_p.returncode == 0 else []
        if head_signers != mb_signers and not (sig_ok or pr_approved):
            die("UNAUTHENTICATED_TRUST_ANCHOR_ENROLLMENT: modifying/enrolling active signers requires a verified SSH signature or approved owner authority")
    parts = subprocess.check_output(["git", "-c", "core.quotePath=false", "diff", "--raw", "-z", "--no-renames", "--end-of-options", mb, h_ref]).split(b"\0")
    tier, policy_mod, file_count, idx = "ring2", False, 0, 0
    while idx + 1 < len(parts) and parts[idx]:
        meta = parts[idx].decode("utf-8", errors="replace").lstrip(":").split()
        path = parts[idx + 1].decode("utf-8", errors="replace")
        idx += 2; file_count += 1
        if len(meta) < 2 or meta[0] not in {"000000", "100644"} or meta[1] not in {"000000", "100644"}:
            tier = "ring0"
        if path in {"crates/agent-guard/src/diagnostics.rs", "tests/bypass_corpus.toml"} or harness_rs_re.fullmatch(path):
            pass
        elif path in {"crates/agent-guard/src/cmd_policy.rs", "crates/agent-guard/src/mcp_policy.rs"}:
            policy_mod = True
        else:
            tier = "ring0"
    auth_ok = (sig_ok or pr_approved) if file_count > 0 else False
    if file_count == 0:
        tier = "ring0"
    base_v, head_v = load_vecs(mb), load_vecs(h_ref)
    if base_v is not None and head_v is None:
        if not auth_ok:
            die("CORPUS_RATCHET_VIOLATION: tests/bypass_corpus.toml deleted")
        return tier, auth_ok, 0
    base_canons = {json.dumps(v, sort_keys=True, separators=(",", ":")) for v in (base_v or [])}
    base_idents = {vec_identity(v) for v in (base_v or [])}
    head_canons, seen_idents, seen_ids, new_deny = set(), set(), set(), 0
    for v in (head_v or []):
        exp, act, vid = v.get("expected_code", 2), v.get("action", "deny"), v.get("id")
        if type(exp) is not int or not isinstance(act, str):
            die(f"CORPUS_SCHEMA_ERROR: invalid expected_code/action in {v}")
        ident = vec_identity(v)
        if (ident in seen_idents or (vid is not None and vid in seen_ids)) and not auth_ok:
            die(f"CORPUS_DUPLICATE_VECTOR_FORBIDDEN: duplicate vector or id '{ident}'")
        seen_idents.add(ident); head_canons.add(json.dumps(v, sort_keys=True, separators=(",", ":")))
        if vid is not None:
            seen_ids.add(vid)
        if ident not in base_idents and exp == 2 and act.lower() == "deny":
            new_deny += 1
    for bc in base_canons:
        if bc not in head_canons and not auth_ok:
            die(f"CORPUS_RATCHET_VIOLATION: vector deleted or weakened: {bc}")
    if policy_mod and not auth_ok and new_deny < 2:
        die(f"CORPUS_RATCHET_VIOLATION: cmd/mcp policy edit requires >= 2 unique new deny vectors (got {new_deny})")
    return tier, auth_ok, new_deny

allow_unsigned_boot = boot_empty and active_signers == 0 and not enforce_hw
if allow_mq and subprocess.run(["git", "rev-parse", "--verify", "-q", f"{head_ref}^2"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
    fp_commits = subprocess.check_output(["git", "rev-list", "--first-parent", f"{base_ref}..{head_ref}"], text=True).splitlines()
    if not fp_commits:
        die("MQ_EMPTY_RANGE: empty merge_group commit range")
    agg_tier, agg_auth, agg_new, agg_elig = "ring2", True, 0, True
    for msha in fp_commits:
        parents = subprocess.check_output(["git", "rev-list", "--parents", "-n", "1", msha], text=True).strip().split()[1:]
        if len(parents) != 2:
            die(f"MQ_NON_TWO_PARENT_COMMIT: {msha} has {len(parents)} parents")
        t, auth_ok, nd = evaluate_range(parents[0], parents[1])
        agg_new += nd
        if t == "ring0":
            agg_tier = "ring0"
            if not auth_ok:
                agg_auth, agg_elig = False, False
                if not allow_unsigned_boot:
                    die(f"RING0_AUTHORITY_REQUIRED: queue entry {parents[1]} missing valid SSH commit signature or approved owner authority")
        else:
            agg_auth = agg_auth and auth_ok
    print(json.dumps({"tier": agg_tier, "hw_signed": agg_auth, "new_corpus_vectors": agg_new, "eligible_for_auto_enqueue": agg_elig}, separators=(",", ":")))
else:
    tier, auth_ok, new_deny = evaluate_range(base_ref, head_ref)
    elig = not (tier == "ring0" and not auth_ok)
    if not elig:
        if not allow_unsigned_boot:
            die("RING0_AUTHORITY_REQUIRED: Ring-0 paths modified without valid SSH commit signature or approved owner authority")
        sys.stderr.write("[verify-pr-authority] BOOTSTRAP_NOTICE: Ring-0 paths modified under explicit empty-signer bootstrap; auto-enqueue disabled\n")
    print(json.dumps({"tier": tier, "hw_signed": auth_ok, "new_corpus_vectors": new_deny, "eligible_for_auto_enqueue": elig}, separators=(",", ":")))
PY
)"

[[ "${JSON_ONLY}" == "true" ]] || echo "[verify-pr-authority] PASS: ${RESULT_JSON}" >&2
printf '%s\n' "${RESULT_JSON}"
