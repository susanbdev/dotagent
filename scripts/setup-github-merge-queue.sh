#!/usr/bin/env bash
# Idempotent GitHub Organization Actions, Ruleset, Native Merge-Queue & Promoter App Provisioner
# (`susanbdev/dotagent` + fleet). Zero personal owner PATs; merges execute strictly via `merge_queue`.

set -euo pipefail

OWNER="susanbdev"; REPO=""; ALL_FLEET="false"; APPLY_ORG="false"; PROMOTER_APP_ID=""; MODE="dry-run"; PRINT_MANIFEST="false"
DEFAULT_FLEET=(api automation control-center dotagent environments infra jobs mcp policy-hub types vespoli-ui webhooks)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --owner) OWNER="${2:-}"; shift 2 ;;
        --repo) REPO="${2:-}"; shift 2 ;;
        --all-fleet) ALL_FLEET="true"; APPLY_ORG="true"; shift ;;
        --apply-org) APPLY_ORG="true"; shift ;;
        --promoter-app-id) PROMOTER_APP_ID="${2:-}"; shift 2 ;;
        --dry-run) MODE="dry-run"; shift ;;
        --apply) MODE="apply"; shift ;;
        --verify) MODE="verify"; shift ;;
        --print-app-manifest) PRINT_MANIFEST="true"; shift ;;
        *) echo "USAGE_ERROR: unknown flag '$1'" >&2; exit 2 ;;
    esac
done

[[ "${OWNER}" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "USAGE_ERROR: invalid --owner '${OWNER}'" >&2; exit 2; }
[[ -z "${REPO}" || "${REPO}" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "USAGE_ERROR: invalid --repo '${REPO}'" >&2; exit 2; }

if [[ "${PRINT_MANIFEST}" == "true" ]]; then
    cat <<EOF
{
  "name": "dotagent-promoter",
  "url": "https://github.com/${OWNER}/dotagent",
  "description": "Minimal-scope automated Merge Queue enqueuer and release tagger for ${OWNER}/dotagent",
  "public": false,
  "default_permissions": {"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"},
  "default_events": []
}
EOF
    exit 0
fi

[[ -z "${PROMOTER_APP_ID}" || "${PROMOTER_APP_ID}" =~ ^[0-9]+$ ]] || { echo "USAGE_ERROR: --promoter-app-id must be numeric" >&2; exit 2; }
[[ "${ALL_FLEET}" == "true" && -n "${REPO}" ]] && { echo "USAGE_ERROR: pass --repo or --all-fleet, not both" >&2; exit 2; }
[[ "${ALL_FLEET}" == "false" && -z "${REPO}" ]] && REPO="dotagent"

build_payloads_json() {
    python3 - "$1" "${PROMOTER_APP_ID}" <<'PY'
import json, sys
repo_name, app_id_s = sys.argv[1], sys.argv[2]
GH_ACTIONS_APP_ID = 15368

dotagent_checks = [
    {"context": ctx, "integration_id": GH_ACTIONS_APP_ID}
    for ctx in (
        "authority-and-ratchet-gate",
        "verify-kernel-matrix (ubuntu-24.04)",
        "verify-kernel-matrix (ubuntu-24.04-arm)",
        "verify-kernel-matrix (ubuntu-22.04)",
        "verify-kernel-matrix (macos-15)",
        "container-cleanroom-matrix",
        "reproducibility-and-supply-chain",
        "kani-formal-proofs",
        "msrv-1-88-gate",
    )
]
branch_rules = [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {
        "type": "merge_queue",
        "parameters": {
            "merge_method": "SQUASH", "grouping_strategy": "ALLGREEN",
            "min_entries_to_merge": 1, "min_entries_to_merge_wait_minutes": 0,
            "max_entries_to_build": 5, "max_entries_to_merge": 5,
            "check_response_timeout_minutes": 30,
        },
    },
    {
        "type": "pull_request",
        "parameters": {
            "required_approving_review_count": 1, "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": False, "require_last_push_approval": False,
            "required_review_thread_resolution": True,
        },
    },
]
if repo_name == "dotagent":
    branch_rules.append({
        "type": "required_status_checks",
        "parameters": {"strict_required_status_checks_policy": True, "do_not_enforce_on_create": False, "required_status_checks": dotagent_checks},
    })

tag_bypass = [{"actor_id": int(app_id_s), "actor_type": "Integration", "bypass_mode": "always"}] if app_id_s else []
print(json.dumps({
    "org_actions": {"enabled_repositories": "all", "allowed_actions": "selected", "sha_pinning_required": True},
    "org_selected": {"github_owned_allowed": True, "verified_allowed": False, "patterns_allowed": []},
    "org_workflow": {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
    "repo_settings": {"allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False, "allow_auto_merge": True, "delete_branch_on_merge": True},
    "ruleset": {
        "name": "dotagent-zero-trust-merge-queue", "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [], "rules": branch_rules,
    },
    "tag_ruleset": {
        "name": "dotagent-release-tags", "target": "tag", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "bypass_actors": tag_bypass,
        "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}, {"type": "non_fast_forward"}],
    },
}, indent=2))
PY
}

REPOS=()
if [[ "${ALL_FLEET}" == "true" ]]; then
    if [[ "${MODE}" == "dry-run" ]]; then
        REPOS=("${DEFAULT_FLEET[@]}")
    else
        RAW_REPOS="$(gh api --paginate "orgs/${OWNER}/repos?per_page=100" --jq '.[] | select(.archived == false) | .name')"
        mapfile -t REPOS <<< "${RAW_REPOS}"
    fi
else
    REPOS=("${REPO}")
fi
[[ "${#REPOS[@]}" -gt 0 && -n "${REPOS[0]}" ]] || { echo "[setup-merge-queue] FAIL: 0 active repositories resolved" >&2; exit 1; }

if [[ "${MODE}" == "dry-run" ]]; then
    for r in "${REPOS[@]}"; do
        echo "=== [DRY-RUN] ${OWNER}/${r} ==="
        build_payloads_json "${r}"
    done
    exit 0
fi

upsert_ruleset() {
    local repo_name="$1" rs_name="$2" payload_key="$3" bundle="$4" existing_id
    existing_id="$(gh api --paginate "repos/${OWNER}/${repo_name}/rulesets" --jq ".[] | select(.name == \"${rs_name}\") | .id" | head -n1)"
    if [[ -n "${existing_id}" ]]; then
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]]))' "${bundle}" "${payload_key}" \
            | gh api --method PUT "repos/${OWNER}/${repo_name}/rulesets/${existing_id}" --input - >/dev/null
    else
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]]))' "${bundle}" "${payload_key}" \
            | gh api --method POST "repos/${OWNER}/${repo_name}/rulesets" --input - >/dev/null
    fi
}

if [[ "${MODE}" == "apply" ]]; then
    if [[ "${APPLY_ORG}" == "true" ]]; then
        BUNDLE="$(build_payloads_json "${REPOS[0]}")"
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["org_actions"]))' "${BUNDLE}" | gh api --method PUT "orgs/${OWNER}/actions/permissions" --input - >/dev/null
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["org_selected"]))' "${BUNDLE}" | gh api --method PUT "orgs/${OWNER}/actions/permissions/selected-actions" --input - >/dev/null
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["org_workflow"]))' "${BUNDLE}" | gh api --method PUT "orgs/${OWNER}/actions/permissions/workflow" --input - >/dev/null
        echo "[setup-merge-queue] applied Org Actions SHA-pinning & read-only token lockdown on ${OWNER}"
    fi
    for r in "${REPOS[@]}"; do
        RBUNDLE="$(build_payloads_json "${r}")"
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["repo_settings"]))' "${RBUNDLE}" | gh api --method PATCH "repos/${OWNER}/${r}" --input - >/dev/null
        upsert_ruleset "${r}" "dotagent-zero-trust-merge-queue" "ruleset" "${RBUNDLE}"
        upsert_ruleset "${r}" "dotagent-release-tags" "tag_ruleset" "${RBUNDLE}"
        echo "[setup-merge-queue] applied merge-queue & release-tag rulesets on ${OWNER}/${r}"
    done
    exit 0
fi

ORG_PERM="$(gh api "orgs/${OWNER}/actions/permissions")"
ORG_SEL="$(gh api "orgs/${OWNER}/actions/permissions/selected-actions")"
ORG_WF="$(gh api "orgs/${OWNER}/actions/permissions/workflow")"
python3 - "${ORG_PERM}" "${ORG_SEL}" "${ORG_WF}" <<'PY'
import json, sys
p, s, w = json.loads(sys.argv[1]), json.loads(sys.argv[2]), json.loads(sys.argv[3])
assert p.get("allowed_actions") == "selected" and p.get("sha_pinning_required") is True
assert s.get("github_owned_allowed") is True and s.get("verified_allowed") is False
assert w.get("default_workflow_permissions") == "read" and w.get("can_approve_pull_request_reviews") is False
PY

for r in "${REPOS[@]}"; do
    REPO_JSON="$(gh api "repos/${OWNER}/${r}")"
    RS_ID="$(gh api --paginate "repos/${OWNER}/${r}/rulesets" --jq '.[] | select(.name == "dotagent-zero-trust-merge-queue") | .id' | head -n1)"
    TAG_RS_ID="$(gh api --paginate "repos/${OWNER}/${r}/rulesets" --jq '.[] | select(.name == "dotagent-release-tags") | .id' | head -n1)"
    [[ -n "${RS_ID}" && -n "${TAG_RS_ID}" ]] || { echo "[setup-merge-queue] FAIL: missing rulesets on ${OWNER}/${r}" >&2; exit 1; }
    RS_JSON="$(gh api "repos/${OWNER}/${r}/rulesets/${RS_ID}")"
    python3 - "${r}" "${REPO_JSON}" "${RS_JSON}" <<'PY'
import json, sys
rname, repo, rs = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
assert repo.get("allow_squash_merge") is True and repo.get("allow_merge_commit") is False and repo.get("allow_rebase_merge") is False
assert repo.get("allow_auto_merge") is True and repo.get("delete_branch_on_merge") is True
assert rs.get("enforcement") == "active" and rs.get("bypass_actors", []) == []
by_type = {rule["type"]: rule for rule in rs.get("rules", [])}
for req in ("deletion", "non_fast_forward", "required_linear_history", "merge_queue", "pull_request"):
    assert req in by_type, f"missing rule {req}"
if rname == "dotagent":
    checks = by_type["required_status_checks"]["parameters"]["required_status_checks"]
    assert len(checks) == 9 and all(c.get("integration_id") == 15368 for c in checks)
PY
    echo "[setup-merge-queue] VERIFIED ${OWNER}/${r} (branch_ruleset=${RS_ID}, tag_ruleset=${TAG_RS_ID})"
done
