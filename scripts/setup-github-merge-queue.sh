#!/usr/bin/env bash
# Idempotent GitHub Organization Actions, Ruleset, Native Merge-Queue & Promoter App Provisioner
# (`susanbdev/dotagent` + fleet). Zero personal owner PATs; merges execute strictly via `merge_queue`.

set -euo pipefail

OWNER="susanbdev"
REPO=""
ALL_FLEET="false"
PROMOTER_APP_ID=""
MODE="dry-run"
PRINT_MANIFEST="false"

DEFAULT_FLEET=(
    api automation control-center dotagent environments infra
    jobs mcp policy-hub types vespoli-ui webhooks
)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --owner) OWNER="${2:-}"; shift 2 ;;
        --repo) REPO="${2:-}"; shift 2 ;;
        --all-fleet) ALL_FLEET="true"; shift ;;
        --promoter-app-id) PROMOTER_APP_ID="${2:-}"; shift 2 ;;
        --dry-run) MODE="dry-run"; shift ;;
        --apply) MODE="apply"; shift ;;
        --verify) MODE="verify"; shift ;;
        --print-app-manifest) PRINT_MANIFEST="true"; shift ;;
        *)
            echo "USAGE_ERROR: unknown flag '$1'" >&2
            echo "Usage: $0 [--owner <org>] [--repo <name> | --all-fleet] [--promoter-app-id <id>] [--dry-run | --apply | --verify | --print-app-manifest]" >&2
            exit 2
            ;;
    esac
done

if [[ "${PRINT_MANIFEST}" == "true" ]]; then
    cat <<EOF
{
  "name": "dotagent-promoter",
  "url": "https://github.com/${OWNER}/dotagent",
  "description": "Minimal-scope automated Merge Queue enqueuer and release tagger for ${OWNER}/dotagent",
  "public": false,
  "default_permissions": {
    "contents": "write",
    "pull_requests": "write",
    "checks": "read",
    "metadata": "read"
  },
  "default_events": []
}
EOF
    exit 0
fi

if [[ -n "${PROMOTER_APP_ID}" && ! "${PROMOTER_APP_ID}" =~ ^[0-9]+$ ]]; then
    echo "USAGE_ERROR: --promoter-app-id must be a numeric GitHub App ID" >&2
    exit 2
fi

if [[ "${ALL_FLEET}" == "true" && -n "${REPO}" ]]; then
    echo "USAGE_ERROR: pass either --repo <name> or --all-fleet, not both" >&2
    exit 2
fi
[[ "${ALL_FLEET}" == "false" && -z "${REPO}" ]] && REPO="dotagent"

build_payloads_json() {
    local repo_name="$1"
    python3 - "${repo_name}" "${PROMOTER_APP_ID}" <<'PY'
import json, sys

repo_name, app_id_s = sys.argv[1], sys.argv[2]

org_actions = {"enabled_repositories": "all", "allowed_actions": "selected", "sha_pinning_required": True}
org_selected = {"github_owned_allowed": True, "verified_allowed": False, "patterns_allowed": []}
org_workflow = {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
repo_settings = {
    "allow_squash_merge": True,
    "allow_merge_commit": False,
    "allow_rebase_merge": False,
    "allow_auto_merge": True,
    "delete_branch_on_merge": True,
}

dotagent_checks = [
    {"context": "authority-and-ratchet-gate"},
    {"context": "verify-kernel-matrix (ubuntu-24.04)"},
    {"context": "verify-kernel-matrix (ubuntu-24.04-arm)"},
    {"context": "verify-kernel-matrix (ubuntu-22.04)"},
    {"context": "verify-kernel-matrix (macos-15)"},
    {"context": "container-cleanroom-matrix"},
    {"context": "reproducibility-and-supply-chain"},
    {"context": "kani-formal-proofs"},
    {"context": "msrv-1-88-gate"},
]

bypass_actors = []
if app_id_s:
    bypass_actors.append({
        "actor_id": int(app_id_s),
        "actor_type": "Integration",
        "bypass_mode": "pull_request",
    })

rules = [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {
        "type": "merge_queue",
        "parameters": {
            "merge_method": "SQUASH",
            "grouping_strategy": "ALLGREEN",
            "min_entries_to_merge": 1,
            "min_entries_to_merge_wait_minutes": 0,
            "max_entries_to_build": 5,
            "max_entries_to_merge": 5,
            "check_response_timeout_minutes": 30,
        },
    },
    {
        "type": "pull_request",
        "parameters": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_review_thread_resolution": True,
        },
    },
]
if repo_name == "dotagent":
    rules.append({
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": True,
            "do_not_enforce_on_create": False,
            "required_status_checks": dotagent_checks,
        },
    })

ruleset = {
    "name": "dotagent-zero-trust-merge-queue",
    "target": "branch",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
    "bypass_actors": bypass_actors,
    "rules": rules,
}

print(json.dumps({
    "org_actions": org_actions,
    "org_selected": org_selected,
    "org_workflow": org_workflow,
    "repo_settings": repo_settings,
    "ruleset": ruleset,
}, indent=2))
PY
}

REPOS=()
if [[ "${ALL_FLEET}" == "true" ]]; then
    if [[ "${MODE}" == "dry-run" ]]; then
        REPOS=("${DEFAULT_FLEET[@]}")
    else
        mapfile -t REPOS < <(gh api "orgs/${OWNER}/repos?per_page=100" --jq '.[].name')
    fi
else
    REPOS=("${REPO}")
fi

if [[ "${MODE}" == "dry-run" ]]; then
    for r in "${REPOS[@]}"; do
        echo "=== [DRY-RUN] ${OWNER}/${r} ==="
        build_payloads_json "${r}"
    done
    exit 0
fi

if [[ "${MODE}" == "apply" ]]; then
    BUNDLE="$(build_payloads_json "${REPOS[0]}")"
    python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["org_actions"]))' "${BUNDLE}" \
        | gh api --method PUT "orgs/${OWNER}/actions/permissions" --input - >/dev/null
    python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["org_selected"]))' "${BUNDLE}" \
        | gh api --method PUT "orgs/${OWNER}/actions/permissions/selected-actions" --input - >/dev/null
    python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["org_workflow"]))' "${BUNDLE}" \
        | gh api --method PUT "orgs/${OWNER}/actions/permissions/workflow" --input - >/dev/null
    echo "[setup-merge-queue] applied Org Actions SHA-pinning & read-only token lockdown on ${OWNER}"

    for r in "${REPOS[@]}"; do
        RBUNDLE="$(build_payloads_json "${r}")"
        python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["repo_settings"]))' "${RBUNDLE}" \
            | gh api --method PATCH "repos/${OWNER}/${r}" --input - >/dev/null
        EXISTING_ID="$(gh api "repos/${OWNER}/${r}/rulesets" --jq '.[] | select(.name == "dotagent-zero-trust-merge-queue") | .id' | head -n1 || true)"
        if [[ -n "${EXISTING_ID}" ]]; then
            python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["ruleset"]))' "${RBUNDLE}" \
                | gh api --method PUT "repos/${OWNER}/${r}/rulesets/${EXISTING_ID}" --input - >/dev/null
        else
            python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["ruleset"]))' "${RBUNDLE}" \
                | gh api --method POST "repos/${OWNER}/${r}/rulesets" --input - >/dev/null
        fi
        echo "[setup-merge-queue] applied squash-only auto-merge & ruleset dotagent-zero-trust-merge-queue on ${OWNER}/${r}"
    done
    exit 0
fi

# --verify mode
ORG_PERM="$(gh api "orgs/${OWNER}/actions/permissions")"
ORG_WF="$(gh api "orgs/${OWNER}/actions/permissions/workflow")"
python3 - "${ORG_PERM}" "${ORG_WF}" <<'PY'
import json, sys
p, w = json.loads(sys.argv[1]), json.loads(sys.argv[2])
assert p.get("allowed_actions") == "selected", f"expected allowed_actions=selected, got {p}"
assert p.get("sha_pinning_required") is True, f"expected sha_pinning_required=True, got {p}"
assert w.get("default_workflow_permissions") == "read", f"expected default_workflow_permissions=read, got {w}"
PY

for r in "${REPOS[@]}"; do
    REPO_JSON="$(gh api "repos/${OWNER}/${r}")"
    RS_ID="$(gh api "repos/${OWNER}/${r}/rulesets" --jq '.[] | select(.name == "dotagent-zero-trust-merge-queue") | .id' | head -n1)"
    [[ -n "${RS_ID}" ]] || { echo "[setup-merge-queue] FAIL: missing ruleset on ${OWNER}/${r}" >&2; exit 1; }
    RS_JSON="$(gh api "repos/${OWNER}/${r}/rulesets/${RS_ID}")"
    python3 - "${REPO_JSON}" "${RS_JSON}" <<'PY'
import json, sys
repo, rs = json.loads(sys.argv[1]), json.loads(sys.argv[2])
assert repo.get("allow_squash_merge") is True and repo.get("allow_merge_commit") is False and repo.get("allow_rebase_merge") is False
assert repo.get("allow_auto_merge") is True and repo.get("delete_branch_on_merge") is True
assert rs.get("enforcement") == "active"
rule_types = {r["type"] for r in rs.get("rules", [])}
for req in ("deletion", "non_fast_forward", "required_linear_history", "merge_queue", "pull_request"):
    assert req in rule_types, f"missing rule {req} in {rule_types}"
PY
    echo "[setup-merge-queue] VERIFIED ${OWNER}/${r} (ruleset id=${RS_ID})"
done
