#!/usr/bin/env python3
"""Plan, verify, and reconcile the Dotagent-managed GitHub rulesets."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote, urlencode


ACTIONS_APP_ID = 15368
REVIEW_GATE = "Ring-0 & Copilot Gate"
APP_VARIABLE = "PROMOTER_APP_ID"
APP_SECRET = "PROMOTER_APP_PRIVATE_KEY"
CHECK_CATALOG = Path(__file__).resolve().parents[1] / "config/github-required-checks.txt"


class RulesetError(Exception):
    pass


class ApiError(RulesetError):
    def __init__(self, method, endpoint, stderr):
        self.not_found = "HTTP 404" in stderr
        super().__init__(f"{method} {endpoint}: {stderr.strip()}")


class Api:
    def call(self, method, endpoint, options=(), payload=None):
        command = [
            "gh", "api", "--hostname", "github.com",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            "--method", method, endpoint, *options,
        ]
        if payload is not None:
            command += ["--input", "-"]
        result = subprocess.run(
            command, input=None if payload is None else json.dumps(payload),
            capture_output=True, text=True, check=False, timeout=45,
        )
        if result.returncode:
            raise ApiError(method, endpoint, result.stderr)
        return result.stdout

    def get(self, endpoint):
        return json.loads(self.call("GET", endpoint))

    def items(self, endpoint, selector=".[]"):
        output = self.call("GET", endpoint, ("--paginate", "--jq", f"{selector} | @json"))
        return [json.loads(line) for line in output.splitlines()]

    def write(self, method, endpoint, payload):
        return json.loads(self.call(method, endpoint, payload=payload))


def identifier(value):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}", value):
        raise argparse.ArgumentTypeError(f"invalid GitHub name {value!r}")
    return value


def repo_name(value):
    parts = value.split("/")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("use OWNER/REPO")
    return "/".join(identifier(part) for part in parts)


def positive(value):
    if not re.fullmatch(r"[1-9][0-9]{0,15}", value):
        raise argparse.ArgumentTypeError("expected a positive numeric ID")
    return int(value)


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--repo", type=repo_name, metavar="OWNER/REPO")
    scope.add_argument("--org", type=identifier, metavar="ORG")
    parser.add_argument("--include-repo", type=identifier, action="append", default=[], metavar="NAME",
                        help="exact repository name to cover in the organization, repeatable")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", dest="mode", action="store_const", const="dry-run",
                      help="print offline desired payloads (default)")
    mode.add_argument("--verify", dest="mode", action="store_const", const="verify",
                      help="compare managed rulesets using read-only API calls")
    mode.add_argument("--apply", dest="mode", action="store_const", const="apply",
                      help="create or update managed rulesets")
    parser.set_defaults(mode="dry-run")
    parser.add_argument("--proof-pr", type=positive, metavar="NUMBER",
                        help="Dotagent PR with every expected check green on its exact head")
    parser.add_argument("--promoter-app-id", type=positive, metavar="ID",
                        help="require the release promoter App to create official Dotagent tags")
    args = parser.parse_args(argv)
    args.dotagent = bool(args.repo and args.repo.rsplit("/", 1)[1].lower() == "dotagent")
    if args.include_repo and not args.org:
        parser.error("--include-repo requires --org")
    if (args.proof_pr or args.promoter_app_id) and not args.dotagent:
        parser.error("--proof-pr and --promoter-app-id require a repository named dotagent")
    return args


def required_checks():
    names = CHECK_CATALOG.read_text(encoding="utf-8").splitlines()
    if (not names or REVIEW_GATE not in names or len(set(names)) != len(names)
            or any(not name or name != name.strip() for name in names)):
        raise RulesetError(f"invalid status check catalog {CHECK_CATALOG.name}")
    return names


def ruleset(name, target, refs, rules, bypass=()):
    return {
        "name": name,
        "target": target,
        "enforcement": "active",
        "bypass_actors": list(bypass),
        "conditions": {"ref_name": {"include": refs, "exclude": []}},
        "rules": rules,
    }


def policy(args):
    branch_rules = [
        {"type": rule} for rule in ("deletion", "non_fast_forward", "required_linear_history")
    ]
    branch_rules.append({"type": "pull_request", "parameters": {
        "allowed_merge_methods": ["squash"],
        "dismiss_stale_reviews_on_push": True,
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": True,
    }})
    branch_name = "dotagent-baseline-main"
    if args.dotagent:
        branch_name = "dotagent-zero-trust-main"
        branch_rules.extend([
            {"type": "copilot_code_review", "parameters": {
                "review_draft_pull_requests": False,
                "review_on_push": True,
            }},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {"context": name, "integration_id": ACTIONS_APP_ID} for name in required_checks()
                ],
            }},
        ])
    branch = ruleset(branch_name, "branch", ["~DEFAULT_BRANCH"], branch_rules)
    if args.org:
        names = sorted(set(args.include_repo)) or ["~ALL"]
        branch["conditions"]["repository_name"] = {"include": names, "exclude": [], "protected": False}
    desired = [branch]
    if args.promoter_app_id:
        desired.extend([
            ruleset("dotagent-release-tag-immutability", "tag", ["refs/tags/v*"], [
                {"type": rule} for rule in ("update", "deletion", "non_fast_forward")
            ]),
            ruleset("dotagent-release-tag-creation", "tag", ["refs/tags/v*"], [
                {"type": "creation"},
            ], [{"actor_id": args.promoter_app_id, "actor_type": "Integration", "bypass_mode": "always"}]),
        ])
    return desired


def canonical(value):
    """Sort set-like ruleset arrays and remove only known API defaults."""
    if isinstance(value, dict):
        return {
            key: canonical(item) for key, item in value.items()
            if not (key in ("parameters", "required_reviewers") and not item)
        }
    if isinstance(value, list):
        return sorted((canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def policy_fields(ruleset_doc):
    if not isinstance(ruleset_doc.get("bypass_actors"), list):
        raise RulesetError(f"{ruleset_doc['name']}: GitHub omitted bypass actors; use ruleset-write access")
    result = {key: ruleset_doc.get(key) for key in (
        "name", "target", "enforcement", "conditions", "bypass_actors", "rules",
    )}
    for condition in ("ref_name", "repository_name"):
        config = (result["conditions"] or {}).get(condition)
        if isinstance(config, dict):
            config.setdefault("exclude", [])
            if condition == "repository_name":
                config.setdefault("protected", False)
    return canonical(result)


def validate_identity(metadata, args):
    source_type = "Repository" if args.repo else "Organization"
    source = args.repo or args.org
    if metadata.get("source_type") != source_type or metadata.get("source", "").lower() != source.lower():
        raise RulesetError(f"{metadata['name']}: ruleset is outside the selected {source_type.lower()}")


def drift(existing, desired):
    actual = policy_fields(existing)
    wanted = policy_fields(desired)
    return [key for key in wanted if wanted[key] != actual[key]]


def apply_safety(existing, desired):
    known = [rule["type"] for rule in desired["rules"]]
    actual = [rule["type"] for rule in existing["rules"]]
    if existing["target"] != desired["target"] or len(actual) != len(set(actual)):
        raise RulesetError(f"{desired['name']}: existing ruleset has a different target or duplicate rules")
    if extra := sorted(set(actual) - set(known)):
        raise RulesetError(f"{desired['name']}: existing ruleset contains unmanaged rules: {', '.join(extra)}")


def verify_pr_checks(api, args, repo, default):
    number = args.proof_pr
    if not number:
        query = urlencode({"state": "closed", "base": default, "sort": "updated", "direction": "desc", "per_page": 100})
        recent = api.get(f"{repo}/pulls?{query}")
        latest = max((pr for pr in recent if pr.get("merged_at")), key=lambda pr: pr["merged_at"], default=None)
        if not latest:
            raise RulesetError("no recent merged default-branch PR; supply --proof-pr NUMBER")
        number = latest["number"]
    pr = api.get(f"{repo}/pulls/{number}")
    head = pr["head"]["sha"]
    if (pr["base"]["repo"]["full_name"].lower() != args.repo.lower() or pr["base"]["ref"] != default
            or pr.get("draft") or (pr["state"] != "open" and not pr.get("merged"))
            or not re.fullmatch(r"[0-9a-f]{40}", head)):
        raise RulesetError(f"PR #{number} must be open and ready or merged, targeting {args.repo}:{default}")
    latest_runs = {}
    for run in api.items(f"{repo}/commits/{head}/check-runs?filter=all&per_page=100", ".check_runs[]"):
        name = run["name"]
        if (run.get("app") or {}).get("id") == ACTIONS_APP_ID and run["id"] > latest_runs.get(name, {}).get("id", 0):
            latest_runs[name] = run
    latest_gate = next(
        (status for status in api.items(f"{repo}/commits/{head}/statuses?per_page=100")
         if status.get("context") == REVIEW_GATE),
        {},
    )
    missing = [name for name in required_checks() if name != REVIEW_GATE and not (
        latest_runs.get(name, {}).get("status") == "completed"
        and latest_runs[name].get("conclusion") == "success"
    )]
    if latest_gate.get("state") != "success" or (latest_gate.get("creator") or {}).get("login") != "github-actions[bot]":
        missing.append(REVIEW_GATE)
    if missing:
        raise RulesetError(f"PR #{number} ({head}) lacks green trusted checks: {', '.join(missing)}")
    print(f"Verified PR #{number} checks on {head}")


def verify_repo_readiness(api, args):
    repo = f"repos/{args.repo}"
    details = api.get(repo)
    if details.get("archived") or details.get("allow_squash_merge") is not True:
        raise RulesetError(f"{args.repo}: enable squash merges on an active repository before applying")
    if args.dotagent:
        default = details["default_branch"]
        rules = api.get(f"{repo}/rules/branches/{quote(default, safe='')}")
        if any(rule.get("type") == "merge_queue" for rule in rules):
            raise RulesetError(f"{args.repo}: the effective native merge queue needs merge_group checks")
        verify_pr_checks(api, args, repo, default)


def release_setting(api, repo, group, name):
    try:
        return api.get(f"{repo}/environments/release/{group}/{name}")
    except ApiError as error:
        if not error.not_found:
            raise
    return api.get(f"{repo}/actions/{group}/{name}")


def verify_release_settings(api, repo, app_id):
    environment = api.get(f"{repo}/environments/release")
    if not any(rule.get("type") == "required_reviewers" and rule.get("reviewers")
               for rule in environment["protection_rules"]):
        raise RulesetError("release environment requires at least one configured reviewer")
    variable = release_setting(api, repo, "variables", APP_VARIABLE)
    if variable.get("value") != str(app_id):
        raise RulesetError(f"{APP_VARIABLE} does not match --promoter-app-id")
    metadata = release_setting(api, repo, "secrets", APP_SECRET)
    if metadata.get("name") != APP_SECRET:
        raise RulesetError(f"missing {APP_SECRET} metadata")


def reconcile(api, args, endpoint, desired):
    query = "?includes_parents=false&per_page=100" if args.repo else "?per_page=100"
    detail_query = "?includes_parents=false" if args.repo else ""
    listed = api.items(endpoint + query)
    changes = []
    for wanted in desired:
        name = wanted["name"]
        matches = [item for item in listed if item.get("name") == name]
        if len(matches) > 1:
            raise RulesetError(f"{name}: multiple managed rulesets found")
        if not matches:
            print(f"{name}: missing")
            changes.append((endpoint, None, wanted))
            continue
        metadata = matches[0]
        validate_identity(metadata, args)
        detail_endpoint = f"{endpoint}/{int(metadata['id'])}"
        current = api.get(detail_endpoint + detail_query)
        validate_identity(current, args)
        if current.get("id") != metadata["id"] or current.get("name") != name:
            raise RulesetError(f"{name}: ruleset identity changed during read")
        fields = drift(current, wanted)
        if fields:
            print(f"{name}: drift in {', '.join(fields)}")
            if args.mode == "apply":
                apply_safety(current, wanted)
            changes.append((detail_endpoint, current, wanted))
        else:
            print(f"{name}: in sync")
    if args.mode == "verify":
        if args.promoter_app_id:
            verify_release_settings(api, f"repos/{args.repo}", args.promoter_app_id)
        if args.proof_pr:
            verify_repo_readiness(api, args)
        return int(bool(changes))
    if args.promoter_app_id:
        verify_release_settings(api, f"repos/{args.repo}", args.promoter_app_id)
    if args.repo and any(wanted["target"] == "branch" for _, _, wanted in changes):
        verify_repo_readiness(api, args)
    for path, previous, wanted in changes:
        if previous:
            snapshot = api.get(path + detail_query)
            validate_identity(snapshot, args)
            if drift(snapshot, previous):
                raise RulesetError(f"{wanted['name']}: ruleset changed during apply; run again")
        written = api.write("PUT" if previous else "POST", path, wanted)
        updated = api.get(f"{endpoint}/{int(written['id'])}{detail_query}")
        validate_identity(updated, args)
        if fields := drift(updated, wanted):
            raise RulesetError(f"{wanted['name']}: GitHub returned drift after write: {', '.join(fields)}")
        print(f"{wanted['name']}: {'updated' if previous else 'created'} (ID {written['id']})")
    return 0


def main(argv=None):
    args = arguments(argv)
    try:
        desired = policy(args)
        endpoint = f"repos/{args.repo}/rulesets" if args.repo else f"orgs/{args.org}/rulesets"
        if args.mode == "dry-run":
            print(json.dumps({"endpoint": endpoint, "rulesets": desired}, indent=2))
            return 0
        if args.mode == "apply":
            for marker in ("AGENT_GUARD_IN_SANDBOX", "AGENT_GUARD_WORKER_LOCK", "AGENT_GUARD_ROLE"):
                if os.environ.get(marker, "").lower() not in ("", "0", "false"):
                    raise RulesetError(f"--apply requires an operator shell ({marker} is set)")
        return reconcile(Api(), args, endpoint, desired)
    except (RulesetError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"rulesets: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
