#!/usr/bin/env python3
"""Offline tests for the ruleset provisioner."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).with_name("setup-github-rulesets.py")
SPEC = importlib.util.spec_from_file_location("setup_github_rulesets", SCRIPT)
rulesets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rulesets
SPEC.loader.exec_module(rulesets)

ORG = "fixture-org"
REPO = f"{ORG}/library"
REPO_ENDPOINT = f"repos/{REPO}"
ORG_ENDPOINT = f"orgs/{ORG}"
RULESET_NAME = "dotagent-baseline-main"


class FakeApi:
    """Model ruleset list, detail, and writes with no subprocess or network."""

    def __init__(self):
        self.requests = []
        self.saved = {REPO_ENDPOINT: {}, ORG_ENDPOINT: {}}
        self.next_id = 71
        self.write_detail_override = {}

    @property
    def writes(self):
        return [request for request in self.requests if request[0] in ("POST", "PUT")]

    def get(self, endpoint):
        endpoint = endpoint.lstrip("/")
        self.requests.append(("GET", endpoint, None))
        if endpoint == REPO_ENDPOINT:
            return {"allow_squash_merge": True, "archived": False}
        for scope, records in self.saved.items():
            suffix = "?includes_parents=false" if scope.startswith("repos/") else ""
            for rule_id, rule in records.items():
                if endpoint == f"{scope}/rulesets/{rule_id}{suffix}":
                    return copy.deepcopy(rule)
        raise AssertionError(f"Unexpected GET {endpoint}")

    def items(self, endpoint, selector=".[]"):
        endpoint = endpoint.lstrip("/")
        self.requests.append(("GET", endpoint, None))
        if endpoint == f"{REPO_ENDPOINT}/rulesets?includes_parents=false&per_page=100":
            scope = REPO_ENDPOINT
        elif endpoint == f"{ORG_ENDPOINT}/rulesets?per_page=100":
            scope = ORG_ENDPOINT
        else:
            raise AssertionError(f"Unexpected paginated GET {endpoint} ({selector})")
        return [
            {key: rule[key] for key in ("id", "name", "source_type", "source", "target", "enforcement")}
            for rule in self.saved[scope].values()
        ]

    def write(self, method, endpoint, payload):
        endpoint = endpoint.lstrip("/")
        self.requests.append((method, endpoint, copy.deepcopy(payload)))
        for scope, records in self.saved.items():
            if method == "POST" and endpoint == f"{scope}/rulesets":
                rule_id = self.next_id
                self.next_id += 1
                break
            if method == "PUT" and endpoint.startswith(f"{scope}/rulesets/"):
                rule_id = int(endpoint.rsplit("/", 1)[1])
                if rule_id not in records:
                    raise AssertionError(f"Unknown managed rule in {endpoint}")
                break
        else:
            raise AssertionError(f"Unexpected {method} {endpoint}")
        org = scope.startswith("orgs/")
        record = {
            **copy.deepcopy(payload),
            "id": rule_id,
            "source_type": "Organization" if org else "Repository",
            "source": scope.split("/", 1)[1],
        }
        records[rule_id] = {**record, **self.write_detail_override}
        return copy.deepcopy(record)


class RulesetTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()

    def invoke(self, *args, env=None):
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(rulesets, "Api", return_value=self.api),
            patch.object(rulesets.subprocess, "run", side_effect=AssertionError("Unexpected subprocess")),
            patch.dict(os.environ, env or {}, clear=True),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = rulesets.main(list(args))
        return result, output.getvalue(), errors.getvalue()

    def run_repo(self, *args, expected=0):
        status, output, errors = self.invoke("--repo", REPO, *args)
        self.assertEqual(status, expected, output + errors)
        return output + errors

    def create_rule(self):
        self.run_repo("--apply")
        [rule_id] = self.api.saved[REPO_ENDPOINT]
        self.api.requests.clear()
        return rule_id, self.api.saved[REPO_ENDPOINT][rule_id]

    def test_dry_run_is_offline_by_default_and_for_explicit_org_scope(self):
        self.assertIn(RULESET_NAME, self.run_repo())
        status, output, errors = self.invoke(
            "--org", ORG, "--include-repo", "library", "--include-repo", "tools", "--dry-run"
        )
        self.assertEqual(status, 0, output + errors)
        for name in (RULESET_NAME, "library", "tools"):
            self.assertIn(name, output)
        self.assertEqual(self.api.requests, [])

    def test_dotagent_dry_run_pins_checks_and_limits_release_bypass_to_creation(self):
        status, output, errors = self.invoke(
            "--repo", f"{ORG}/dotagent", "--promoter-app-id", "351217"
        )
        self.assertEqual(status, 0, output + errors)
        branch, immutable_tags, creation = json.loads(output)["rulesets"]
        self.assertEqual(branch["name"], "dotagent-zero-trust-main")
        checks = next(rule for rule in branch["rules"] if rule["type"] == "required_status_checks")
        contexts = checks["parameters"]["required_status_checks"]
        self.assertIn({"context": "Ring-0 & Copilot Gate", "integration_id": 15368}, contexts)
        self.assertTrue(all(entry["integration_id"] == 15368 for entry in contexts))
        self.assertEqual(branch["bypass_actors"], [])
        self.assertEqual(immutable_tags["bypass_actors"], [])
        self.assertEqual(
            {rule["type"] for rule in immutable_tags["rules"]},
            {"update", "deletion", "non_fast_forward"},
        )
        self.assertEqual(creation["rules"], [{"type": "creation"}])
        self.assertEqual(
            creation["bypass_actors"],
            [{"actor_id": 351217, "actor_type": "Integration", "bypass_mode": "always"}],
        )
        self.assertEqual(self.api.requests, [])

    def test_verify_reports_drift_and_cannot_write(self):
        self.run_repo("--verify", expected=1)
        self.assertEqual(self.api.writes, [])
        _, record = self.create_rule()
        record["enforcement"] = "disabled"
        self.run_repo("--verify", expected=1)
        self.assertEqual(self.api.writes, [])
        self.assertTrue(self.api.requests)

    def test_apply_creates_updates_and_skips_unchanged_rules(self):
        self.run_repo("--apply")
        self.assertEqual(
            [(method, endpoint) for method, endpoint, _ in self.api.writes],
            [("POST", f"{REPO_ENDPOINT}/rulesets")],
        )
        [(rule_id, record)] = self.api.saved[REPO_ENDPOINT].items()
        self.assertEqual(record["name"], RULESET_NAME)
        self.assertIn(
            ("GET", f"{REPO_ENDPOINT}/rulesets/{rule_id}?includes_parents=false", None),
            self.api.requests,
        )

        # GitHub supplies these default parameters even when the client omits them.
        pull_request = next(rule for rule in record["rules"] if rule["type"] == "pull_request")
        pull_request["parameters"]["required_reviewers"] = []
        pull_request["parameters"]["require_extra_approval_for_unattributed_changes"] = False
        self.api.requests.clear()
        self.run_repo("--apply")
        self.assertEqual(self.api.writes, [])
        self.run_repo("--verify")
        self.assertEqual(self.api.writes, [])

        record["enforcement"] = "disabled"
        self.api.requests.clear()
        self.run_repo("--apply")
        self.assertEqual(
            [(method, endpoint) for method, endpoint, _ in self.api.writes],
            [("PUT", f"{REPO_ENDPOINT}/rulesets/{rule_id}")],
        )
        self.assertEqual(self.api.saved[REPO_ENDPOINT][rule_id]["enforcement"], "active")

    def test_org_apply_uses_org_ruleset_and_preserves_repo_scope(self):
        args = ("--org", ORG, "--include-repo", "library", "--include-repo", "tools")
        status, output, errors = self.invoke(*args, "--apply")
        self.assertEqual(status, 0, output + errors)
        self.assertEqual(
            [(method, endpoint) for method, endpoint, _ in self.api.writes],
            [("POST", f"{ORG_ENDPOINT}/rulesets")],
        )
        [record] = self.api.saved[ORG_ENDPOINT].values()
        self.assertEqual(record["name"], RULESET_NAME)
        self.assertEqual(record["source_type"], "Organization")
        self.assertEqual(record["conditions"]["repository_name"]["include"], ["library", "tools"])
        self.assertEqual(record["conditions"]["repository_name"]["exclude"], ["dotagent"])
        pull_request = next(rule for rule in record["rules"] if rule["type"] == "pull_request")
        self.assertEqual(pull_request["parameters"]["required_approving_review_count"], 1)
        self.assertEqual(self.api.saved[REPO_ENDPOINT], {})
        self.api.requests.clear()
        status, output, errors = self.invoke(*args, "--apply")
        self.assertEqual(status, 0, output + errors)
        self.assertEqual(self.api.writes, [])

    def test_apply_rejects_missing_bypass_permissions_or_unsupported_rule(self):
        _, record = self.create_rule()
        original = copy.deepcopy(record)
        for defect in ("missing actors", "unmanaged rule"):
            with self.subTest(defect=defect):
                record.clear()
                record.update(copy.deepcopy(original))
                if defect == "missing actors":
                    del record["bypass_actors"]
                else:
                    record["rules"].append({"type": "required_signatures"})
                self.run_repo("--apply", expected=2)
                self.assertEqual(self.api.writes, [])

    def test_apply_rejects_same_name_ruleset_from_another_scope(self):
        _, record = self.create_rule()
        record["source_type"] = "Organization"
        record["source"] = ORG
        self.run_repo("--apply", expected=2)
        self.assertEqual(self.api.writes, [])

    def test_apply_fails_when_readback_disagrees_with_write_response(self):
        self.api.write_detail_override = {"enforcement": "disabled"}
        self.run_repo("--apply", expected=2)
        self.assertEqual(len(self.api.writes), 1)
        [rule_id] = self.api.saved[REPO_ENDPOINT]
        self.assertEqual(
            self.api.requests[-1],
            ("GET", f"{REPO_ENDPOINT}/rulesets/{rule_id}?includes_parents=false", None),
        )

    def test_proof_requires_current_success_from_expected_github_apps(self):
        full_repo = f"{ORG}/dotagent"
        endpoint = f"repos/{full_repo}"
        head = "a" * 40
        args = rulesets.arguments(["--repo", full_repo, "--verify", "--proof-pr", "42"])
        api = Mock()
        api.get.return_value = {
            "base": {"repo": {"full_name": full_repo}, "ref": "main"},
            "head": {"sha": head},
            "state": "open",
            "draft": False,
        }
        checks = [
            {"name": name, "id": index, "app": {"id": rulesets.ACTIONS_APP_ID},
             "status": "completed", "conclusion": "success"}
            for index, name in enumerate(rulesets.required_checks(), start=1)
            if name != rulesets.REVIEW_GATE
        ]
        trusted_gate = {
            "context": rulesets.REVIEW_GATE,
            "state": "success",
            "creator": {"login": "github-actions[bot]"},
        }
        for first_gate, passes in (
            (trusted_gate, True),
            ({**trusted_gate, "creator": {"login": "some-other-app[bot]"}}, False),
            ({**trusted_gate, "state": "pending"}, False),
        ):
            with self.subTest(first_gate=first_gate), contextlib.redirect_stdout(io.StringIO()):
                api.items.side_effect = [checks, [first_gate, trusted_gate]]
                if passes:
                    rulesets.verify_pr_checks(api, args, endpoint, "main")
                else:
                    with self.assertRaisesRegex(rulesets.RulesetError, "lacks green trusted checks"):
                        rulesets.verify_pr_checks(api, args, endpoint, "main")

    def test_repository_preflight_rejects_an_effective_merge_queue(self):
        full_repo = f"{ORG}/dotagent"
        args = rulesets.arguments(["--repo", full_repo, "--apply"])
        api = Mock()
        api.get.return_value = {"default_branch": "release/main", "allow_squash_merge": True}
        api.items.return_value = [{"type": "merge_queue"}]
        with self.assertRaisesRegex(rulesets.RulesetError, "needs merge_group"):
            rulesets.verify_repo_readiness(api, args)
        api.items.assert_called_once_with(f"repos/{full_repo}/rules/branches/release%2Fmain?per_page=100")

    def test_dotagent_readiness_runs_when_branch_policy_is_already_aligned(self):
        full_repo = f"{ORG}/dotagent"
        args = rulesets.arguments(["--repo", full_repo, "--apply"])
        desired = rulesets.policy(args)
        current = {
            **desired[0], "id": 9, "source": full_repo, "source_type": "Repository",
        }
        api = Mock()
        api.items.return_value = [current]
        api.get.return_value = current
        with patch.object(rulesets, "verify_repo_readiness") as verify, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rulesets.reconcile(api, args, f"repos/{full_repo}/rulesets", desired), 0)
        verify.assert_called_once_with(api, args)
        api.write.assert_not_called()

    def test_operator_markers_stop_apply_before_any_api_calls(self):
        for marker in ("AGENT_GUARD_WORKER_LOCK", "CLAUDECODE", "CODEX_ENV_SANDBOX", "GEMINI_CLI"):
            with self.subTest(marker=marker):
                status, output, errors = self.invoke("--repo", REPO, "--apply", env={marker: "1"})
                self.assertEqual(status, 2, output + errors)
                self.assertIn(marker, errors)
        self.assertEqual(self.api.requests, [])


if __name__ == "__main__":
    unittest.main()
