# GitHub rulesets

Use `scripts/setup-github-rulesets.py` to review and reconcile rulesets in one GitHub repository or organization. The script uses Python 3 and the authenticated GitHub CLI for live operations. Use an account or installation with permission to read rulesets for verification and to create or update rulesets in the selected scope for application. [GitHub ruleset API](https://docs.github.com/en/rest/repos/rules)

## Choose the scope

Pass `--repo OWNER/REPO` for a repository-owned ruleset, or `--org ORG` for an organization-owned ruleset. An organization scope covers all repositories except `dotagent` by default. Repeat `--include-repo NAME` to use a specific list of repository names in that organization. Configure Dotagent with its repository scope.

```sh
python3 scripts/setup-github-rulesets.py --repo susanbdev/dotagent
python3 scripts/setup-github-rulesets.py --org susanbdev
python3 scripts/setup-github-rulesets.py --org susanbdev --include-repo types --include-repo policy-hub
```

The common default-branch rules require squash pull requests, resolution of review threads, and one approval. Dotagent's repository policy in `OWNER/dotagent` requires its nine checks and Copilot review, with zero required human approvals in the managed rule. GitHub combines rules from all applicable rulesets, so the organization approval policy excludes Dotagent.

## Review, verify, and apply

`--dry-run` is the default. It prints the planned JSON offline. Check the owner, names, target refs, repository selection, and bypass actors before using a live mode.

```sh
python3 scripts/setup-github-rulesets.py --repo susanbdev/dotagent --verify
python3 scripts/setup-github-rulesets.py --repo susanbdev/dotagent --apply
python3 scripts/setup-github-rulesets.py --repo susanbdev/dotagent --verify
```

`--verify` reads GitHub and reports drift. It exits with status 1 for a missing or different ruleset and status 2 for an API or prerequisite error. `--apply` creates or updates the exact managed names owned by the selected repository or organization. GitHub may require ruleset write access to return bypass actor details during verification. An integration that returns `403` needs access to the applicable repository or organization ruleset endpoints. Enable squash merging in the covered repositories before applying. GitHub permissions authorize these operations and ordinary guarded merges. [Organization ruleset API](https://docs.github.com/en/rest/orgs/rules)

For Dotagent, `--proof-pr N` selects an open non-draft or merged pull request targeting that repository's default branch. Use a PR whose exact head has passed all nine required checks. The default for `--apply` selects the newest merged PR into the default branch and stops if its exact evidence is missing or unsuccessful. Run `--verify --proof-pr N` to check that evidence before applying. If Copilot has returned a clean review and the status is still pending, rerun the trusted **Server-Side Ring-0 & Copilot Gate** workflow for that exact PR revision. [Review gate](../.github/workflows/copilot-gate.yml)

## Dotagent required checks

The repository ruleset pins these pull-request contexts to GitHub Actions. The ruleset script and fleet provenance verifier use the same [check catalog](../config/github-required-checks.txt).

- `Security Kernel & Harness (ubuntu-latest)`
- `Security Kernel & Harness (macos-latest)`
- `Supply-Chain Advisory & License Gate (cargo-deny)`
- `Container Cleanroom Matrix`
- `Dual-Directory Reproducibility Proof`
- `Kani Bounded Model Checking Proofs`
- `MSRV 1.88.0 Compatibility Gate`
- `Ring-0 Constitutional Ratchet`
- `Ring-0 & Copilot Gate`

The first seven also run on pushes to `main`. The Ring-0 job evaluates PRs and branch pushes outside `main`. The server-side gate publishes the `Ring-0 & Copilot Gate` commit status on default-branch pull requests. Native merge queue requires `merge_group` coverage for required checks. Use the squash PR flow with the current workflows. [Guardrail CI](../.github/workflows/ci.yml) · [Review gate](../.github/workflows/copilot-gate.yml) · [GitHub merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)

The compatibility script `scripts/setup-github-merge-queue.sh` keeps `--print-app-manifest` for offline GitHub App setup and delegates supported single-repository commands. Use the Python entrypoint with `--org` in place of the retired organization flags.

## Protect Dotagent release tags

For `--repo OWNER/dotagent`, add `--promoter-app-id ID` to include separate rulesets for creation and immutability of `refs/tags/v*`. The create rule grants the named release promoter App an exception. The immutable-tag rule has no bypass actors and blocks updates and deletion of official tags. Operators stage the original annotated tag object under `refs/tags/release-request/v*` for validation and promotion.

Review the release configuration before applying the optional tag rules.

1. Install the release promoter GitHub App specifically on the selected Dotagent repository with Contents write access. Record the numeric GitHub App ID.
2. Configure the `release` environment with required reviewers. If you restrict deployment refs, allow `main` for promotion and `v*` tags for publication jobs.
3. Set `PROMOTER_APP_ID` to the same App ID and configure `PROMOTER_APP_PRIVATE_KEY` as an Actions secret. The script supports the environment or repository settings. Verification checks secret enrollment by name.

Use the same App ID in dry-run, verify, and apply so each command selects the same tag policy. The live preflight checks release reviewers and App configuration before applying the tag rules. Follow the separate signing instructions to enroll a public OpenSSH FIDO2 key and produce a signed release request. [Release signing](RELEASE_SIGNING.md) · [Release workflow](../.github/workflows/release.yml)
