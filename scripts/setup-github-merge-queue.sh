#!/usr/bin/env bash
# Compatibility entrypoint for repository rulesets and the release promoter App manifest.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
owner=susanbdev
repo=dotagent
manifest=false
args=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --owner|--repo|--promoter-app-id|--proof-pr)
            if [[ $# -lt 2 || "$2" == --* ]]; then
                printf 'Missing value for %s\n' "$1" >&2
                exit 2
            fi
            case "$1" in
                --owner) owner="$2" ;;
                --repo) repo="$2" ;;
                *) args+=("$1" "$2") ;;
            esac
            shift 2
            ;;
        --dry-run|--verify|--apply) args+=("$1"); shift ;;
        --print-app-manifest) manifest=true; shift ;;
        --all-fleet|--apply-org)
            printf '%s requires the organization entrypoint: python3 scripts/setup-github-rulesets.py --org ORG\n' "$1" >&2
            exit 2
            ;;
        -h|--help)
            printf '%s\n' 'Compatibility entrypoint for single-repository rulesets.' \
                'Use --print-app-manifest to print the release promoter manifest.' \
                'Native merge-queue provisioning is retired until the required checks support merge_group.'
            exec python3 "${script_dir}/setup-github-rulesets.py" --help
            ;;
        *) printf 'Unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [[ "${manifest}" == true ]]; then
    if [[ ! "${owner}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$ ]]; then
        printf 'Invalid GitHub owner\n' >&2
        exit 2
    fi
    cat <<MANIFEST
{
  "name": "dotagent-promoter",
  "url": "https://github.com/${owner}/dotagent",
  "description": "Promotes verified official release tags for ${owner}/dotagent",
  "public": false,
  "default_permissions": {"contents": "write", "metadata": "read"},
  "default_events": []
}
MANIFEST
    exit 0
fi

# The stock macOS Bash handles empty arrays under nounset via the + expansion.
exec python3 "${script_dir}/setup-github-rulesets.py" --repo "${owner}/${repo}" \
    ${args[@]+"${args[@]}"}
