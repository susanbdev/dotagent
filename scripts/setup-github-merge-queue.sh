#!/usr/bin/env bash
# Compatibility entrypoint for repository rulesets and the release promoter App manifest.
set -euo pipefail

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
        --print-app-manifest) manifest=true; args+=("$1"); shift ;;
        --all-fleet|--apply-org)
            printf '%s requires the organization entrypoint: dotagent github-rulesets --org ORG\n' "$1" >&2
            exit 2
            ;;
        -h|--help)
            exec dotagent github-rulesets --help
            ;;
        *) printf 'Unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
done

# The stock macOS Bash handles empty arrays under nounset via the + expansion.
if [[ "${manifest}" == true ]]; then
    exec dotagent github-rulesets --org "${owner}" ${args[@]+"${args[@]}"}
fi
exec dotagent github-rulesets --repo "${owner}/${repo}" \
    ${args[@]+"${args[@]}"}
