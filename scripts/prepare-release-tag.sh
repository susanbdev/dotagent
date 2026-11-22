#!/usr/bin/env bash
# Prepare a local FIDO2 SSH-signed release tag and print the staging command.
set -euo pipefail

die() {
    printf '[prepare-release-tag] %s\n' "$1" >&2
    exit 1
}

[[ $# -ge 1 && $# -le 2 ]] || die 'usage: prepare-release-tag.sh vX.Y.Z [commit]'
tag="$1"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die 'expected an explicit version tag such as v2.1.0'
base_ref='refs/remotes/origin/main'
ref="refs/tags/${tag}"
stage_ref="refs/tags/release-request/${tag}"
dotagent_bin="${DOTAGENT_BIN:-dotagent}"

command -v "${dotagent_bin}" >/dev/null || die 'install the current dotagent verifier or set DOTAGENT_BIN'
command -v python3 >/dev/null || die 'Python 3.11 or later is required to read Cargo.toml'
repo="$(git rev-parse --show-toplevel)" || die 'run this command inside the dotagent checkout'

# Work from local objects, including in a partial clone. Refresh origin/main separately when needed.
export GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_ALLOW_PROTOCOL='' GIT_TERMINAL_PROMPT=0
base="$(git -C "${repo}" rev-parse --verify "${base_ref}^{commit}")" || die 'local origin/main is unavailable'
commit="$(git -C "${repo}" rev-parse --verify --end-of-options "${2:-${base}}^{commit}")" || die 'release target is not a local commit'
git -C "${repo}" merge-base --is-ancestor "${commit}" "${base}" || die 'release target must be on local origin/main'
version="$(git -C "${repo}" show "${commit}:Cargo.toml" | python3 -c '
import sys
import tomllib

print(tomllib.load(sys.stdin.buffer)["workspace"]["package"]["version"])
')" || die 'cannot read the target commit workspace version'
[[ "${tag}" == "v${version}" ]] || die "tag must match target commit workspace version v${version}"

created_oid=''
cleanup() {
    if [[ -n "${created_oid}" ]]; then
        git -C "${repo}" update-ref -d "${ref}" "${created_oid}" || true
    fi
}
trap cleanup EXIT

if ! git -C "${repo}" show-ref --verify --quiet "${ref}"; then
    [[ "$(git -C "${repo}" config --get gpg.format || true)" == ssh ]] \
        || die 'configure Git for SSH signing with an enrolled FIDO2 sk-* key'
    git -C "${repo}" tag -s -m "dotagent ${tag}" "${tag}" "${commit}" >&2 \
        || die 'hardware-backed SSH tag signing failed'
    created_oid="$(git -C "${repo}" rev-parse --verify "${ref}^{tag}")" \
        || die 'cannot resolve the newly signed tag object'
fi

tag_oid="$(git -C "${repo}" rev-parse --verify "${ref}^{tag}")" || die 'existing release tag must be annotated'
tag_commit="$(git -C "${repo}" rev-parse --verify "${tag_oid}^{commit}")" || die 'release tag must point to a commit'
[[ "${tag_commit}" == "${commit}" ]] || die 'existing release tag points to a different commit'
"${dotagent_bin}" verify-ring0-ratchet --repo "${repo}" --base "${base}" --verify-release-tag "${tag}" >&2 \
    || die 'release tag verification failed'
[[ "$(git -C "${repo}" rev-parse --verify "${ref}^{tag}")" == "${tag_oid}" ]] \
    || die 'local release tag changed during verification'
created_oid=''

printf '[prepare-release-tag] Verified local tag %s for commit %s\n' "${tag}" "${commit}" >&2
printf 'git push origin %s:%s\n' "${ref}" "${stage_ref}"
