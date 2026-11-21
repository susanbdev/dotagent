#!/usr/bin/env bash
# Local YubiKey release ceremony for dotagent (run by the human release owner).
#
#   git tag -s v2.1.0 && git push origin v2.1.0     # CI builds + attests everything
#   scripts/sign-release-yk.sh v2.1.0               # then, on your Mac with the YubiKey
#
# What it does, fail-closed at every step:
#   1. verifies the signed git tag
#   2. downloads every release asset and runs `gh attestation verify` on each
#      (pinned workflow, pinned tag ref, pinned OIDC issuer) -- nothing is signed
#      unless CI provenance checks out
#   3. (macOS, when identities are configured) lipo's a universal binary set,
#      codesigns, builds + notarizes + staples dotagent-<tag>-universal-apple-darwin.pkg
#   4. signs SHA256SUMS (and SHA256SUMS.macos) with the hardware SSH key
#      (namespace dotagent-release-v1) and self-verifies against the key pinned
#      inside the released install.sh
#   5. uploads the new assets; optionally stages install.sh for susanb.dev
#
# Required env:
#   DOTAGENT_SIGN_KEY          path to the sk-ssh-ed25519 key handle (private key never leaves the YubiKey)
# Optional env (macOS .pkg):
#   DOTAGENT_APP_IDENTITY      "Developer ID Application: ..."
#   DOTAGENT_INSTALLER_IDENTITY "Developer ID Installer: ..."
#   DOTAGENT_NOTARY_PROFILE    keychain profile created with `xcrun notarytool store-credentials`
# Optional env (website promotion):
#   DOTAGENT_WEB_DIR           checkout/dir served at https://susanb.dev/ (gets dotagent/<tag>/install.sh and dotagent/install.sh)
#
# No secrets are read from files or argv, and nothing is written outside
# ~/.local/state/dotagent-release (never /tmp).

set -euo pipefail
umask 077

readonly REPO="susanbdev/dotagent"
readonly NAMESPACE="dotagent-release-v1"
readonly SIGNER_ID="release@susanb.dev"
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly WORKFLOW="susanbdev/dotagent/.github/workflows/release.yml"

die() {
    printf '[sign-release] FATAL: %s\n' "$1" >&2
    exit 1
}

note() {
    printf '[sign-release] %s\n' "$1" >&2
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

verify_tag() {
    local tag="$1"
    git tag -v "${tag}" >/dev/null 2>&1 || die "git tag ${tag} is missing or its signature does not verify"
}

download_assets() {
    local tag="$1" dest="$2"
    gh release download "${tag}" --repo "${REPO}" --dir "${dest}"
    [[ -f "${dest}/SHA256SUMS" ]] || die "release has no SHA256SUMS"
    [[ -f "${dest}/install.sh" ]] || die "release has no install.sh"
}

verify_attestations() {
    local tag="$1" dir="$2" asset
    for asset in "${dir}"/*; do
        case "${asset##*/}" in
            *.sshsig|SHA256SUMS.macos) continue ;;
        esac
        note "attestation: ${asset##*/}"
        gh attestation verify "${asset}" --repo "${REPO}" \
            --signer-workflow "${WORKFLOW}" \
            --source-ref "refs/tags/${tag}" \
            --cert-oidc-issuer "${OIDC_ISSUER}" >/dev/null \
            || die "attestation FAILED for ${asset##*/}; refusing to sign"
    done
}

verify_sums() {
    local dir="$1" line want name have
    while IFS= read -r line; do
        want="${line%% *}"
        name="${line#*  }"
        [[ -f "${dir}/${name}" ]] || die "SHA256SUMS lists missing file ${name}"
        have="$(hash_file "${dir}/${name}")"
        [[ "${have}" == "${want}" ]] || die "SHA256SUMS mismatch for ${name}"
    done < "${dir}/SHA256SUMS"
}

build_pkg() {
    local tag="$1" dir="$2" version="${1#v}" work="$2/pkg" t bin arm intel
    [[ "$(uname -s)" == "Darwin" ]] || { note "not macOS: skipping .pkg"; return 1; }
    if [[ -z "${DOTAGENT_APP_IDENTITY:-}" || -z "${DOTAGENT_INSTALLER_IDENTITY:-}" || -z "${DOTAGENT_NOTARY_PROFILE:-}" ]]; then
        note "macOS signing identities not configured: skipping .pkg"
        return 1
    fi
    for t in lipo codesign pkgbuild productbuild xcrun; do require_tool "${t}"; done
    arm="${work}/arm"
    intel="${work}/intel"
    mkdir -p "${arm}" "${intel}" "${work}/root/opt" "${work}/root/etc/paths.d"
    tar -xzf "${dir}/dotagent-${tag}-aarch64-apple-darwin.tar.gz" -C "${arm}" --no-same-owner
    tar -xzf "${dir}/dotagent-${tag}-x86_64-apple-darwin.tar.gz" -C "${intel}" --no-same-owner
    cp -R "${arm}/dotagent-${tag}-aarch64-apple-darwin" "${work}/root/opt/dotagent"
    for bin in dotagent agent-guard agent-guard-sh dotagent-compiler swarm-tool dotagent-harness; do
        chmod u+w "${work}/root/opt/dotagent/bin/${bin}"
        lipo -create \
            "${arm}/dotagent-${tag}-aarch64-apple-darwin/bin/${bin}" \
            "${intel}/dotagent-${tag}-x86_64-apple-darwin/bin/${bin}" \
            -output "${work}/root/opt/dotagent/bin/${bin}"
        codesign --force --options runtime --timestamp \
            --sign "${DOTAGENT_APP_IDENTITY}" "${work}/root/opt/dotagent/bin/${bin}"
        chmod 0555 "${work}/root/opt/dotagent/bin/${bin}"
    done
    printf '/opt/dotagent/bin\n' > "${work}/root/etc/paths.d/dotagent"
    pkgbuild --root "${work}/root" --identifier dev.susanb.dotagent --version "${version}" \
        --install-location / --ownership recommended "${work}/component.pkg"
    productbuild --package "${work}/component.pkg" --sign "${DOTAGENT_INSTALLER_IDENTITY}" \
        "${dir}/dotagent-${tag}-universal-apple-darwin.pkg"
    xcrun notarytool submit "${dir}/dotagent-${tag}-universal-apple-darwin.pkg" \
        --keychain-profile "${DOTAGENT_NOTARY_PROFILE}" --wait
    xcrun stapler staple "${dir}/dotagent-${tag}-universal-apple-darwin.pkg"
    return 0
}

pinned_blob() {
    local line
    line="$(grep '^DOTAGENT_SIGNER_LINE=' "$1" | head -n 1)"
    [[ -n "${line}" ]] || die "install.sh carries no pinned signer"
    printf '%s' "${line}" | tr -s ' "' '\n' | grep -E '^AAAA' | head -n 1
}

sign_file() {
    local file="$1" signers="$2"
    rm -f "${file}.sig" "${file}.sshsig"
    ssh-keygen -Y sign -f "${DOTAGENT_SIGN_KEY}" -n "${NAMESPACE}" "${file}"
    mv "${file}.sig" "${file}.sshsig"
    ssh-keygen -Y verify -f "${signers}" -I "${SIGNER_ID}" -n "${NAMESPACE}" \
        -s "${file}.sshsig" < "${file}" >/dev/null || die "self-verification of ${file##*/}.sshsig failed"
}

main() {
    [[ $# -eq 1 ]] || die "usage: sign-release-yk.sh vX.Y.Z"
    local tag="$1"
    [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "tag must look like v1.2.3"
    [[ -n "${DOTAGENT_SIGN_KEY:-}" && -f "${DOTAGENT_SIGN_KEY}" ]] || die "set DOTAGENT_SIGN_KEY to your sk-ssh-ed25519 key handle"
    [[ -f "${DOTAGENT_SIGN_KEY}.pub" ]] || die "missing ${DOTAGENT_SIGN_KEY}.pub"
    for t in git gh ssh-keygen tar cut tr grep; do require_tool "${t}"; done

    verify_tag "${tag}"

    local state="${HOME}/.local/state/dotagent-release" dir
    mkdir -p "${state}"
    chmod 0700 "${state}"
    dir="${state}/${tag}"
    rm -rf "${dir}"
    mkdir -m 0700 "${dir}"

    download_assets "${tag}" "${dir}"
    verify_attestations "${tag}" "${dir}"
    verify_sums "${dir}"

    local pub_type pub_blob signers
    pub_type="$(cut -d' ' -f1 "${DOTAGENT_SIGN_KEY}.pub")"
    pub_blob="$(cut -d' ' -f2 "${DOTAGENT_SIGN_KEY}.pub")"
    [[ "${pub_type}" == "sk-ssh-ed25519@openssh.com" ]] || die "signing key must be a hardware sk-ssh-ed25519@openssh.com key"
    [[ "$(pinned_blob "${dir}/install.sh")" == "${pub_blob}" ]] \
        || die "released install.sh pins a different key than DOTAGENT_SIGN_KEY; refusing to sign"
    signers="${dir}/allowed_signers"
    printf '%s namespaces="%s" %s %s\n' "${SIGNER_ID}" "${NAMESPACE}" "${pub_type}" "${pub_blob}" > "${signers}"

    local uploads="SHA256SUMS.sshsig"
    sign_file "${dir}/SHA256SUMS" "${signers}"

    local pkg="dotagent-${tag}-universal-apple-darwin.pkg"
    if build_pkg "${tag}" "${dir}"; then
        printf '%s  %s\n' "$(hash_file "${dir}/${pkg}")" "${pkg}" > "${dir}/SHA256SUMS.macos"
        sign_file "${dir}/SHA256SUMS.macos" "${signers}"
        uploads="${uploads} ${pkg} SHA256SUMS.macos SHA256SUMS.macos.sshsig"
    fi

    note "touch your YubiKey for any further prompts; uploading: ${uploads}"
    local files="" name
    for name in ${uploads}; do files="${files} ${dir}/${name}"; done
    # shellcheck disable=SC2086
    gh release upload "${tag}" ${files} --repo "${REPO}" --clobber

    if [[ -n "${DOTAGENT_WEB_DIR:-}" ]]; then
        mkdir -p "${DOTAGENT_WEB_DIR}/dotagent/${tag}"
        cp "${dir}/install.sh" "${DOTAGENT_WEB_DIR}/dotagent/${tag}/install.sh"
        cp "${dir}/install.sh" "${DOTAGENT_WEB_DIR}/dotagent/install.sh"
        note "staged install.sh under ${DOTAGENT_WEB_DIR}/dotagent/ (deploy it as static bytes)"
    else
        note "install.sh sha256 $(hash_file "${dir}/install.sh"): publish it at /dotagent/${tag}/install.sh and /dotagent/install.sh"
    fi
    note "done: ${tag} is signed"
}

main "$@"
