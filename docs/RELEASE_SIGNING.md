# Release signing

Normal pull requests and merges to `main` use the automated CI and review gates. An official version tag requires an annotated Git tag signed by an enrolled FIDO2 OpenSSH `sk-*` key. The release owner keeps the authenticator and its signing handle on their local machine. [GitHub signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) · [Yubico Git signing guide](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html)

## Prepare and stage the signed tag

1. In a trusted local checkout, fetch `origin/main`. Choose the approved commit on `main` and the `v` tag matching its workspace version in `Cargo.toml`.
2. Run `ssh-keygen -lf` on the local SSH `.pub` file and compare the fingerprint with the enrolled key in [`config/allowed_human_signers`](../config/allowed_human_signers). Register that public key as a **Signing Key** on the release owner's GitHub account, and use a verified GitHub email as the tagger identity. [GitHub SSH key enrollment](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)
3. Configure SSH signing for the release checkout and build the current verifier. Substitute the actual local OpenSSH FIDO2 key handle, version, and approved commit below. Touch the authenticator when Git prompts.

   ```sh
   git config --local gpg.format ssh
   git config --local user.signingkey "$HOME/.ssh/id_ed25519_sk"
   cargo build --locked -p agent-guard --bin dotagent
   DOTAGENT_BIN=target/debug/dotagent bash scripts/prepare-release-tag.sh vX.Y.Z APPROVED_COMMIT_SHA
   ```

4. Review the commit and tag printed by the script, then run its printed push command. It stages the verified annotated tag object at `refs/tags/release-request/vX.Y.Z`. Treat staging and official refs as immutable. If either ref already names a different object, stop and have the release owner resolve the conflict.

   ```sh
   git push origin refs/tags/vX.Y.Z:refs/tags/release-request/vX.Y.Z
   ```

## Promote from GitHub

The repository administrator configures required reviewers for the `release` environment and installs the repository-scoped release promoter GitHub App.

1. In the repository's **Actions** tab, select **Verifiable Release & SLSA Provenance**, choose **Run workflow** on `main`, and enter `vX.Y.Z` in `release_tag`. [Run a workflow in GitHub](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
2. Review the staging object, signature check, and target commit. An authorized reviewer approves the protected `release` environment. Promotion creates the official `refs/tags/vX.Y.Z` ref from that same signed object. The official tag then triggers the release CI, provenance checks, and publication gates. If `main` advances during approval, dispatch again to verify against the current trust anchors.
3. Record the official tag object ID, its target commit SHA, the signer fingerprint, and the workflow run in the release audit trail.

## Verify the installer PIV key

The P-256 installer key is pinned in [`packaging/release-signer.pub`](../packaging/release-signer.pub). A public PEM with the SHA-256 fingerprint `31f6f5f179f8951f4e2ed76dd22ef0e3256c51ae9fbb22732057b82c47838c94` over its DER SubjectPublicKeyInfo matches this key. It verifies the `SHA256SUMS` sidecars for the installer distribution channel. Official Git tags use the separate OpenSSH FIDO2 credential.

With the device connected locally, read the public key from the configured PIV slot. The example uses slot `9a`, the default in the release ceremony. `--verify` checks possession against the slot and may prompt for the PIN. [YubiKey Manager PIV commands](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html)

```sh
ykman piv keys export --verify 9a piv-9a.pub.pem
openssl pkey -pubin -in piv-9a.pub.pem -outform DER | openssl dgst -sha256
```

When publishing installer sidecars, use the existing [`scripts/sign-release-yk.sh`](../scripts/sign-release-yk.sh) ceremony after the official release builds and attests its assets. The script verifies the tag and provenance before the local PIV operation and verifies each generated sidecar against the pinned public key.

## Rotate an enrolled key

Open a dedicated trust-anchor change. For a replacement SSH key, generate an `sk-*` credential on the approved authenticator at a fresh local path. Capture FIDO attestation at generation where supported, verify it against the trusted vendor chain, and verify possession of the exact public key. Enroll the public key in GitHub and the repository signer file after review. Keep the existing approved signer available until the replacement has been verified. [OpenSSH hardware enrollment](https://man.openbsd.org/ssh-keygen)

For a replacement PIV key generated on the device, obtain the slot and device attestation certificates locally. Verify the chain against a trusted Yubico root, then compare the attested public-key fingerprint with the candidate installer pin. Coordinate the pin change with installer distribution before release. [YubiKey PIV attestation](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html)

```sh
ykman piv keys attest 9a piv-9a.attestation.pem
ykman piv certificates export f9 piv-device.attestation.pem
openssl verify -CAfile yubico-piv-root.pem -untrusted piv-device.attestation.pem piv-9a.attestation.pem
```

Record the public fingerprint, verified attestation result, reviewer, and approved trust-anchor commit in the audit trail. Keep private handles, PINs, management keys, and device-identifying attestation details in operator custody.
