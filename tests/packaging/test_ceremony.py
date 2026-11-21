"""Integration tests for scripts/sign-release-yk.sh using stubbed git/gh/yubico-piv-tool/Apple tools."""

import os
import subprocess
import unittest

import release_fixture as fx
from release_fixture import slurp

CEREMONY = os.path.join(fx.ROOT, "scripts", "sign-release-yk.sh")

STUBS = {
    "git": """#!/bin/sh
case "$1" in
  fetch) exit 0 ;;
  tag) exit "${STUB_TAG_RC:-0}" ;;
  rev-parse) echo 0123456789abcdef0123456789abcdef01234567 ;;
  *) exit 0 ;;
esac
""",
    "gh": """#!/bin/sh
printf '%s\\n' "gh $*" >> "${STUB_LOG}"
case "$1 $2" in
  "release download")
    while [ $# -gt 0 ]; do
      if [ "$1" = "--dir" ]; then cp "${STUB_RELEASE_DIR}"/* "$2"/; fi
      shift
    done ;;
  "attestation verify") exit "${STUB_ATTEST_RC:-0}" ;;
  "release upload") printf '%s\\n' "UPLOAD $*" >> "${STUB_LOG}" ;;
esac
exit 0
""",
    "yubico-piv-tool": """#!/bin/sh
in="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -i) in="$2"; shift 2 ;;
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
exec /usr/bin/openssl pkeyutl -sign -inkey "${STUB_PRIV_KEY}" -pkeyopt digest:sha256 -in "${in}" -out "${out}"
""",
    "uname": """#!/bin/sh
if [ -n "${STUB_DARWIN:-}" ]; then echo Darwin; else exec /usr/bin/uname "$@"; fi
""",
}
for _tool in ("lipo", "codesign", "pkgbuild", "productbuild", "xcrun"):
    STUBS[_tool] = "#!/bin/sh\nexit 1\n"


class CeremonyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = fx.make_scratch()
        self.addCleanup(fx.drop_scratch, self.scratch)
        self.home = os.path.join(self.scratch, "home")
        os.makedirs(self.home)
        self.stubs = os.path.join(self.scratch, "stubs")
        os.makedirs(self.stubs)
        for name, body in STUBS.items():
            path = os.path.join(self.stubs, name)
            with open(path, "w", encoding="ascii") as handle:
                handle.write(body)
            os.chmod(path, 0o755)
        self.key = fx.make_key(self.scratch, "piv")
        self.signer = self.key + ".pub"
        self.release = fx.build_release(self.scratch, key=self.key, signer_pub=self.signer, sign=False)
        self.log = os.path.join(self.scratch, "stub.log")

    def ceremony(self, extra_env=None):
        env = {
            "HOME": self.home,
            "PATH": self.stubs + ":" + fx.CLEAN_PATH,
            "DOTAGENT_SIGNER_PUB": self.signer,
            "STUB_PRIV_KEY": self.key,
            "STUB_RELEASE_DIR": self.release["dir"],
            "STUB_LOG": self.log,
        }
        env.update(extra_env or {})
        return subprocess.run(["bash", CEREMONY, fx.TAG], capture_output=True, text=True, env=env)

    def uploads(self):
        if not os.path.exists(self.log):
            return []
        return [line for line in slurp(self.log).splitlines() if line.startswith("UPLOAD ")]

    def test_happy_path_signs_sums_and_uploads_only_the_signature(self):
        result = self.ceremony()
        self.assertEqual(result.returncode, 0, result.stderr)
        uploads = self.uploads()
        self.assertEqual(len(uploads), 1)
        self.assertIn("SHA256SUMS.sig", uploads[0])
        self.assertNotIn(".pkg", uploads[0])
        verified = [l for l in slurp(self.log).splitlines() if l.startswith("gh attestation verify")]
        self.assertGreaterEqual(len(verified), 10)
        for line in verified:
            self.assertIn("--source-digest 0123456789abcdef0123456789abcdef01234567", line)
            self.assertIn("--source-ref refs/tags/%s" % fx.TAG, line)
            self.assertIn("--signer-workflow susanbdev/dotagent/.github/workflows/release.yml", line)

    def test_attestation_failure_blocks_signing_and_upload(self):
        result = self.ceremony({"STUB_ATTEST_RC": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attestation FAILED", result.stderr)
        self.assertEqual(self.uploads(), [])

    def test_unverifiable_git_tag_blocks_everything(self):
        result = self.ceremony({"STUB_TAG_RC": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature does not verify", result.stderr)
        self.assertFalse(os.path.exists(self.log))

    def test_key_not_pinned_in_installer_is_refused(self):
        other = fx.make_key(self.scratch, "other")
        result = self.ceremony({"DOTAGENT_SIGNER_PUB": other + ".pub"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pins a different key", result.stderr)
        self.assertEqual(self.uploads(), [])

    def test_mismatched_private_key_fails_self_verify(self):
        other = fx.make_key(self.scratch, "other")
        result = self.ceremony({"STUB_PRIV_KEY": other})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("self-verification", result.stderr)
        self.assertEqual(self.uploads(), [])

    def test_installer_bake_that_disagrees_with_sums_is_refused(self):
        installer = os.path.join(self.release["dir"], "install.sh")
        text = slurp(installer)
        digest = [l for l in text.splitlines() if l.startswith("DOTAGENT_SHA256_LINUX_X64=")][0].split('"')[1]
        with open(installer, "w", encoding="ascii") as handle:
            handle.write(text.replace(digest, "f" * 64))
        sums = os.path.join(self.release["dir"], "SHA256SUMS")
        rewritten = []
        for line in slurp(sums).splitlines():
            if line.endswith("  install.sh"):
                line = fx.sha256_file(installer) + "  install.sh"
            rewritten.append(line)
        with open(sums, "w", encoding="ascii") as handle:
            handle.write("\n".join(rewritten) + "\n")
        result = self.ceremony()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from SHA256SUMS", result.stderr)
        self.assertEqual(self.uploads(), [])

    def test_failed_pkg_build_aborts_instead_of_uploading_an_unsigned_pkg(self):
        result = self.ceremony(
            {
                "STUB_DARWIN": "1",
                "DOTAGENT_APP_IDENTITY": "Developer ID Application: Test",
                "DOTAGENT_INSTALLER_IDENTITY": "Developer ID Installer: Test",
                "DOTAGENT_NOTARY_PROFILE": "test",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.uploads(), [])

    def test_latest_install_sh_is_not_downgraded(self):
        web = os.path.join(self.scratch, "web")
        os.makedirs(os.path.join(web, "dotagent"))
        newer = slurp(os.path.join(self.release["dir"], "install.sh")).replace('"%s"' % fx.TAG, '"v10.0.0"', 1)
        with open(os.path.join(web, "dotagent", "install.sh"), "w", encoding="ascii") as handle:
            handle.write(newer)
        result = self.ceremony({"DOTAGENT_WEB_DIR": web})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"v10.0.0"', slurp(os.path.join(web, "dotagent", "install.sh")))
        self.assertTrue(os.path.isfile(os.path.join(web, "dotagent", fx.TAG, "install.sh")))

    def test_newer_tag_is_promoted_to_latest(self):
        web = os.path.join(self.scratch, "web")
        os.makedirs(os.path.join(web, "dotagent"))
        older = slurp(os.path.join(self.release["dir"], "install.sh")).replace('"%s"' % fx.TAG, '"v1.0.0"', 1)
        with open(os.path.join(web, "dotagent", "install.sh"), "w", encoding="ascii") as handle:
            handle.write(older)
        result = self.ceremony({"DOTAGENT_WEB_DIR": web})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"%s"' % fx.TAG, slurp(os.path.join(web, "dotagent", "install.sh")))

    def test_duplicate_baked_digest_in_installer_is_refused(self):
        installer = os.path.join(self.release["dir"], "install.sh")
        text = slurp(installer) + 'DOTAGENT_SHA256_LINUX_X64="%s"\n' % ("0" * 64)
        with open(installer, "w", encoding="ascii") as handle:
            handle.write(text)
        sums = os.path.join(self.release["dir"], "SHA256SUMS")
        new_hash = fx.sha256_file(installer)
        lines = [
            ("%s  install.sh" % new_hash) if line.endswith("  install.sh") else line
            for line in slurp(sums).splitlines()
        ]
        with open(sums, "w", encoding="ascii") as handle:
            handle.write("\n".join(lines) + "\n")
        result = self.ceremony()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected exactly 1", result.stderr)
        self.assertEqual(self.uploads(), [])

    def test_sums_path_traversal_is_refused(self):
        sums = os.path.join(self.release["dir"], "SHA256SUMS")
        with open(sums, "a", encoding="ascii") as handle:
            handle.write("%s  ../outside\n" % ("0" * 64))
        result = self.ceremony()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid filename", result.stderr)
        self.assertEqual(self.uploads(), [])


if __name__ == "__main__":
    unittest.main()
