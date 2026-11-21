"""Integration tests for scripts/sign-release-yk.sh using stubbed git/gh/ssh-keygen/Apple tools."""

import os
import shutil
import subprocess
import unittest

import release_fixture as fx
from release_fixture import slurp

CEREMONY = os.path.join(fx.ROOT, "scripts", "sign-release-yk.sh")
FAKE_BLOB = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tZmFrZWZha2VmYWtl"
SK_LINE = "sk-ssh-ed25519@openssh.com %s release@susanb.dev\n" % FAKE_BLOB

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
    "ssh-keygen": """#!/bin/sh
if [ "$1 $2" = "-Y sign" ]; then
  for last; do :; done
  printf 'SIG\\n' > "${last}.sig"
fi
exit 0
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
        self.signer = os.path.join(self.scratch, "signer.pub")
        with open(self.signer, "w", encoding="ascii") as handle:
            handle.write(SK_LINE)
        self.key = os.path.join(self.scratch, "yubikey")
        with open(self.key, "w", encoding="ascii") as handle:
            handle.write("handle\n")
        with open(self.key + ".pub", "w", encoding="ascii") as handle:
            handle.write(SK_LINE)
        self.release = fx.build_release(self.scratch, signer_pub=self.signer, sign=False)
        self.log = os.path.join(self.scratch, "stub.log")

    def ceremony(self, extra_env=None):
        env = {
            "HOME": self.home,
            "PATH": self.stubs + ":" + fx.CLEAN_PATH,
            "DOTAGENT_SIGN_KEY": self.key,
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
        self.assertIn("SHA256SUMS.sshsig", uploads[0])
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
        other = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tb3RoZXJvdGhlcg== x\n"
        with open(self.key + ".pub", "w", encoding="ascii") as handle:
            handle.write(other)
        result = self.ceremony()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pins a different key", result.stderr)
        self.assertEqual(self.uploads(), [])

    def test_software_key_is_refused(self):
        with open(self.key + ".pub", "w", encoding="ascii") as handle:
            handle.write("ssh-ed25519 %s x\n" % FAKE_BLOB)
        result = self.ceremony()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hardware", result.stderr)

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
