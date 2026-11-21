import os
import shutil
import subprocess
import unittest

import release_fixture as fx

ACTIVATE = os.path.join(fx.ROOT, "scripts", "activate-local.sh")
CEREMONY = os.path.join(fx.ROOT, "scripts", "sign-release-yk.sh")
PACKAGING_FILES = (
    "packaging/install.sh.in",
    "packaging/repackage.py",
    "packaging/nfpm.yaml",
    "packaging/Containerfile.oci",
    "packaging/release-signer.pub",
    "scripts/sign-release-yk.sh",
    "scripts/activate-local.sh",
    ".github/workflows/release.yml",
)


class ActivateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = fx.make_scratch()
        self.addCleanup(fx.drop_scratch, self.scratch)
        self.home = os.path.join(self.scratch, "home")
        os.makedirs(self.home)
        self.prebuilt = os.path.join(self.scratch, "prebuilt")
        os.makedirs(os.path.join(self.prebuilt, "bin"))
        for name in fx.BINARIES:
            path = os.path.join(self.prebuilt, "bin", name)
            with open(path, "wb") as handle:
                handle.write(fx.stub_script(name))
            os.chmod(path, 0o755)

    def run_activate(self, *args):
        return subprocess.run(
            ["bash", ACTIVATE] + list(args),
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH},
            stdin=subprocess.DEVNULL,
        )

    def test_from_prebuilt_skips_cargo_and_installs_sealed_binaries(self):
        result = self.run_activate("--from-prebuilt", self.prebuilt, self.home)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in fx.BINARIES:
            if name == "agent-guard-sh":
                continue
            self.assertEqual(fx.mode_of(os.path.join(self.home, ".local", "bin", name)), 0o555, name)
        with open(os.path.join(self.home, ".stub.log"), encoding="ascii") as handle:
            log = handle.read()
        self.assertIn("dotagent-compiler verify", log)
        self.assertIn("agent-guard activate --dotagent-root", log)

    def test_from_prebuilt_rejects_symlinked_binary(self):
        target = os.path.join(self.prebuilt, "bin", "swarm-tool")
        os.remove(target)
        os.symlink("/bin/true", target)
        result = self.run_activate("--from-prebuilt", self.prebuilt)
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_from_prebuilt_rejects_missing_binary(self):
        os.remove(os.path.join(self.prebuilt, "bin", "agent-guard"))
        result = self.run_activate("--from-prebuilt", self.prebuilt)
        self.assertEqual(result.returncode, 2)

    def test_unknown_option_is_rejected(self):
        self.assertEqual(self.run_activate("--bogus").returncode, 2)


class CeremonyTests(unittest.TestCase):
    def run_ceremony(self, *args, env=None):
        base = {"HOME": os.path.expanduser("~"), "PATH": os.environ.get("PATH", fx.CLEAN_PATH)}
        base.update(env or {})
        return subprocess.run(["bash", CEREMONY] + list(args), capture_output=True, text=True, env=base)

    def test_requires_exactly_one_tag(self):
        self.assertEqual(self.run_ceremony().returncode, 1)

    def test_rejects_malformed_tag(self):
        result = self.run_ceremony("main", env={"DOTAGENT_SIGN_KEY": "/dev/null"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("tag must look like", result.stderr)

    def test_requires_signing_key(self):
        result = self.run_ceremony("v1.2.3")
        self.assertEqual(result.returncode, 1)
        self.assertIn("DOTAGENT_SIGN_KEY", result.stderr)


class HygieneTests(unittest.TestCase):
    def test_tracked_packaging_files_are_pure_ascii_without_cr(self):
        for rel in PACKAGING_FILES:
            with open(os.path.join(fx.ROOT, rel), "rb") as handle:
                data = handle.read()
            data.decode("ascii")
            self.assertNotIn(b"\r", data, rel)
            self.assertNotIn(b"\x1b", data, rel)

    def test_workflow_pins_every_action_to_a_commit(self):
        with open(os.path.join(fx.ROOT, ".github", "workflows", "release.yml"), encoding="ascii") as handle:
            lines = handle.read().splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("uses:") or stripped.startswith("- uses:"):
                ref = stripped.split("uses:", 1)[1].strip().split()[0]
                self.assertRegex(ref, r"^[\w./-]+@[0-9a-f]{40}$", line)

    def test_workflow_has_no_static_registry_tokens(self):
        with open(os.path.join(fx.ROOT, ".github", "workflows", "release.yml"), encoding="ascii") as handle:
            text = handle.read()
        for forbidden in ("NPM_TOKEN", "PYPI_TOKEN", "PYPI_API_TOKEN", "NODE_AUTH_TOKEN", "TWINE_PASSWORD"):
            self.assertNotIn(forbidden, text)

    def test_shellcheck_is_clean_when_available(self):
        if shutil.which("shellcheck") is None:
            self.skipTest("shellcheck not installed")
        files = [os.path.join(fx.ROOT, rel) for rel in PACKAGING_FILES if rel.endswith((".sh", ".sh.in"))]
        result = subprocess.run(["shellcheck"] + files, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
