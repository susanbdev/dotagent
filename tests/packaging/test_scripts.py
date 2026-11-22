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

    def write_sums(self, tamper=False):
        lines = []
        for name in fx.BINARIES:
            digest = fx.sha256_file(os.path.join(self.prebuilt, "bin", name))
            lines.append("%s  bin/%s" % (("0" * 64) if tamper and name == "swarm-tool" else digest, name))
        path = os.path.join(self.scratch, "prebuilt.sums")
        with open(path, "w", encoding="ascii") as handle:
            handle.write("\n".join(lines) + "\n")
        return path

    def run_activate(self, *args):
        return subprocess.run(
            ["bash", ACTIVATE] + list(args),
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH},
            stdin=subprocess.DEVNULL,
        )

    def test_from_prebuilt_skips_cargo_and_installs_sealed_binaries(self):
        result = self.run_activate("--from-prebuilt", self.prebuilt, "--prebuilt-sums", self.write_sums(), self.home)
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
        sums = self.write_sums()
        target = os.path.join(self.prebuilt, "bin", "swarm-tool")
        os.remove(target)
        os.symlink(os.path.join(self.prebuilt, "bin", "dotagent"), target)
        result = self.run_activate("--from-prebuilt", self.prebuilt, "--prebuilt-sums", sums)
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_from_prebuilt_rejects_symlinked_optional_harness(self):
        sums = self.write_sums()
        target = os.path.join(self.prebuilt, "bin", "dotagent-harness")
        os.remove(target)
        os.symlink(os.path.join(self.prebuilt, "bin", "dotagent"), target)
        result = self.run_activate("--from-prebuilt", self.prebuilt, "--prebuilt-sums", sums)
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_from_prebuilt_requires_sums(self):
        result = self.run_activate("--from-prebuilt", self.prebuilt)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--prebuilt-sums", result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "bin", "dotagent")))

    def test_from_prebuilt_rejects_tampered_binary_before_installing_anything(self):
        result = self.run_activate("--from-prebuilt", self.prebuilt, "--prebuilt-sums", self.write_sums(tamper=True))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not listed", result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "bin", "dotagent")))

    def test_from_prebuilt_rejects_missing_binary(self):
        sums = self.write_sums()
        os.remove(os.path.join(self.prebuilt, "bin", "agent-guard"))
        result = self.run_activate("--from-prebuilt", self.prebuilt, "--prebuilt-sums", sums)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "bin", "dotagent")))

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
        result = self.run_ceremony("main")
        self.assertEqual(result.returncode, 1)
        self.assertIn("tag must look like", result.stderr)

    def test_requires_signer_pubkey(self):
        result = self.run_ceremony("v1.2.3", env={"DOTAGENT_SIGNER_PUB": "/nonexistent"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing signer pubkey", result.stderr)


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

    def load_workflow(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with open(os.path.join(fx.ROOT, ".github", "workflows", "release.yml"), encoding="ascii") as handle:
            return yaml.safe_load(handle)

    def test_workflow_permissions_are_least_privilege(self):
        flow = self.load_workflow()
        self.assertEqual(flow["permissions"], {"contents": "read"})
        for name in ("publish-pypi", "publish-npm", "publish-homebrew", "repackage-ecosystem"):
            self.assertNotIn("contents: write", str(flow["jobs"][name].get("permissions")), name)
        oidc_publish = {"contents": "read", "attestations": "read", "id-token": "write"}
        for name in ("publish-pypi", "publish-npm"):
            self.assertEqual(flow["jobs"][name]["permissions"], oidc_publish, name)
        read_provenance = {"contents": "read", "attestations": "read"}
        for name in ("publish-homebrew", "build-oci-image"):
            self.assertEqual(flow["jobs"][name]["permissions"], read_provenance, name)
        self.assertNotIn("packages", flow["jobs"]["publish-pypi"]["permissions"])

    def test_every_publish_job_sits_behind_a_named_environment(self):
        flow = self.load_workflow()
        for name in ("publish-attested-release", "publish-ghcr", "publish-pypi", "publish-npm", "publish-homebrew"):
            self.assertIn("environment", flow["jobs"][name], name)

    def test_publish_chain_is_ordered_and_gated(self):
        flow = self.load_workflow()
        jobs = flow["jobs"]
        self.assertEqual(jobs["build-archives"]["needs"], "verify-release-gate")
        self.assertEqual(jobs["repackage-ecosystem"]["needs"], "build-archives")
        self.assertEqual(jobs["publish-attested-release"]["needs"], "repackage-ecosystem")
        for name in ("build-oci-image", "publish-pypi", "publish-npm", "publish-homebrew"):
            self.assertEqual(jobs[name]["needs"], "publish-attested-release", name)
        self.assertEqual(jobs["publish-ghcr"]["needs"], "build-oci-image")
        gate = "\n".join(str(step.get("run", "")) for step in jobs["verify-release-gate"]["steps"])
        self.assertIn("merge-base --is-ancestor", gate)
        self.assertIn("verification.verified", gate)

    def test_release_job_has_an_explicit_repo_context(self):
        flow = self.load_workflow()
        step = [s for s in flow["jobs"]["publish-attested-release"]["steps"] if "gh release create" in str(s.get("run", ""))][0]
        self.assertEqual(step["env"]["GH_REPO"], "${{ github.repository }}")

    def test_downstream_jobs_verify_provenance_before_using_assets(self):
        flow = self.load_workflow()
        for name in ("build-oci-image", "publish-pypi", "publish-npm", "publish-homebrew"):
            runs = [str(step.get("run", "")) for step in flow["jobs"][name]["steps"]]
            self.assertTrue(any("gh attestation verify" in run and "--source-digest" in run for run in runs), name)

    def test_multiarch_build_uses_a_container_builder(self):
        flow = self.load_workflow()
        text = "\n".join(str(step.get("run", "")) for step in flow["jobs"]["build-oci-image"]["steps"])
        self.assertLess(text.index("buildx create --name dotagent --driver docker-container"), text.index("buildx build"))
        self.assertIn("type=oci,dest=", text)
        self.assertNotIn("--push", text)
        steps = flow["jobs"]["publish-ghcr"]["steps"]
        publish = "\n".join(str(step.get("run", "")) for step in steps)
        verify = publish.index("verify-file-sha256 oci/dotagent-image.tar")
        copy = publish.index("skopeo copy")
        self.assertLess(verify, copy)
        self.assertIn("--all --preserve-digests", publish)
        self.assertNotIn("buildx build", publish)
        self.assertTrue(any(step.get("with", {}).get("push-to-registry") for step in steps))

    def test_shellcheck_is_clean_when_available(self):
        if shutil.which("shellcheck") is None:
            self.skipTest("shellcheck not installed")
        files = [os.path.join(fx.ROOT, rel) for rel in PACKAGING_FILES if rel.endswith((".sh", ".sh.in"))]
        result = subprocess.run(["shellcheck"] + files, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
