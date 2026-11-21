"""Smoke tests that actually install the generated wheels and npm packages."""

import os
import shutil
import subprocess
import sys
import tarfile
import unittest

import release_fixture as fx
from release_fixture import slurp

HOST = fx.host_target()


def wheel_name():
    return {
        "x86_64-unknown-linux-musl": "dotagent-9.9.9-py3-none-musllinux_1_2_x86_64.manylinux_2_17_x86_64.whl",
        "aarch64-unknown-linux-musl": "dotagent-9.9.9-py3-none-musllinux_1_2_aarch64.manylinux_2_17_aarch64.whl",
        "x86_64-apple-darwin": "dotagent-9.9.9-py3-none-macosx_10_12_x86_64.whl",
        "aarch64-apple-darwin": "dotagent-9.9.9-py3-none-macosx_11_0_arm64.whl",
    }[HOST]


NPM_PLATFORM = {
    "x86_64-unknown-linux-musl": "linux-x64",
    "aarch64-unknown-linux-musl": "linux-arm64",
    "x86_64-apple-darwin": "darwin-x64",
    "aarch64-apple-darwin": "darwin-arm64",
}


@unittest.skipIf(HOST is None, "unsupported host platform")
class PackageSmokeTests(unittest.TestCase):
    def setUp(self):
        self.scratch = fx.make_scratch()
        self.addCleanup(fx.drop_scratch, self.scratch)
        self.release = fx.build_release(self.scratch)
        self.home = os.path.join(self.scratch, "home")
        os.makedirs(self.home)

    def test_wheel_installs_with_pip_and_binaries_run(self):
        probe = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("pip unavailable")
        target = os.path.join(self.scratch, "site")
        wheel = os.path.join(self.release["out"], "pypi", wheel_name())
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-deps", "--no-index", "--no-compile", "--target", target, wheel],
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in fx.BINARIES:
            path = os.path.join(target, "bin", name)
            self.assertTrue(os.path.isfile(path), name)
            self.assertTrue(os.access(path, os.X_OK), name)
        run = subprocess.run([os.path.join(target, "bin", "dotagent"), "--probe"], env={"HOME": self.home})
        self.assertEqual(run.returncode, 0)
        self.assertTrue(os.path.isfile(os.path.join(target, "share", "dotagent", "dist", "manifest.txt")))

    def test_npm_shim_resolves_platform_package_and_runs_binary(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node unavailable")
        modules = os.path.join(self.scratch, "project", "node_modules", "@susanbdev")
        os.makedirs(modules)
        npm_dir = os.path.join(self.release["out"], "npm")
        for archive, folder in (
            ("susanbdev-dotagent-9.9.9.tgz", "dotagent"),
            ("susanbdev-dotagent-%s-9.9.9.tgz" % NPM_PLATFORM[HOST], "dotagent-" + NPM_PLATFORM[HOST]),
        ):
            with tarfile.open(os.path.join(npm_dir, archive), "r:gz") as tar:
                tar.extractall(os.path.join(self.scratch, "x-" + folder))
            shutil.copytree(os.path.join(self.scratch, "x-" + folder, "package"), os.path.join(modules, folder))
        shim = os.path.join(modules, "dotagent", "bin", "agent-guard.js")
        result = subprocess.run(
            [node, shim, "hello", "world"],
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH},
            cwd=os.path.join(self.scratch, "project"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("agent-guard hello world", slurp(os.path.join(self.home, ".stub.log")))

    def test_npm_shim_fails_loudly_when_platform_package_is_missing(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node unavailable")
        modules = os.path.join(self.scratch, "project", "node_modules", "@susanbdev")
        os.makedirs(modules)
        with tarfile.open(os.path.join(self.release["out"], "npm", "susanbdev-dotagent-9.9.9.tgz"), "r:gz") as tar:
            tar.extractall(os.path.join(self.scratch, "x-root"))
        shutil.copytree(os.path.join(self.scratch, "x-root", "package"), os.path.join(modules, "dotagent"))
        result = subprocess.run(
            [node, os.path.join(modules, "dotagent", "bin", "dotagent.js")],
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH},
            cwd=os.path.join(self.scratch, "project"),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not installed", result.stderr)


if __name__ == "__main__":
    unittest.main()
