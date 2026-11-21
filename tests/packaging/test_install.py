import os
import shutil
import signal
import subprocess
import tarfile
import time
import unittest

import release_fixture as fx
from release_fixture import slurp

HOST = fx.host_target()
PREFIX = "dotagent-%s-%s" % (fx.TAG, HOST)


@unittest.skipIf(HOST is None, "unsupported host platform")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = fx.make_scratch()
        self.addCleanup(fx.drop_scratch, self.scratch)
        self.release = fx.build_release(self.scratch)
        self.nogate = fx.strip_gate(self.release["installer"], os.path.join(self.scratch, "nogate.sh"))
        self.home = os.path.join(self.scratch, "home")
        os.makedirs(self.home)
        self.bin = os.path.join(self.home, ".local", "bin")

    def install(self, *args, **kwargs):
        return fx.run_install(self.release, self.nogate, self.home, args, **kwargs)

    def assert_untouched(self):
        self.assertFalse(os.path.exists(self.bin), "binaries must not be installed")
        share = os.path.join(self.home, ".local", "share")
        self.assertFalse(os.path.exists(share), "payload must not be installed")

    def assert_no_stage_left(self):
        state = os.path.join(self.home, ".local", "state", "agent-guard")
        leftovers = [n for n in os.listdir(state) if n.startswith(".stage.")] if os.path.isdir(state) else []
        self.assertEqual(leftovers, [])

    def test_happy_path_installs_sealed_tree_and_binaries(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in fx.BINARIES:
            path = os.path.join(self.bin, name)
            self.assertTrue(os.path.isfile(path), name)
            self.assertEqual(fx.mode_of(path), 0o555)
        share = os.path.join(self.home, ".local", "share", "dotagent", fx.TAG)
        self.assertEqual(fx.mode_of(share), 0o555)
        self.assertEqual(fx.mode_of(os.path.join(share, "dist", "manifest.txt")), 0o444)
        self.assertEqual(fx.mode_of(os.path.join(share, "bin", "dotagent")), 0o555)
        self.assert_no_stage_left()
        log = slurp(os.path.join(self.home, ".stub.log"))
        self.assertIn("dotagent self-verify --subject", log)
        self.assertIn("--sums", log)

    def test_reinstall_over_existing_install_succeeds(self):
        self.assertEqual(self.install().returncode, 0)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        parent = os.path.join(self.home, ".local", "share", "dotagent")
        self.assertEqual(os.listdir(parent), [fx.TAG])

    def test_activate_runs_verify_then_activate(self):
        result = self.install("--activate", "--workspace", self.home)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = slurp(os.path.join(self.home, ".stub.log")).splitlines()
        compiler = [i for i, line in enumerate(log) if line.startswith("dotagent-compiler verify ")]
        activate = [i for i, line in enumerate(log) if line.startswith("agent-guard activate --dotagent-root ")]
        self.assertEqual(len(compiler), 1)
        self.assertEqual(len(activate), 1)
        self.assertLess(compiler[0], activate[0])

    def test_tampered_archive_is_rejected(self):
        path = os.path.join(self.release["dir"], PREFIX + ".tar.gz")
        with open(path, "ab") as handle:
            handle.write(b"x")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match digest baked", result.stderr)
        self.assert_untouched()
        self.assert_no_stage_left()

    def test_forged_signature_is_rejected(self):
        other = fx.make_key(self.scratch, "attacker")
        sums = os.path.join(self.release["dir"], "SHA256SUMS")
        fx.sign_file(sums, other)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is NOT valid", result.stderr)
        self.assert_untouched()

    def test_edited_sums_break_the_signature(self):
        sums = os.path.join(self.release["dir"], "SHA256SUMS")
        text = slurp(sums)
        with open(sums, "w", encoding="ascii") as handle:
            handle.write(text.replace("a", "b", 1).replace("0", "1", 1))
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assert_untouched()

    def test_missing_signature_is_rejected(self):
        os.remove(os.path.join(self.release["dir"], "SHA256SUMS.sshsig"))
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assert_untouched()

    def test_namespace_confusion_is_rejected(self):
        sums = os.path.join(self.release["dir"], "SHA256SUMS")
        os.remove(sums + ".sshsig")
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", self.release["key"], "-n", "git", sums],
            check=True,
            capture_output=True,
        )
        os.replace(sums + ".sig", sums + ".sshsig")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is NOT valid", result.stderr)

    def test_agent_guard_session_refuses_with_exit_2(self):
        result = self.install(extra_env={"AGENT_GUARD_SESSION": "1"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("guarded agent session", result.stderr)
        self.assertEqual(os.listdir(self.home), [])

    def test_unknown_flag_exits_2(self):
        result = self.install("--bogus")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(os.listdir(self.home), [])

    @unittest.skipIf(os.geteuid() == 0, "needs a non-root user")
    def test_system_install_requires_existing_root(self):
        result = self.install("--system")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("never invokes sudo", result.stderr)

    def test_running_binary_is_replaced_atomically(self):
        os.makedirs(self.bin)
        busy = os.path.join(self.bin, "dotagent")
        shutil.copy("/bin/sleep", busy)
        os.chmod(busy, 0o555)
        process = subprocess.Popen([busy, "30"])
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        time.sleep(0.2)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(process.poll(), "running binary must keep running")
        with open(busy, "rb") as handle:
            self.assertTrue(handle.read(2) == b"#!", "binary was swapped for the release copy")
        process.send_signal(signal.SIGTERM)

    def audit(self, members):
        archive = os.path.join(self.scratch, "evil.tar.gz")
        fx.write_archive(archive, PREFIX, fx.default_files(), extra=members)
        script = 'source "${INSTALLER_NOGATE}"\nset -euo pipefail\ndotagent_audit_archive "$1" "$2"\n'
        return subprocess.run(
            ["bash", "-c", script, "bash", archive, PREFIX],
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH, "INSTALLER_NOGATE": self.nogate},
        )

    def test_audit_accepts_a_clean_archive(self):
        self.assertEqual(self.audit([]).returncode, 0)

    def test_audit_rejects_traversal_absolute_links_and_devices(self):
        cases = {
            "traversal": ("%s/../evil" % PREFIX, b"x", 0o644, tarfile.REGTYPE, ""),
            "absolute": ("/etc/evil", b"x", 0o644, tarfile.REGTYPE, ""),
            "outside": ("elsewhere/evil", b"x", 0o644, tarfile.REGTYPE, ""),
            "symlink": ("%s/link" % PREFIX, b"", 0o777, tarfile.SYMTYPE, "/etc/passwd"),
            "hardlink": ("%s/hard" % PREFIX, b"", 0o644, tarfile.LNKTYPE, "%s/AGENTS.md" % PREFIX),
            "device": ("%s/dev" % PREFIX, b"", 0o644, tarfile.CHRTYPE, ""),
            "fifo": ("%s/fifo" % PREFIX, b"", 0o644, tarfile.FIFOTYPE, ""),
            "oddname": ("%s/a b" % PREFIX, b"x", 0o644, tarfile.REGTYPE, ""),
        }
        for label, member in cases.items():
            with self.subTest(label):
                result = self.audit([member])
                self.assertNotEqual(result.returncode, 0, label)
                self.assertIn("refusing", result.stderr)

    def test_truncated_stream_executes_nothing(self):
        script = slurp(self.release["installer"], "rb")
        gate = script.rindex(b'dotagent_install_main "$@"')
        offsets = set(range(0, gate + len(b"dotagent_install_main"), 89))
        offsets.update(i + 1 for i, byte in enumerate(script[:gate]) if byte == 10)
        offsets.add(gate + len(b"dotagent_install_main") - 1)
        for offset in sorted(offsets):
            if offset > gate + len(b"dotagent_install_main") - 1:
                continue
            home = os.path.join(self.scratch, "trunc-home")
            shutil.rmtree(home, ignore_errors=True)
            os.makedirs(home)
            subprocess.run(
                ["bash"],
                input=script[:offset],
                capture_output=True,
                env={"HOME": home, "PATH": fx.CLEAN_PATH},
            )
            self.assertEqual(os.listdir(home), [], "truncation at byte %d had side effects" % offset)

    def test_full_script_via_stdin_pipe_refuses_inside_agent_session(self):
        script = slurp(self.release["installer"], "rb")
        result = subprocess.run(
            ["bash"],
            input=script,
            capture_output=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH, "AGENT_GUARD_SESSION": "x"},
        )
        self.assertEqual(result.returncode, 2)

    def test_unrendered_template_refuses(self):
        template = os.path.join(fx.PACKAGING, "install.sh.in")
        result = subprocess.run(
            ["bash", template],
            capture_output=True,
            text=True,
            env={"HOME": self.home, "PATH": fx.CLEAN_PATH},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrendered", result.stderr)
        self.assertFalse(os.path.exists(self.bin))


if __name__ == "__main__":
    unittest.main()
