import io
import json
import os
import re
import subprocess
import tarfile
import unittest
import zipfile

import release_fixture as fx
from release_fixture import slurp


class RepackageTests(unittest.TestCase):
    def setUp(self):
        self.scratch = fx.make_scratch()
        self.addCleanup(fx.drop_scratch, self.scratch)
        self.archives = os.path.join(self.scratch, "archives")
        fx.build_archives(self.archives)
        self.key = fx.make_key(self.scratch)

    def repackage(self, out_name="out", **kwargs):
        out = os.path.join(self.scratch, out_name)
        result = fx.run_repackage(self.archives, self.key + ".pub", out, **kwargs)
        return result, out

    def snapshot(self, out):
        files = {}
        for root, _, names in os.walk(out):
            for name in names:
                path = os.path.join(root, name)
                files[os.path.relpath(path, out)] = fx.sha256_file(path)
        return files

    def test_output_is_byte_identical_across_runs(self):
        first, out_a = self.repackage("out-a")
        second, out_b = self.repackage("out-b")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.snapshot(out_a), self.snapshot(out_b))

    def test_expected_assets_exist(self):
        result, out = self.repackage()
        self.assertEqual(result.returncode, 0, result.stderr)
        files = self.snapshot(out)
        self.assertIn("web/install.sh", files)
        self.assertIn("brew/dotagent.rb", files)
        self.assertEqual(len([n for n in files if n.endswith(".whl")]), 4)
        self.assertEqual(len([n for n in files if n.endswith(".tgz")]), 5)
        sums = slurp(os.path.join(out, "SHA256SUMS")).splitlines()
        names = [line.split("  ", 1)[1] for line in sums]
        self.assertEqual(names, sorted(names))
        for target in fx.TARGETS:
            self.assertIn("dotagent-%s-%s.tar.gz" % (fx.TAG, target), names)
        self.assertIn("install.sh", names)

    def test_wheel_record_matches_contents(self):
        result, out = self.repackage()
        self.assertEqual(result.returncode, 0, result.stderr)
        wheel = os.path.join(out, "pypi", "dotagent-9.9.9-py3-none-macosx_11_0_arm64.whl")
        import base64
        import hashlib

        with zipfile.ZipFile(wheel) as archive:
            record = archive.read("dotagent-9.9.9.dist-info/RECORD").decode("ascii").splitlines()
            listed = {}
            for line in record:
                name, digest, size = line.rsplit(",", 2)
                listed[name] = (digest, size)
            for info in archive.infolist():
                if info.filename.endswith("/RECORD"):
                    self.assertEqual(listed[info.filename], ("", ""))
                    continue
                data = archive.read(info.filename)
                want = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
                self.assertEqual(listed[info.filename], (want, str(len(data))))
                self.assertEqual(info.date_time, (2023, 11, 14, 22, 13, 20))
            scripts = [i for i in archive.infolist() if "/scripts/" in i.filename]
            self.assertEqual(len(scripts), 6)
            for info in scripts:
                self.assertEqual((info.external_attr >> 16) & 0o777, 0o555)
            wheel_meta = archive.read("dotagent-9.9.9.dist-info/WHEEL").decode("ascii")
            self.assertIn("Tag: py3-none-macosx_11_0_arm64", wheel_meta)

    def test_linux_wheel_carries_both_tags(self):
        result, out = self.repackage()
        self.assertEqual(result.returncode, 0, result.stderr)
        wheel = os.path.join(out, "pypi", "dotagent-9.9.9-py3-none-musllinux_1_2_x86_64.manylinux_2_17_x86_64.whl")
        with zipfile.ZipFile(wheel) as archive:
            meta = archive.read("dotagent-9.9.9.dist-info/WHEEL").decode("ascii")
        self.assertIn("Tag: py3-none-musllinux_1_2_x86_64", meta)
        self.assertIn("Tag: py3-none-manylinux_2_17_x86_64", meta)

    def test_npm_packages_have_no_lifecycle_scripts(self):
        result, out = self.repackage()
        self.assertEqual(result.returncode, 0, result.stderr)
        npm_dir = os.path.join(out, "npm")
        for name in sorted(os.listdir(npm_dir)):
            with tarfile.open(os.path.join(npm_dir, name), "r:gz") as tar:
                manifest = json.load(tar.extractfile("package/package.json"))
                self.assertNotIn("scripts", manifest, name)
                self.assertEqual(manifest["version"], "9.9.9")
                for member in tar:
                    self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1700000000))
        with tarfile.open(os.path.join(npm_dir, "susanbdev-dotagent-9.9.9.tgz"), "r:gz") as tar:
            manifest = json.load(tar.extractfile("package/package.json"))
        self.assertEqual(len(manifest["optionalDependencies"]), 4)
        self.assertTrue(all(v == "9.9.9" for v in manifest["optionalDependencies"].values()))
        self.assertEqual(sorted(manifest["bin"]), sorted(fx.BINARIES))

    def test_installer_is_ascii_gated_and_syntax_clean(self):
        result, out = self.repackage()
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = slurp(os.path.join(out, "web", "install.sh"), "rb")
        raw.decode("ascii")
        text = raw.decode("ascii")
        self.assertTrue(text.endswith('dotagent_bootstrap "$@" --eof-v1\n'))
        self.assertEqual(text.count("--eof-v1\n"), 1)
        self.assertIsNone(re.search(r"@[A-Z0-9_]{3,}@", text))
        self.assertEqual(subprocess.run(["bash", "-n"], input=raw).returncode, 0)

    def test_formula_pins_digests(self):
        result, out = self.repackage()
        self.assertEqual(result.returncode, 0, result.stderr)
        formula = slurp(os.path.join(out, "brew", "dotagent.rb"))
        for target in fx.TARGETS:
            digest = fx.sha256_file(os.path.join(self.archives, "dotagent-%s-%s.tar.gz" % (fx.TAG, target)))
            self.assertIn(digest, formula)
        self.assertIn('Dir["dotagent-*"]', formula)

    def test_divergent_shared_trees_are_rejected(self):
        fx.build_archives(self.archives, skew_target="x86_64-apple-darwin")
        result, _ = self.repackage()
        self.assertEqual(result.returncode, 2)
        self.assertIn("shared trees differ", result.stderr)

    def test_missing_or_placeholder_signer_fails_closed(self):
        placeholder = os.path.join(self.scratch, "placeholder.pub")
        with open(placeholder, "w", encoding="ascii") as handle:
            handle.write("# nothing here\n")
        result = fx.run_repackage(self.archives, placeholder, os.path.join(self.scratch, "o"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("PEM PUBLIC KEY", result.stderr)

    def test_non_p256_key_is_rejected(self):
        ed_priv = os.path.join(self.scratch, "ed.pem")
        ed_pub = os.path.join(self.scratch, "ed.pub")
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", ed_priv], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", ed_priv, "-pubout", "-out", ed_pub], check=True, capture_output=True)
        result = fx.run_repackage(self.archives, ed_pub, os.path.join(self.scratch, "o"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("P-256", result.stderr)

    def test_committed_release_signer_pub_is_valid(self):
        pub = os.path.join(fx.PACKAGING, "release-signer.pub")
        result = fx.run_repackage(self.archives, pub, os.path.join(self.scratch, "o"))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hostile_archive_member_is_rejected(self):
        target = "x86_64-unknown-linux-musl"
        prefix = "dotagent-%s-%s" % (fx.TAG, target)
        fx.write_archive(
            os.path.join(self.archives, prefix + ".tar.gz"),
            prefix,
            fx.default_files(),
            extra=[("../escape", b"x", 0o644, tarfile.REGTYPE, "")],
        )
        result, _ = self.repackage()
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside archive root", result.stderr)

    def test_bad_tag_is_rejected(self):
        result, _ = self.repackage(tag="v1.2")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
