#!/usr/bin/env python3
"""Deterministic repackager for dotagent release archives (stdlib only).

Consumes the four attested `dotagent-<tag>-<target>.tar.gz` archives produced by
the `build-archives` CI job and emits, WITHOUT recompiling anything:

    <out>/web/install.sh                   baked, hardened installer
    <out>/pypi/dotagent-<ver>-*.whl        4 platform wheels
    <out>/npm/*.tgz                        4 platform packages + 1 root package
    <out>/brew/dotagent.rb                 Homebrew formula
    <out>/sys/*.deb|*.rpm|*.apk            via nfpm (only when nfpm is available)
    <out>/SHA256SUMS                       archives + everything above, flat names

Same inputs always produce byte-identical outputs (fixed mtimes, sorted entries,
zeroed owners, no host paths). Every output is checked to be 7-bit ASCII text or
a binary payload taken verbatim from an archive.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile

EPOCH = 1700000000
EPOCH_ZIP = (2023, 11, 14, 22, 13, 20)
BINARIES = (
    "dotagent",
    "agent-guard",
    "agent-guard-sh",
    "dotagent-compiler",
    "swarm-tool",
    "dotagent-harness",
)
SHARED_TREES = ("dist", "profiles", "skills")
TAG_RE = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$")
TARGETS = {
    "x86_64-unknown-linux-musl": {
        "wheel": "musllinux_1_2_x86_64.manylinux_2_17_x86_64",
        "npm": "linux-x64",
        "os": "linux",
        "cpu": "x64",
        "deb": "amd64",
    },
    "aarch64-unknown-linux-musl": {
        "wheel": "musllinux_1_2_aarch64.manylinux_2_17_aarch64",
        "npm": "linux-arm64",
        "os": "linux",
        "cpu": "arm64",
        "deb": "arm64",
    },
    "x86_64-apple-darwin": {
        "wheel": "macosx_10_12_x86_64",
        "npm": "darwin-x64",
        "os": "darwin",
        "cpu": "x64",
        "deb": None,
    },
    "aarch64-apple-darwin": {
        "wheel": "macosx_11_0_arm64",
        "npm": "darwin-arm64",
        "os": "darwin",
        "cpu": "arm64",
        "deb": None,
    },
}
SUMMARY = "Zero-trust guard, compiler and harness for AI coding agents"
HOMEPAGE = "https://susanb.dev/dotagent"
REPO_URL = "https://github.com/susanbdev/dotagent"


class RepackageError(Exception):
    """Raised for any integrity or input problem; the CLI turns it into exit 2."""


def assert_ascii(label, text):
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RepackageError("%s is not pure 7-bit ASCII" % label) from exc
    if "\r" in text or "\x1b" in text:
        raise RepackageError("%s contains CR or ESC" % label)


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_archive(path, tag, target):
    """Return {relative_path: (bytes, is_exec)} after strict member auditing."""
    prefix = "dotagent-%s-%s" % (tag, target)
    files = {}
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            name = member.name.rstrip("/")
            parts = name.split("/")
            if not (parts[0] == prefix) or ".." in parts or name.startswith("/") or "" in parts:
                raise RepackageError("%s: member outside archive root: %r" % (path, member.name))
            if member.isdir():
                continue
            if not member.isreg():
                raise RepackageError("%s: non-regular member: %r" % (path, member.name))
            rel = "/".join(parts[1:])
            if not rel:
                raise RepackageError("%s: unexpected file at archive root" % path)
            handle = tar.extractfile(member)
            if handle is None:
                raise RepackageError("%s: unreadable member %r" % (path, member.name))
            files[rel] = (handle.read(), rel.startswith("bin/"))
    for binary in BINARIES:
        if "bin/" + binary not in files:
            raise RepackageError("%s: missing binary %s" % (path, binary))
    return files


def check_parity(trees):
    """Every target must ship byte-identical dist/profiles/skills trees."""
    reference_target = sorted(trees)[0]
    reference = {
        rel: hash_bytes(data)
        for rel, (data, _) in trees[reference_target].items()
        if rel.split("/")[0] in SHARED_TREES
    }
    if not any(rel.startswith("dist/") for rel in reference):
        raise RepackageError("archives contain no dist/ tree")
    for target, files in sorted(trees.items()):
        current = {
            rel: hash_bytes(data)
            for rel, (data, _) in files.items()
            if rel.split("/")[0] in SHARED_TREES
        }
        if current != reference:
            raise RepackageError("shared trees differ between %s and %s" % (reference_target, target))


P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


def parse_signer_pem(raw):
    """Extract and validate an ECDSA P-256 SPKI PEM public key as canonical single-line base64."""
    assert_ascii("signers file", raw)
    in_block = False
    body = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not in_block:
            if not stripped or stripped.startswith("#"):
                continue
            if stripped == "-----BEGIN PUBLIC KEY-----":
                in_block = True
                continue
            raise RepackageError("release signer must be a PEM PUBLIC KEY block")
        if stripped == "-----END PUBLIC KEY-----":
            try:
                der = base64.b64decode("".join(body), validate=True)
            except Exception as exc:
                raise RepackageError("malformed PEM base64 in signers file") from exc
            if len(der) != 91 or not der.startswith(P256_SPKI_PREFIX):
                raise RepackageError("release signer must be an ECDSA P-256 SPKI public key")
            return base64.b64encode(der).decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
            raise RepackageError("malformed PEM body in signers file")
        body.append(stripped)
    raise RepackageError("no PEM PUBLIC KEY found in signers file")


def render_installer(template_path, tag, digests, signer_spki):
    with open(template_path, "r", encoding="ascii", newline="") as handle:
        text = handle.read()
    values = {"RELEASE_TAG": tag, "SIGNER_SPKI": signer_spki}
    for target, digest in digests.items():
        values["SHA256_" + target.upper().replace("-", "_")] = digest
    for key, value in values.items():
        text = text.replace("@%s@" % key, value)
    leftover = re.findall(r"@[A-Z0-9_]{3,}@", text)
    if leftover:
        raise RepackageError("unrendered placeholders: %s" % ", ".join(sorted(set(leftover))))
    assert_ascii("install.sh", text)
    if not text.endswith('dotagent_bootstrap "$@" --eof-v1\n'):
        raise RepackageError("install.sh must end with the EOF function gate")
    bash = shutil.which("bash")
    if bash:
        result = subprocess.run([bash, "-n"], input=text.encode("ascii"), capture_output=True)
        if result.returncode != 0:
            raise RepackageError("rendered install.sh fails bash -n: %s" % result.stderr.decode("ascii", "replace"))
    return text.encode("ascii")


def write_zip(path, entries):
    """entries: list of (name, bytes, mode). Order is preserved."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=EPOCH_ZIP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def write_tgz(path, entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data, mode in sorted(entries):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = EPOCH
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    with open(path, "wb") as handle:
        with gzip.GzipFile(filename="", fileobj=handle, mode="wb", mtime=0, compresslevel=9) as zipped:
            zipped.write(raw.getvalue())


def record_digest(data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def build_wheel(out_dir, version, license_id, target, files):
    spec = TARGETS[target]
    data_dir = "dotagent-%s.data" % version
    info_dir = "dotagent-%s.dist-info" % version
    entries = []
    for rel, (data, is_exec) in sorted(files.items()):
        if rel.startswith("bin/"):
            entries.append(("%s/scripts/%s" % (data_dir, rel[4:]), data, 0o555))
        elif rel.split("/")[0] in SHARED_TREES:
            entries.append(("%s/data/share/dotagent/%s" % (data_dir, rel), data, 0o444))
    metadata = "\n".join(
        [
            "Metadata-Version: 2.1",
            "Name: dotagent",
            "Version: " + version,
            "Summary: " + SUMMARY,
            "Home-page: " + HOMEPAGE,
            "License: " + license_id,
            "Project-URL: Source, " + REPO_URL,
            "Requires-Python: >=3.8",
            "",
            "Prebuilt dotagent binaries. Verify provenance with: gh attestation verify <file> --owner susanbdev",
            "",
        ]
    )
    tags = spec["wheel"].split(".")
    wheel_meta = "\n".join(
        ["Wheel-Version: 1.0", "Generator: dotagent-repackage", "Root-Is-Purelib: false"]
        + ["Tag: py3-none-" + tag for tag in tags]
        + [""]
    )
    assert_ascii("METADATA", metadata)
    assert_ascii("WHEEL", wheel_meta)
    entries.append((info_dir + "/METADATA", metadata.encode("ascii"), 0o444))
    entries.append((info_dir + "/WHEEL", wheel_meta.encode("ascii"), 0o444))
    record_lines = ["%s,%s,%d" % (name, record_digest(data), len(data)) for name, data, _ in entries]
    record_lines.append(info_dir + "/RECORD,,")
    entries.append((info_dir + "/RECORD", ("\n".join(record_lines) + "\n").encode("ascii"), 0o444))
    path = os.path.join(out_dir, "dotagent-%s-py3-none-%s.whl" % (version, spec["wheel"]))
    write_zip(path, entries)
    return path


def render_shim(binary, package_map):
    lines = [
        "#!/usr/bin/env node",
        '"use strict";',
        'const { spawnSync } = require("node:child_process");',
        'const path = require("node:path");',
        "const PACKAGES = %s;" % json.dumps(package_map, separators=(",", ":"), sort_keys=True),
        "const key = process.platform + \"-\" + process.arch;",
        "const name = PACKAGES[key];",
        "if (!name) {",
        '  process.stderr.write("dotagent: unsupported platform " + key + "\\n");',
        "  process.exit(2);",
        "}",
        "let root;",
        "try {",
        '  root = path.dirname(require.resolve(name + "/package.json"));',
        "} catch (err) {",
        '  process.stderr.write("dotagent: platform package " + name + " is not installed (optionalDependencies skipped?)\\n");',
        "  process.exit(2);",
        "}",
        'const result = spawnSync(path.join(root, "bin", "%s"), process.argv.slice(2), { stdio: "inherit" });' % binary,
        "if (result.error) {",
        "  process.stderr.write(String(result.error) + \"\\n\");",
        "  process.exit(2);",
        "}",
        "if (result.signal) {",
        "  process.kill(process.pid, result.signal);",
        "}",
        "process.exit(result.status === null ? 1 : result.status);",
        "",
    ]
    return "\n".join(lines)


def dump_json(value):
    text = json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n"
    assert_ascii("package.json", text)
    return text.encode("ascii")


def npm_license(license_id):
    """npm only accepts SPDX ids, UNLICENSED, or SEE LICENSE IN <file>."""
    return "UNLICENSED" if license_id.startswith("LicenseRef-") else license_id


def build_npm(out_dir, version, license_id, trees):
    license_id = npm_license(license_id)
    paths = []
    package_map = {}
    for target, spec in sorted(TARGETS.items()):
        package_map["%s-%s" % (spec["os"], spec["cpu"])] = "@susanbdev/dotagent-" + spec["npm"]
    for target, files in sorted(trees.items()):
        spec = TARGETS[target]
        name = "@susanbdev/dotagent-" + spec["npm"]
        manifest = {
            "name": name,
            "version": version,
            "description": SUMMARY + " (%s binaries)" % spec["npm"],
            "license": license_id,
            "homepage": HOMEPAGE,
            "repository": {"type": "git", "url": "git+" + REPO_URL + ".git"},
            "os": [spec["os"]],
            "cpu": [spec["cpu"]],
            "files": ["bin/", "share/"],
            "publishConfig": {"access": "public"},
        }
        entries = [("package/package.json", dump_json(manifest), 0o644)]
        for rel, (data, is_exec) in files.items():
            if rel.startswith("bin/"):
                entries.append(("package/" + rel, data, 0o755))
            elif rel.split("/")[0] in SHARED_TREES:
                entries.append(("package/share/dotagent/" + rel, data, 0o644))
        path = os.path.join(out_dir, "susanbdev-dotagent-%s-%s.tgz" % (spec["npm"], version))
        write_tgz(path, entries)
        paths.append(path)
    root_manifest = {
        "name": "@susanbdev/dotagent",
        "version": version,
        "description": SUMMARY,
        "license": license_id,
        "homepage": HOMEPAGE,
        "repository": {"type": "git", "url": "git+" + REPO_URL + ".git"},
        "bin": {binary: "bin/%s.js" % binary for binary in BINARIES},
        "files": ["bin/"],
        "engines": {"node": ">=18"},
        "optionalDependencies": {pkg: version for pkg in sorted(package_map.values())},
        "publishConfig": {"access": "public"},
    }
    entries = [("package/package.json", dump_json(root_manifest), 0o644)]
    for binary in BINARIES:
        shim = render_shim(binary, package_map)
        assert_ascii("npm shim", shim)
        entries.append(("package/bin/%s.js" % binary, shim.encode("ascii"), 0o755))
    path = os.path.join(out_dir, "susanbdev-dotagent-%s.tgz" % version)
    write_tgz(path, entries)
    paths.append(path)
    return paths


def render_formula(version, tag, license_id, digests):
    def block(target):
        return (
            '      url "%s/releases/download/%s/dotagent-%s-%s.tar.gz"\n      sha256 "%s"\n'
            % (REPO_URL, tag, tag, target, digests[target])
        )

    text = "\n".join(
        [
            "class Dotagent < Formula",
            '  desc "%s"' % SUMMARY,
            '  homepage "%s"' % HOMEPAGE,
            '  version "%s"' % version,
            "  license :cannot_represent" if license_id.startswith("LicenseRef") else '  license "%s"' % license_id,
            "",
            "  on_macos do",
            "    on_arm do",
            block("aarch64-apple-darwin").rstrip("\n"),
            "    end",
            "    on_intel do",
            block("x86_64-apple-darwin").rstrip("\n"),
            "    end",
            "  end",
            "",
            "  on_linux do",
            "    on_arm do",
            block("aarch64-unknown-linux-musl").rstrip("\n"),
            "    end",
            "    on_intel do",
            block("x86_64-unknown-linux-musl").rstrip("\n"),
            "    end",
            "  end",
            "",
            "  def install",
            '    root = Dir["dotagent-*"].find { |p| File.directory?(p) } || "."',
            '    libexec.install Dir["#{root}/*"]',
        ]
        + ["    bin.install_symlink libexec/\"bin/%s\"" % binary for binary in BINARIES]
        + [
            "  end",
            "",
            "  test do",
            '    assert_predicate bin/"dotagent", :executable?',
            "  end",
            "end",
            "",
        ]
    )
    assert_ascii("dotagent.rb", text)
    return text.encode("ascii")


def stage_system_tree(stage_dir, files):
    """Write /opt/dotagent contents with final modes (dirs 0555, files 0444, bin 0555)."""
    if os.path.isdir(stage_dir):
        remove_tree(stage_dir)
    os.makedirs(stage_dir)
    for rel, (data, is_exec) in sorted(files.items()):
        if not (rel.startswith("bin/") or rel.split("/")[0] in SHARED_TREES or "/" not in rel):
            continue
        target = os.path.join(stage_dir, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(data)
        os.chmod(target, 0o555 if rel.startswith("bin/") else 0o444)
        os.utime(target, (EPOCH, EPOCH))
    for root, dirs, _ in os.walk(stage_dir, topdown=False):
        for name in dirs:
            os.utime(os.path.join(root, name), (EPOCH, EPOCH))
    seal_dirs(stage_dir)


def seal_dirs(stage_dir):
    for root, dirs, _ in os.walk(stage_dir, topdown=False):
        os.chmod(root, 0o555)


def remove_tree(path):
    for root, dirs, files in os.walk(path):
        os.chmod(root, 0o755)
    shutil.rmtree(path)


def build_system(out_dir, version, trees, nfpm_path, config_path):
    """Return list of produced package paths (empty when nfpm is unavailable)."""
    nfpm = nfpm_path or shutil.which("nfpm")
    produced = []
    if not nfpm:
        sys.stderr.write("[repackage] nfpm not found: skipping .deb/.rpm/.apk\n")
        return produced
    with open(config_path, "r", encoding="ascii") as cfg_handle:
        config_tpl = cfg_handle.read()
    assert_ascii("nfpm.yaml", config_tpl)
    for target, spec in sorted(TARGETS.items()):
        if spec["deb"] is None:
            continue
        scratch_dir = os.path.join(out_dir, "stage-" + spec["deb"])
        stage = os.path.abspath(os.path.join(scratch_dir, "opt", "dotagent"))
        stage_system_tree(stage, trees[target])
        stage_yaml = "'" + stage.replace("'", "''") + "'"
        rendered_cfg = (
            config_tpl.replace("${NFPM_VERSION}", version)
            .replace("${NFPM_ARCH}", spec["deb"])
            .replace("${NFPM_STAGE}", stage_yaml)
        )
        rendered_cfg_path = os.path.join(scratch_dir, "nfpm.yaml")
        write_file(rendered_cfg_path, rendered_cfg.encode("ascii"), mode=0o444)
        env = dict(os.environ)
        env.update(
            {
                "NFPM_VERSION": version,
                "NFPM_ARCH": spec["deb"],
                "NFPM_STAGE": stage,
                "SOURCE_DATE_EPOCH": str(EPOCH),
            }
        )
        for packager in ("deb", "rpm", "apk"):
            before = set(os.listdir(out_dir))
            result = subprocess.run(
                [nfpm, "package", "--packager", packager, "--config", rendered_cfg_path, "--target", out_dir],
                env=env,
                capture_output=True,
            )
            if result.returncode != 0:
                raise RepackageError("nfpm %s failed: %s" % (packager, result.stderr.decode("ascii", "replace")))
            produced.extend(
                os.path.join(out_dir, name) for name in sorted(set(os.listdir(out_dir)) - before) if name.endswith("." + packager)
            )
        remove_tree(scratch_dir)
    return produced


def write_sums(out_dir, archive_paths, extra_paths):
    names = {}
    for path in list(archive_paths) + list(extra_paths):
        base = os.path.basename(path)
        if base in names:
            raise RepackageError("duplicate release asset name: " + base)
        with open(path, "rb") as handle:
            names[base] = hash_bytes(handle.read())
    lines = "".join("%s  %s\n" % (names[name], name) for name in sorted(names))
    assert_ascii("SHA256SUMS", lines)
    path = os.path.join(out_dir, "SHA256SUMS")
    with open(path, "w", encoding="ascii", newline="") as handle:
        handle.write(lines)
    return path


def write_file(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)
    os.utime(path, (EPOCH, EPOCH))
    return path


def run_repackage(args):
    match = TAG_RE.match(args.tag)
    if not match:
        raise RepackageError("tag must look like v1.2.3")
    version = match.group(1)
    here = os.path.dirname(os.path.abspath(__file__))
    template = os.path.join(here, "install.sh.in")
    config = os.path.join(here, "nfpm.yaml")
    with open(args.signers, "r", encoding="ascii") as handle:
        signer = parse_signer_pem(handle.read())

    archive_paths = []
    digests = {}
    trees = {}
    for target in sorted(TARGETS):
        path = os.path.join(args.archives, "dotagent-%s-%s.tar.gz" % (args.tag, target))
        if not os.path.isfile(path) or os.path.islink(path):
            raise RepackageError("missing archive: " + path)
        with open(path, "rb") as handle:
            digests[target] = hash_bytes(handle.read())
        trees[target] = read_archive(path, args.tag, target)
        archive_paths.append(path)
    check_parity(trees)

    if os.path.exists(args.out):
        remove_tree(args.out)
    outputs = []
    outputs.append(write_file(os.path.join(args.out, "web", "install.sh"), render_installer(template, args.tag, digests, signer)))
    outputs.append(write_file(os.path.join(args.out, "brew", "dotagent.rb"), render_formula(version, args.tag, args.license, digests)))
    pypi_dir = os.path.join(args.out, "pypi")
    npm_dir = os.path.join(args.out, "npm")
    sys_dir = os.path.join(args.out, "sys")
    for directory in (pypi_dir, npm_dir, sys_dir):
        os.makedirs(directory, exist_ok=True)
    for target, files in sorted(trees.items()):
        outputs.append(build_wheel(pypi_dir, version, args.license, target, files))
    outputs.extend(build_npm(npm_dir, version, args.license, trees))
    outputs.extend(build_system(sys_dir, version, trees, args.nfpm, config))
    sums = write_sums(args.out, archive_paths, outputs)
    sys.stdout.write("repackaged %d assets; sums: %s\n" % (len(outputs), sums))
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Deterministically repackage dotagent release archives")
    parser.add_argument("--archives", required=True, help="directory holding the 4 release archives")
    parser.add_argument("--tag", required=True, help="release tag, for example v2.1.0")
    parser.add_argument("--signers", required=True, help="file with the YubiKey PIV ECDSA P-256 PEM public key")
    parser.add_argument("--out", required=True, help="output directory (recreated)")
    parser.add_argument("--license", default="LicenseRef-Proprietary", help="SPDX expression for package metadata")
    parser.add_argument("--nfpm", default=None, help="path to nfpm (default: PATH lookup)")
    return parser.parse_args(argv)


def main(argv):
    try:
        return run_repackage(parse_args(argv))
    except RepackageError as exc:
        sys.stderr.write("[repackage] FATAL: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
