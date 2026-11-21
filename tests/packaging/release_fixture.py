"""Shared fixtures for the packaging tests (stdlib only, no /tmp, no network)."""

import hashlib
import io
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PACKAGING = os.path.join(ROOT, "packaging")
SCRATCH_BASE = os.path.join(os.path.expanduser("~"), ".local", "state", "dotagent-packaging-tests")
TAG = "v9.9.9"
TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
)
BINARIES = ("dotagent", "agent-guard", "agent-guard-sh", "dotagent-compiler", "swarm-tool", "dotagent-harness")
CLEAN_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def make_scratch():
    os.makedirs(SCRATCH_BASE, exist_ok=True)
    return tempfile.mkdtemp(dir=SCRATCH_BASE)


def drop_scratch(path):
    for root, dirs, _ in os.walk(path):
        os.chmod(root, 0o755)
        for name in dirs:
            os.chmod(os.path.join(root, name), 0o755)
    shutil.rmtree(path, ignore_errors=True)


def host_target():
    system = platform.system()
    machine = platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(machine)
    if arch is None:
        return None
    if system == "Linux":
        return arch + "-unknown-linux-musl"
    if system == "Darwin":
        return arch + "-apple-darwin"
    return None


def stub_script(name):
    body = (
        "#!/bin/sh\n"
        "printf '%%s %%s\\n' '%s' \"$*\" >> \"${HOME}/.stub.log\"\n"
        "if [ \"$1\" = self-verify ] && [ -n \"${STUB_FAIL_SELFVERIFY:-}\" ]; then exit 1; fi\n"
        "exit 0\n"
    ) % name
    return body.encode("ascii")


def add_member(tar, name, data, mode, kind=tarfile.REGTYPE, linkname=""):
    info = tarfile.TarInfo(name)
    info.mtime = 1700000000
    info.mode = mode
    info.type = kind
    info.linkname = linkname
    if kind == tarfile.REGTYPE:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    else:
        tar.addfile(info)


def write_archive(path, prefix, files, extra=(), fmt=tarfile.GNU_FORMAT):
    """files: {rel: (bytes, mode)}; extra: [(name, data, mode, kind, linkname)] appended verbatim."""
    with tarfile.open(path, "w:gz", format=fmt) as tar:
        add_member(tar, prefix, b"", 0o555, tarfile.DIRTYPE)
        for rel, (data, mode) in sorted(files.items()):
            add_member(tar, prefix + "/" + rel, data, mode)
        for name, data, mode, kind, linkname in extra:
            add_member(tar, name, data, mode, kind, linkname)


def default_files(shared_marker="one"):
    files = {"bin/" + name: (stub_script(name), 0o555) for name in BINARIES}
    files["dist/manifest.txt"] = (("dist-%s\n" % shared_marker).encode("ascii"), 0o444)
    files["skills/note.md"] = (b"skill\n", 0o444)
    files["profiles/p.toml"] = (b"profile = 1\n", 0o444)
    files["AGENTS.md"] = (b"root\n", 0o444)
    return files


def build_archives(dest, tag=TAG, shared_marker="one", skew_target=None, fmt=tarfile.GNU_FORMAT):
    os.makedirs(dest, exist_ok=True)
    for target in TARGETS:
        marker = "two" if target == skew_target else shared_marker
        prefix = "dotagent-%s-%s" % (tag, target)
        write_archive(os.path.join(dest, prefix + ".tar.gz"), prefix, default_files(marker), fmt=fmt)


def make_key(directory, name="key"):
    path = os.path.join(directory, name)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "release@susanb.dev", "-f", path],
        check=True,
        capture_output=True,
    )
    return path


def run_repackage(archives, signers, out, tag=TAG, extra_args=()):
    command = [
        sys.executable,
        "-B",
        os.path.join(PACKAGING, "repackage.py"),
        "--archives",
        archives,
        "--tag",
        tag,
        "--signers",
        signers,
        "--out",
        out,
        "--allow-software-key",
    ]
    command.extend(extra_args)
    return subprocess.run(command, capture_output=True, text=True, env={"PATH": CLEAN_PATH, "HOME": os.path.expanduser("~")})


def sign_file(path, key):
    for stale in (path + ".sig", path + ".sshsig"):
        if os.path.exists(stale):
            os.remove(stale)
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", key, "-n", "dotagent-release-v1", path],
        check=True,
        capture_output=True,
    )
    os.replace(path + ".sig", path + ".sshsig")


def build_release(scratch, key=None, signer_pub=None, sign=True, fmt=tarfile.GNU_FORMAT):
    """Return dict(dir, out, installer, key) with a flat release directory (signed unless sign=False)."""
    archives = os.path.join(scratch, "archives")
    build_archives(archives, fmt=fmt)
    if signer_pub is None:
        key = key or make_key(scratch)
        signer_pub = key + ".pub"
    out = os.path.join(scratch, "out")
    result = run_repackage(archives, signer_pub, out)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    release = os.path.join(scratch, "release")
    os.makedirs(release)
    for name in os.listdir(archives):
        shutil.copy(os.path.join(archives, name), release)
    shutil.copy(os.path.join(out, "SHA256SUMS"), release)
    installer = os.path.join(out, "web", "install.sh")
    for sub in sorted(os.listdir(out)):
        sub_dir = os.path.join(out, sub)
        if os.path.isdir(sub_dir):
            for name in sorted(os.listdir(sub_dir)):
                if os.path.isfile(os.path.join(sub_dir, name)):
                    shutil.copy(os.path.join(sub_dir, name), release)
    if sign:
        sign_file(os.path.join(release, "SHA256SUMS"), key)
    return {"dir": release, "out": out, "installer": installer, "key": key, "archives": archives}


def strip_gate(installer, dest):
    with open(installer, "r", encoding="ascii") as handle:
        lines = handle.read().splitlines(keepends=True)
    assert lines[-1] == 'dotagent_bootstrap "$@" --eof-v1\n'
    with open(dest, "w", encoding="ascii") as handle:
        handle.writelines(lines[:-1])
    return dest


WRAPPER = (
    'source "${INSTALLER_NOGATE}"\n'
    'dotagent_fetch() { printf "%s\\n" "$1" >> "${RELEASE_DIR}/.fetch.log"; cp "${RELEASE_DIR}/${1##*/}" "$2"; }\n'
    'dotagent_bootstrap "$@" --eof-v1\n'
)


def run_install(release, nogate, home, args=(), extra_env=None):
    env = {"HOME": home, "PATH": CLEAN_PATH, "RELEASE_DIR": release["dir"], "INSTALLER_NOGATE": nogate}
    env.update(extra_env or {})
    return subprocess.run(
        ["bash", "-c", WRAPPER, "bash"] + list(args),
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
    )


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def slurp(path, mode="r"):
    with open(path, mode, **({"encoding": "ascii"} if "b" not in mode else {})) as handle:
        return handle.read()
