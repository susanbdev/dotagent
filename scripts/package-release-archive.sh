#!/usr/bin/env bash
# Deterministic, bit-for-bit reproducible PAX `.tar.gz` release packager (`susanbdev/dotagent`).
# Shared across CI cleanroom smoke tests, dual-directory reproducibility checks, and `release.yml`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET=""
TAG=""
OUT_ARCHIVE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift 2 ;;
        --tag) TAG="${2:-}"; shift 2 ;;
        --out) OUT_ARCHIVE="${2:-}"; shift 2 ;;
        --repo-root) REPO_ROOT="$(cd "${2:-}" && pwd)"; shift 2 ;;
        *)
            echo "USAGE_ERROR: unknown flag '$1' (expected --target <triple> --tag <ver> --out <path.tar.gz>)" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${TARGET}" || -z "${TAG}" || -z "${OUT_ARCHIVE}" ]]; then
    echo "USAGE_ERROR: --target <triple>, --tag <ver>, and --out <path.tar.gz> are required" >&2
    exit 2
fi
[[ "${TARGET}" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "USAGE_ERROR: invalid --target '${TARGET}'" >&2; exit 2; }
[[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "USAGE_ERROR: invalid --tag '${TAG}'" >&2; exit 2; }

BIN_SRC_DIR="${REPO_ROOT}/target/${TARGET}/release"
BINS=(dotagent agent-guard agent-guard-sh dotagent-compiler swarm-tool dotagent-harness)
for bin in "${BINS[@]}"; do
    if [[ ! -f "${BIN_SRC_DIR}/${bin}" || -L "${BIN_SRC_DIR}/${bin}" ]]; then
        echo "MISSING_RELEASE_BINARY: expected regular file '${BIN_SRC_DIR}/${bin}'" >&2
        exit 2
    fi
done

STAGE_BASE="${REPO_ROOT}/target/.pkg-stage-$$-${RANDOM}"
PKG_NAME="dotagent-${TAG}-${TARGET}"
STAGE_DIR="${STAGE_BASE}/${PKG_NAME}"
mkdir -p "${STAGE_DIR}/bin"
cleanup() {
    chmod -R u+w "${STAGE_BASE}" 2>/dev/null || true
    rm -rf "${STAGE_BASE}"
}
trap cleanup EXIT

for bin in "${BINS[@]}"; do
    cp "${BIN_SRC_DIR}/${bin}" "${STAGE_DIR}/bin/${bin}"
    chmod 0555 "${STAGE_DIR}/bin/${bin}"
done

cp -RP "${REPO_ROOT}/dist" "${REPO_ROOT}/dist-verify" "${REPO_ROOT}/profiles" "${REPO_ROOT}/skills" "${STAGE_DIR}/"
for doc in AGENTS.md README.md THREAT_MODEL.md SECURITY.md CHANGELOG.md spec.md; do
    cp "${REPO_ROOT}/${doc}" "${STAGE_DIR}/${doc}"
done

mkdir -p "$(dirname "${OUT_ARCHIVE}")"
python3 - "${STAGE_DIR}" "${OUT_ARCHIVE}" <<'PY'
import gzip, os, stat, sys, tarfile

stage_dir, out_tar_gz = sys.argv[1], sys.argv[2]
base_parent = os.path.dirname(stage_dir)
entries = []
for root, dirs, files in os.walk(stage_dir, followlinks=False):
    dirs.sort()
    files.sort()
    rel_root = os.path.relpath(root, base_parent)
    entries.append((root, rel_root, True))
    for dname in dirs:
        dfull = os.path.join(root, dname)
        if os.path.islink(dfull):
            raise SystemExit(f"FORBIDDEN_SYMLINK_IN_STAGE: {dfull}")
    for fname in files:
        full = os.path.join(root, fname)
        entries.append((full, os.path.join(rel_root, fname), False))
entries.sort(key=lambda item: item[1])

with open(out_tar_gz, "wb") as raw_fh:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz_fh:
        with tarfile.open(mode="w", fileobj=gz_fh, format=tarfile.PAX_FORMAT) as tf:
            for full, arcname, is_dir in entries:
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    raise SystemExit(f"FORBIDDEN_SYMLINK_IN_STAGE: {full}")
                ti = tarfile.TarInfo(name=arcname.replace(os.sep, "/"))
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                ti.mtime = 0
                if is_dir and stat.S_ISDIR(st.st_mode):
                    ti.name = ti.name.rstrip("/") + "/"
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o755
                    tf.addfile(ti)
                elif stat.S_ISREG(st.st_mode):
                    ti.type = tarfile.REGTYPE
                    ti.size = st.st_size
                    ti.mode = 0o555 if (st.st_mode & 0o111) else 0o444
                    with open(full, "rb") as src_fh:
                        tf.addfile(ti, src_fh)
                else:
                    raise SystemExit(f"FORBIDDEN_SPECIAL_FILE_IN_STAGE: {full}")
PY

echo "[package-release-archive] packaged ${OUT_ARCHIVE} (${PKG_NAME})"
