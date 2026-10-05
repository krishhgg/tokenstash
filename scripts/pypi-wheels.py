#!/usr/bin/env python3
"""Repack the release tarballs into platform wheels so `pipx install tokenstash` /
`uv tool install tokenstash` work. No Python code ships: the wheel carries only the binary
under `tokenstash-<version>.data/scripts/`, which installers place on PATH with the exec
bit. macOS wheels are tagged per arch; Linux wheels carry manylinux + musllinux tags (static).

    scripts/pypi-wheels.py <version> <dir-with-tokenstash-*.tar.gz> <out-dir>
"""
import base64, hashlib, os, re, struct, sys, tarfile, zipfile

# Linux binaries are static, so they need nothing from the platform: tag them for glibc
# (manylinux_2_17 is the floor old pips accept) AND musl in one compressed tag set, the way
# ruff/uv ship. pip on a glibc system refuses a musllinux-only wheel even though the binary runs.
PLATFORMS = {
    "linux-x64": "manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64",
    "linux-arm64": "manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64",
    "darwin-x64": "macosx_10_12_x86_64",
    "darwin-arm64": "macosx_11_0_arm64",
}
NAME = "tokenstash"

# (magic check) → the tarball for a platform must hold a binary of that platform; the
# fixtures used to test this script are identical across platforms, so nothing else would
# catch a mix-up.
def check_arch(name, blob):
    ok = False
    if name.startswith("linux") and blob[:4] == b"\x7fELF":
        machine = struct.unpack("<H", blob[18:20])[0]
        ok = machine == {"linux-x64": 0x3E, "linux-arm64": 0xB7}[name]
    elif name.startswith("darwin") and blob[:4] == b"\xcf\xfa\xed\xfe":
        cputype = struct.unpack("<I", blob[4:8])[0]
        ok = cputype == {"darwin-x64": 0x01000007, "darwin-arm64": 0x0100000C}[name]
    if not ok:
        sys.exit(f"tokenstash-{name}.tar.gz does not contain a {name} binary")

def pep440(version):
    """Tag versions are semver (0.3.0-rc.1); wheels need PEP 440 (0.3.0rc1)."""
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(rc|a|b|alpha|beta)\.?(\d+))?", version)
    if not m:
        sys.exit(f"version {version!r} is not X.Y.Z or X.Y.Z-rc.N")
    base, kind, n = m.groups()
    kind = {"alpha": "a", "beta": "b"}.get(kind, kind)
    return base if not kind else f"{base}{kind}{n}"

# One implementation, shared with the npm packager: two copies drifting apart is how one
# registry ends up with working links and the other with 404s.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from importlib import import_module  # noqa: E402

absolute_links = import_module("absolute-links").absolute_links

def metadata(version, readme):
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {NAME}\n"
        f"Version: {version}\n"
        "Summary: Credential broker for coding agents: paste a key once, approve each directory, keep secrets out of status output.\n"
        "Home-page: https://github.com/krishhgg/tokenstash\n"
        "Author: Krish Garg\n"
        "License: MIT\n"
        "Project-URL: Repository, https://github.com/krishhgg/tokenstash\n"
        "Project-URL: Changelog, https://github.com/krishhgg/tokenstash/blob/main/CHANGELOG.md\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
        "Classifier: Environment :: Console\n"
        "Classifier: Topic :: Security\n"
        "Requires-Python: >=3.8\n"
        "Description-Content-Type: text/markdown\n\n" + absolute_links(readme)
    )

def build(version, src, out, readme, license_text):
    os.makedirs(out, exist_ok=True)
    for name, tag in PLATFORMS.items():
        tar = os.path.join(src, f"tokenstash-{name}.tar.gz")
        with tarfile.open(tar) as t:
            member = t.extractfile("tokenstash")
            if member is None:
                sys.exit(f"{tar} has no 'tokenstash' member")
            binary = member.read()
        check_arch(name, binary)
        distinfo = f"{NAME}-{version}.dist-info"
        data = f"{NAME}-{version}.data"
        files = [
            (f"{data}/scripts/tokenstash", binary, 0o755),
            (f"{distinfo}/METADATA", metadata(version, readme).encode(), 0o644),
            (f"{distinfo}/WHEEL", (
                "Wheel-Version: 1.0\nGenerator: tokenstash-release\nRoot-Is-Purelib: false\n"
                + "".join(f"Tag: py3-none-{t}\n" for t in tag.split("."))).encode(), 0o644),
            (f"{distinfo}/LICENSE", license_text.encode(), 0o644),
            (f"{distinfo}/top_level.txt", b"", 0o644),
        ]
        record = []
        path = os.path.join(out, f"{NAME}-{version}-py3-none-{tag}.whl")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for arc, blob, mode in files:
                info = zipfile.ZipInfo(arc, date_time=(1980, 1, 1, 0, 0, 0))
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, blob)
                digest = base64.urlsafe_b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()
                record.append(f"{arc},sha256={digest},{len(blob)}")
            record.append(f"{distinfo}/RECORD,,")
            info = zipfile.ZipInfo(f"{distinfo}/RECORD", date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | 0o644) << 16
            z.writestr(info, "\n".join(record) + "\n")
        print(path)

if __name__ == "__main__":
    version, src, out = sys.argv[1:4]
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
    with open(os.path.join(root, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    with open(os.path.join(root, "LICENSE"), encoding="utf-8") as f:
        license_text = f.read()
    build(pep440(version), src, out, readme, license_text)
