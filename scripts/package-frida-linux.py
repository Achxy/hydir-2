#!/usr/bin/env python3
"""Build and verify Hydir's Linux x86-64 Frida release without installer downloads."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = "hydir-linux-x86_64"
FRIDA_VERSION = "17.9.5"
DEVKIT_SHA256 = "e98803f6cad21c41a1b67eaa495963955afab6ed7ae95a18dc485ab2188bb021"
FRIDA_COPYING_SHA256 = "5ea1544b51a28bc823b03159190d4108f9fb4f4ef912389f5137c6d295e175b2"
REQUIRED_DEVKIT_FILES = {"libfrida-core.a", "frida-core.h"}
PAYLOAD_FILES = {
    "hydirctl",
    "hydir-frida-observer",
    "LICENSE",
    "licenses/Frida-COPYING",
    "THIRD_PARTY_NOTICES.md",
    "README.txt",
    "manifest.json",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_linux_x86_64():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("the Frida bundle must be built and verified on Linux x86-64")


def check_elf(path):
    with path.open("rb") as source:
        header = source.read(20)
    if (len(header) < 20 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01"
            or struct.unpack_from("<H", header, 18)[0] != 62):
        raise ValueError(f"expected a Linux x86-64 ELF executable: {path}")
    result = subprocess.run(["ldd", str(path)], capture_output=True, text=True, check=False)
    dependencies = result.stdout + result.stderr
    if "not found" in dependencies or "libfrida-core" in dependencies:
        raise ValueError(f"unavailable or external Frida native dependency: {dependencies}")


def checked_devkit(archive_path, directory):
    if sha256_file(archive_path) != DEVKIT_SHA256:
        raise ValueError("Frida 17.9.5 devkit SHA-256 mismatch")
    with tarfile.open(archive_path, mode="r:xz") as archive:
        for member in archive.getmembers():
            name = member.name.removeprefix("./")
            if name in REQUIRED_DEVKIT_FILES and member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"missing Frida devkit member: {name}")
                with (directory / name).open("wb") as destination:
                    shutil.copyfileobj(source, destination)
    if not all((directory / name).is_file() for name in REQUIRED_DEVKIT_FILES):
        raise ValueError("pinned Frida devkit lacks its static library or header")


def run_doctors(directory, require_ready):
    env = os.environ.copy()
    for key in ("CPATH", "RUSTFLAGS", "HYDIR_FRIDA_OBSERVER"):
        env.pop(key, None)
    helper = directory / "hydir-frida-observer"
    check_elf(helper)
    check_elf(directory / "hydirctl")
    result = subprocess.run([str(helper), "--doctor"], env=env, capture_output=True,
                            text=True, timeout=10, check=True)
    helper_report = json.loads(result.stdout)
    if (helper_report.get("frida_version") != FRIDA_VERSION
            or helper_report.get("observer") != "hydir-frida-observer"):
        raise ValueError(f"bundled native Frida version differs from {FRIDA_VERSION}")
    result = subprocess.run([str(directory / "hydirctl"), "doctor"], env=env,
                            capture_output=True, text=True, timeout=45, check=True)
    doctor = json.loads(result.stdout)
    if Path(doctor["frida_observer_helper"]).resolve() != helper.resolve():
        raise ValueError("hydirctl did not locate its colocated Frida helper")
    if require_ready and doctor.get("frida_observation_ready") is not True:
        raise ValueError("installed hydirctl doctor reports Frida observation unavailable")
    return {"frida_version": helper_report["frida_version"],
            "frida_observation_ready": doctor.get("frida_observation_ready")}


def add_file(archive, root, relative):
    path = root / relative
    info = tarfile.TarInfo(f"{PACKAGE_ROOT}/{relative}")
    info.size = path.stat().st_size
    info.mode = 0o755 if relative in {"hydirctl", "hydir-frida-observer"} else 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    with path.open("rb") as source:
        archive.addfile(info, source)


def build(args):
    require_linux_x86_64()
    archive_path = args.devkit_archive.resolve()
    output = args.output.resolve()
    if output.exists():
        raise ValueError(f"release archive already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hydir-frida-package-") as scratch_name:
        scratch = Path(scratch_name)
        devkit = scratch / "devkit"
        devkit.mkdir()
        checked_devkit(archive_path, devkit)
        env = os.environ.copy()
        env["CPATH"] = str(devkit)
        env["RUSTFLAGS"] = f"-L native={devkit}"
        subprocess.run(["cargo", "build", "--locked", "--release", "-p", "hydir-cli",
                        "--bin", "hydirctl"], cwd=ROOT, env=env, check=True)
        subprocess.run(["cargo", "build", "--locked", "--release", "-p",
                        "hydir-frida-observer", "--features", "frida-runtime", "--bin",
                        "hydir-frida-observer"], cwd=ROOT, env=env, check=True)
        target = Path(env.get("CARGO_TARGET_DIR", "target"))
        if not target.is_absolute():
            target = ROOT / target
        release = target / "release"
        bundle = scratch / PACKAGE_ROOT
        bundle.mkdir()
        (bundle / "licenses").mkdir()
        for name in ("hydirctl", "hydir-frida-observer"):
            shutil.copyfile(release / name, bundle / name)
            (bundle / name).chmod(0o755)
            check_elf(bundle / name)
        shutil.copyfile(ROOT / "LICENSE", bundle / "LICENSE")
        frida_copying = ROOT / "vendor/frida-rust-0.17.2/COPYING"
        if sha256(frida_copying.read_bytes()) != FRIDA_COPYING_SHA256:
            raise ValueError("vendored Frida COPYING differs from the pinned upstream text")
        shutil.copyfile(frida_copying, bundle / "licenses/Frida-COPYING")
        (bundle / "THIRD_PARTY_NOTICES.md").write_text(
            "# Third-party notices\n\n"
            "Frida core 17.9.5 is statically linked into hydir-frida-observer from "
            "frida-core-devkit-17.9.5-linux-x86_64.tar.xz. Its upstream COPYING "
            "is included at licenses/Frida-COPYING. The patched frida-rust 0.17.2 "
            "bindings and frida-sys 0.17.2 use the same upstream wxWindows "
            "Library Licence text.\n\n"
            "Frida core: https://github.com/frida/frida-core/tree/17.9.5\n"
            "Frida Rust bindings: https://github.com/frida/frida-rust\n"
            "Hydir source and license: https://github.com/Achxy/hydir-2\n",
            encoding="utf-8",
        )
        (bundle / "README.txt").write_text(
            "Hydir Linux x86-64 Frida bundle\n\n"
            "Run ./hydirctl doctor after extraction. The Frida 17.9.5 native "
            "runtime is statically linked into the adjacent hydir-frida-observer. "
            "Linux Bubblewrap with working user and network namespaces is required "
            "for observation. No Frida devkit, Python package, or network download "
            "is needed after installation.\n",
            encoding="utf-8",
        )
        manifest = {
            "schema_version": 1,
            "target": "linux-x86_64",
            "frida_version": FRIDA_VERSION,
            "frida_rust_version": "0.17.2",
            "frida_devkit_archive_sha256": DEVKIT_SHA256,
            "files_sha256": {
                name: sha256_file(bundle / name)
                for name in sorted(PAYLOAD_FILES - {"manifest.json"})
            },
        }
        (bundle / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with output.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0,
                               compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for name in sorted(PAYLOAD_FILES):
                        add_file(archive, bundle, name)
        print(f"bundle: {output}")
        print(f"sha256: {sha256_file(output)}")


def verify(args):
    require_linux_x86_64()
    with tempfile.TemporaryDirectory(prefix="hydir-frida-install-") as install_name:
        install = Path(install_name)
        with tarfile.open(args.archive, mode="r:gz") as archive:
            members = archive.getmembers()
            expected = {f"{PACKAGE_ROOT}/{name}" for name in PAYLOAD_FILES}
            if {member.name for member in members} != expected or not all(
                    member.isfile() and not member.issym() for member in members):
                raise ValueError("release archive has missing, extra, or non-file members")
            for member in members:
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"cannot extract {member.name}")
                destination = install / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read())
                destination.chmod(member.mode)
        bundle = install / PACKAGE_ROOT
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        if (manifest.get("schema_version") != 1 or manifest.get("target") != "linux-x86_64"
                or manifest.get("frida_version") != FRIDA_VERSION
                or manifest.get("frida_devkit_archive_sha256") != DEVKIT_SHA256):
            raise ValueError("release manifest has an unexpected version or devkit")
        expected_hashes = manifest.get("files_sha256")
        if not isinstance(expected_hashes, dict) or set(expected_hashes) != PAYLOAD_FILES - {
                "manifest.json"}:
            raise ValueError("release manifest file set is incomplete")
        for name, expected in expected_hashes.items():
            if sha256_file(bundle / name) != expected:
                raise ValueError(f"release file digest mismatch: {name}")
        if sha256((bundle / "licenses/Frida-COPYING").read_bytes()) != FRIDA_COPYING_SHA256:
            raise ValueError("release omits the pinned Frida license text")
        print(json.dumps(run_doctors(bundle, args.require_observation_ready), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="build and archive the pinned release")
    build_parser.add_argument("--devkit-archive", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.set_defaults(action=build)
    verify_parser = commands.add_parser("verify", help="install and test the archive offline")
    verify_parser.add_argument("archive", type=Path)
    verify_parser.add_argument("--require-observation-ready", action="store_true")
    verify_parser.set_defaults(action=verify)
    args = parser.parse_args()
    try:
        args.action(args)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f"Frida release bundle failed: {error}\n")


if __name__ == "__main__":
    main()
