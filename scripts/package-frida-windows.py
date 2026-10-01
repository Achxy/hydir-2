#!/usr/bin/env python3
"""Build a WSL2 worker rootfs on Linux, then bundle it with the Windows desktop."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FRIDA_VERSION = "17.9.5"
WORKER_FILES = {"rootfs.tar.gz", "manifest.json"}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def verify_worker(directory):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    expected = {"schema_version": 1, "target": "windows-wsl2-x86_64",
                "protocol_version": 1, "frida_version": FRIDA_VERSION}
    if set(manifest) != set(expected) | {"rootfs_sha256"} or any(
            manifest.get(key) != value for key, value in expected.items()):
        raise ValueError("incompatible WSL worker manifest")
    if digest(directory / "rootfs.tar.gz") != manifest["rootfs_sha256"]:
        raise ValueError("WSL worker rootfs digest mismatch")
    return manifest


def build_rootfs(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("build-rootfs requires Linux x86-64 and Docker")
    output = args.output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    bundle = args.linux_bundle.resolve()
    # Verify exact archive membership, all hashes, native linkage and Frida version
    # with the existing Linux release verifier before touching the Docker context.
    subprocess.run([sys.executable, str(ROOT / "scripts/package-frida-linux.py"),
                    "verify", str(bundle), "--require-observation-ready"], check=True)
    with tempfile.TemporaryDirectory(prefix="hydir-wsl-build-") as scratch:
        context = Path(scratch)
        with tarfile.open(bundle, "r:gz") as archive:
            archive.extractall(context, filter="data")
        for name in ("Dockerfile.wsl", "wsl.conf"):
            shutil.copyfile(ROOT / "integrations/frida" / name, context / name)
        tag = f"hydir-frida-wsl-build:{uuid.uuid4().hex}"
        container = None
        try:
            subprocess.run(["docker", "build", "--platform", "linux/amd64", "-t", tag,
                            "-f", str(context / "Dockerfile.wsl"), str(context)], check=True)
            container = subprocess.check_output(["docker", "create", tag, "/bin/true"], text=True).strip()
            exported = context / "rootfs.tar"
            subprocess.run(["docker", "export", "--output", str(exported), container], check=True)
            output.mkdir(parents=True)
            with exported.open("rb") as source, (output / "rootfs.tar.gz").open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
                    shutil.copyfileobj(source, compressed)
            (output / "manifest.json").write_text(json.dumps({
                "schema_version": 1, "target": "windows-wsl2-x86_64", "protocol_version": 1,
                "frida_version": FRIDA_VERSION, "rootfs_sha256": digest(output / "rootfs.tar.gz"),
            }, indent=2) + "\n", encoding="utf-8")
            verify_worker(output)
        finally:
            if container:
                subprocess.run(["docker", "rm", container], check=False)
            subprocess.run(["docker", "image", "rm", tag], check=False)
    print(f"WSL worker: {output}")


def package_windows(args):
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("package requires Windows x86-64")
    worker = args.worker_dir.resolve()
    verify_worker(worker)
    output = args.output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    subprocess.run(["cargo", "build", "--locked", "--release", "-p", "hydir-cli", "-p", "hydir-gui"], cwd=ROOT, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    if not target.is_absolute():
        target = ROOT / target
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ("hydir.exe", "hydirctl.exe"):
            archive.write(target / "release" / name, f"hydir-windows-x86_64/{name}")
        archive.write(ROOT / "LICENSE", "hydir-windows-x86_64/LICENSE")
        archive.write(ROOT / "integrations/frida/README.md", "hydir-windows-x86_64/FRIDA-WINDOWS.md")
        for name in sorted(WORKER_FILES):
            archive.write(worker / name, f"hydir-windows-x86_64/workers/frida/{name}", compress_type=zipfile.ZIP_STORED)
    print(f"Windows desktop + Linux Frida worker: {output}")
    print(f"sha256: {digest(output)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    rootfs = commands.add_parser("build-rootfs")
    rootfs.add_argument("--linux-bundle", type=Path, required=True)
    rootfs.add_argument("--output", type=Path, required=True)
    rootfs.set_defaults(action=build_rootfs)
    package = commands.add_parser("package")
    package.add_argument("--worker-dir", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    package.set_defaults(action=package_windows)
    verify = commands.add_parser("verify-worker")
    verify.add_argument("worker_dir", type=Path)
    verify.set_defaults(action=lambda args: print(json.dumps(verify_worker(args.worker_dir))))
    args = parser.parse_args()
    try:
        args.action(args)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f"Frida Windows packaging failed: {error}\n")


if __name__ == "__main__":
    main()
