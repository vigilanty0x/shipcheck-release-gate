#!/usr/bin/env python3
"""Run the Shipcheck source, package, and installed-artifact release gate."""

from __future__ import annotations

import argparse
import compileall
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
REQUIRED = {
    "README.md", "LICENSE", "SECURITY.md", "MIGRATION.md", "CHANGELOG.md",
    "docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md", "docs/GOVERNANCE.md",
    "docs/TRUST_AND_CI.md", "docs/ADAPTERS.md", ".github/workflows/ci.yml",
}


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> bytes:
    completed = subprocess.run(command, cwd=cwd, env=env, check=True, stdout=subprocess.PIPE)
    return completed.stdout


def source_env() -> dict[str, str]:
    environment = os.environ.copy()
    previous = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(SOURCE) if not previous else str(SOURCE) + os.pathsep + previous
    return environment


def validate_public_json() -> int:
    paths = sorted((SOURCE / "shipcheck" / "public_schemas").glob("*.json"))
    paths.append(SOURCE / "shipcheck" / "compatibility.json")
    if len(paths) < 6:
        raise RuntimeError("public schema/compatibility files are missing")
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_no_duplicate_pairs)
        if not isinstance(value, dict) or "schema_version" not in value and "$schema" not in value:
            raise RuntimeError(f"invalid public JSON document: {path}")
    return len(paths)


def _no_duplicate_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise RuntimeError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not name.startswith(("/", "\\")) and "\\" not in name and ":" not in name and all(part not in {"", ".", ".."} for part in path.parts)


def build_artifacts(work: Path) -> tuple[Path, Path]:
    copied = work / "source"
    shutil.copytree(
        ROOT,
        copied,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info", "build", "dist", ".git"),
    )
    output = work / "dist"; output.mkdir()
    old = Path.cwd()
    try:
        os.chdir(copied)
        from setuptools import build_meta
        sdist_name = build_meta.build_sdist(str(output))
        wheel_name = build_meta.build_wheel(str(output))
    finally:
        os.chdir(old)
    wheel = output / wheel_name
    sdist = output / sdist_name
    if not wheel.is_file() or not sdist.is_file():
        raise RuntimeError("wheel or sdist build output is missing")
    return wheel, sdist


def package_files() -> dict[str, bytes]:
    root = SOURCE / "shipcheck"
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            result[path.relative_to(SOURCE).as_posix()] = path.read_bytes()
    return result


def verify_wheel(wheel: Path, expected: dict[str, bytes]) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if any(not safe_member(name.rstrip("/")) for name in names if not name.endswith("/")):
            raise RuntimeError("wheel contains an unsafe path")
        for name, body in expected.items():
            if name not in names or archive.read(name) != body:
                raise RuntimeError(f"wheel/source parity failed: {name}")


def verify_sdist(sdist: Path, expected: dict[str, bytes]) -> None:
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        if any(not safe_member(member.name.rstrip("/")) or member.issym() or member.islnk() or member.isdev() for member in members):
            raise RuntimeError("sdist contains an unsafe member")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise RuntimeError("sdist must have one top-level directory")
        prefix = next(iter(roots)) + "/src/"
        by_name = {member.name: member for member in members if member.isfile()}
        for name, body in expected.items():
            member = by_name.get(prefix + name)
            extracted = archive.extractfile(member) if member is not None else None
            if extracted is None or extracted.read() != body:
                raise RuntimeError(f"sdist/source parity failed: {name}")


def installed_gate(wheel: Path, work: Path, source_capabilities: bytes, source_selftest: bytes, *, tests_root: Path, name: str) -> None:
    environment = work / name
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", str(wheel)], cwd=work)
    clean_env = os.environ.copy(); clean_env.pop("PYTHONPATH", None)
    installed_capabilities = run([str(python), "-m", "shipcheck", "capabilities"], cwd=work, env=clean_env)
    installed_selftest = run([str(python), "-m", "shipcheck", "selftest"], cwd=work, env=clean_env)
    if installed_capabilities != source_capabilities:
        raise RuntimeError("installed/source capability contract differs")
    if installed_selftest != source_selftest:
        raise RuntimeError("installed/source selftest differs")
    run(
        [str(python), "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
        cwd=tests_root,
        env=clean_env,
    )


def extract_and_rebuild_sdist(sdist: Path, work: Path) -> tuple[Path, Path]:
    destination = work / "sdist-source"; destination.mkdir()
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        if any(not safe_member(member.name.rstrip("/")) or member.issym() or member.islnk() or member.isdev() for member in members):
            raise RuntimeError("sdist contains an unsafe member")
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(f"sdist member cannot be read: {member.name}")
                target.write_bytes(source.read())
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("sdist extraction did not produce one project root")
    rebuilt = work / "sdist-wheel"; rebuilt.mkdir()
    old = Path.cwd()
    try:
        os.chdir(roots[0])
        from setuptools import build_meta
        wheel_name = build_meta.build_wheel(str(rebuilt))
    finally:
        os.chdir(old)
    return rebuilt / wheel_name, roots[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true", help="run source checks only")
    args = parser.parse_args(argv)
    missing = sorted(path for path in REQUIRED if not (ROOT / path).is_file())
    if missing:
        raise RuntimeError("required project files missing: " + ", ".join(missing))
    if not compileall.compile_dir(SOURCE, quiet=1, force=True):
        raise RuntimeError("source compilation failed")
    json_count = validate_public_json()
    env = source_env()
    run([sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", ".", "-v"], env=env)
    source_capabilities = run([sys.executable, "-m", "shipcheck", "capabilities"], env=env)
    source_selftest = run([sys.executable, "-m", "shipcheck", "selftest"], env=env)
    json.loads(source_capabilities); json.loads(source_selftest)
    built = []
    if not args.skip_build:
        with tempfile.TemporaryDirectory(prefix="shipcheck-check-") as directory:
            work = Path(directory)
            wheel, sdist = build_artifacts(work)
            expected = package_files()
            verify_wheel(wheel, expected); verify_sdist(sdist, expected)
            installed_gate(wheel, work, source_capabilities, source_selftest, tests_root=ROOT, name="wheel-venv")
            sdist_wheel, sdist_root = extract_and_rebuild_sdist(sdist, work)
            sdist_env = os.environ.copy()
            sdist_env["PYTHONPATH"] = str(sdist_root / "src")
            run(
                [sys.executable, "scripts/check.py", "--skip-build"],
                cwd=sdist_root,
                env=sdist_env,
            )
            verify_wheel(sdist_wheel, expected)
            installed_gate(sdist_wheel, work, source_capabilities, source_selftest, tests_root=sdist_root, name="sdist-venv")
            built = [wheel.name, sdist.name, f"sdist-rebuilt:{sdist_wheel.name}"]
    print(json.dumps({
        "schema_version": "shipcheck/check-v1", "ok": True,
        "tests": "unittest-discover", "public_json_documents": json_count,
        "built_artifacts": built, "source_wheel_sdist_parity": not args.skip_build,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
