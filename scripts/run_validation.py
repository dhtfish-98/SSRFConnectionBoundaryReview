#!/usr/bin/env python3
"""Build and exercise this version using only a caller-chosen Build directory."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT = "SSRFConnectionBoundaryReview"
VERSION = "0.1.0"
AUTHOR = "dhtfish98"
EXPECTED_TESTS = 14
EXPECTED_SCENARIOS = 10
BUILD_TOOLS = ("build==1.6.1", "setuptools==84.0.0", "wheel==0.48.0")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(
    args: list[str],
    *,
    cwd: pathlib.Path,
    env: dict[str, str],
    log: pathlib.Path,
) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(completed.stdout, encoding="utf-8")
    if completed.returncode:
        raise RuntimeError(f"{args[0]} exited {completed.returncode}; inspect {log}")
    return completed.stdout


def source_inventory() -> tuple[list[str], bytes]:
    manifest_path = ROOT / "项目文档/SOURCE_MANIFEST.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if (
        manifest.get("version") != VERSION
        or manifest.get("author") != AUTHOR
        or manifest.get("cvp_qualification") != "OPEN"
    ):
        raise RuntimeError("source manifest identity or CVP scope mismatch")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise RuntimeError("source manifest files missing")
    paths: list[str] = []
    for entry in entries:
        name = entry["path"]
        rel = pathlib.PurePosixPath(name)
        if rel.is_absolute() or ".." in rel.parts or name == "项目文档/SOURCE_MANIFEST.json":
            raise RuntimeError(f"invalid source manifest path: {name}")
        path = ROOT / name
        data = path.read_bytes()
        if entry["bytes"] != len(data) or entry["sha256"] != digest(data):
            raise RuntimeError(f"source manifest mismatch: {name}")
        paths.append(name)
    if len(paths) != len(set(paths)):
        raise RuntimeError("duplicate source manifest path")
    paths.append("项目文档/SOURCE_MANIFEST.json")

    actual: set[str] = set()
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            if name == ".git":
                continue
            actual.add((pathlib.Path(base) / name).relative_to(ROOT).as_posix())
    if actual != set(paths):
        raise RuntimeError(f"source-only file set mismatch: extra={sorted(actual-set(paths))}; missing={sorted(set(paths)-actual)}")
    return sorted(paths), manifest_bytes


def unpack_sdist(archive: pathlib.Path, target: pathlib.Path) -> pathlib.Path:
    with tarfile.open(archive, "r:gz") as package:
        for member in package.getmembers():
            rel = pathlib.PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts or member.issym() or member.islnk():
                raise RuntimeError(f"unsafe source archive member: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError(f"unsupported source archive member: {member.name}")
            payload = package.extractfile(member)
            if payload is None:
                raise RuntimeError(f"unreadable source archive member: {member.name}")
            dest = target.joinpath(*rel.parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload.read())
    return target / "ssrf_connection_boundary_review-0.1.0"


def compare_sdist(archive: pathlib.Path, paths: list[str]) -> None:
    prefix = "ssrf_connection_boundary_review-0.1.0/"
    with tarfile.open(archive, "r:gz") as package:
        members = {m.name[len(prefix) :]: m for m in package if m.isfile() and m.name.startswith(prefix)}
        for name in paths:
            member = members.get(name)
            if member is None:
                raise RuntimeError(f"source archive missing {name}")
            payload = package.extractfile(member)
            if payload is None or payload.read() != (ROOT / name).read_bytes():
                raise RuntimeError(f"source archive differs from reviewed source: {name}")
        if any(name.endswith((".pyc", ".so", ".dylib", ".dll", ".exe")) for name in members):
            raise RuntimeError("source archive contains build output")


def compare_wheel(archive: pathlib.Path) -> None:
    runtime_paths = sorted(
        p.relative_to(ROOT / "src").as_posix()
        for p in (ROOT / "src/ssrf_connection_boundary_review").glob("*.py")
    )
    if len(runtime_paths) != 5:
        raise RuntimeError("unexpected runtime module count")
    with zipfile.ZipFile(archive) as wheel:
        names = set(wheel.namelist())
        if {name for name in names if name.endswith(".py")} != set(runtime_paths):
            raise RuntimeError("wheel runtime file set mismatch")
        for name in runtime_paths:
            if wheel.read(name) != (ROOT / "src" / name).read_bytes():
                raise RuntimeError(f"wheel runtime bytes mismatch: {name}")
        licenses = [name for name in names if name.endswith("/licenses/项目文档/LICENSE")]
        if len(licenses) != 1 or wheel.read(licenses[0]) != (ROOT / "项目文档/LICENSE").read_bytes():
            raise RuntimeError("wheel self-owned license missing")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise RuntimeError("wheel metadata missing")
        metadata = wheel.read(metadata_names[0]).decode("utf-8")
        if (
            f"Version: {VERSION}" not in metadata
            or f"Author: {AUTHOR}" not in metadata
            or "License-Expression: MIT" not in metadata
        ):
            raise RuntimeError("wheel version, author or license mismatch")


def verify_tests(text: str) -> int:
    match = re.search(r"Ran (\d+) tests? in ", text)
    if match is None or int(match.group(1)) != EXPECTED_TESTS or not text.rstrip().endswith("OK"):
        raise RuntimeError("real loopback test count or result mismatch")
    return int(match.group(1))


def verify_experiment(path: pathlib.Path) -> dict[str, object]:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if (
        receipt.get("project_version") != VERSION
        or receipt.get("pass_count") != EXPECTED_SCENARIOS
        or receipt.get("cvp_qualification") != "OPEN"
        or receipt.get("upstream_vulnerability_claim") is not False
    ):
        raise RuntimeError(f"experiment identity, count or scope mismatch: {path}")
    if any(row["role"] == "internal" for row in receipt["http_requests"]):
        raise RuntimeError("fake internal HTTP endpoint received a request")
    scenarios = receipt["scenarios"]
    for name in (
        "slow_drip_whole_fetch_deadline",
        "redirects_share_whole_fetch_deadline",
        "retries_share_whole_fetch_deadline",
    ):
        if scenarios[name]["outcome"] != "DEADLINE_EXCEEDED":
            raise RuntimeError(f"whole-fetch deadline did not close {name}")
    return receipt


def git_commit() -> str | None:
    if not (ROOT / ".git").exists():
        return None
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", required=True, type=pathlib.Path)
    args = parser.parse_args()
    build_root = args.build_root
    if not build_root.is_absolute():
        raise SystemExit("--build-root must be an absolute path outside the project source directory")
    build_root = build_root.resolve()
    if (
        "Build" not in build_root.parts
        or build_root.name == "Build"
        or build_root == ROOT
        or build_root.is_relative_to(ROOT)
    ):
        raise SystemExit("--build-root must be a new directory under an external Build directory")
    if build_root.exists() and any(build_root.iterdir()):
        raise SystemExit(f"refusing to reuse a nonempty build root: {build_root}")
    build_root.mkdir(parents=True, exist_ok=True)
    (build_root / "tmp").mkdir()
    (build_root / "logs").mkdir()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(
        {
            "PYTHONPYCACHEPREFIX": str(build_root / "pycache"),
            "PIP_CACHE_DIR": str(build_root / "pip-cache"),
            "TMPDIR": str(build_root / "tmp"),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )

    paths, manifest_bytes = source_inventory()
    run(
        [sys.executable, "-m", "venv", str(build_root / "venv")],
        cwd=ROOT,
        env=env,
        log=build_root / "logs/venv.log",
    )
    python = build_root / "venv/bin/python"
    run(
        [str(python), "-m", "pip", "install", *BUILD_TOOLS],
        cwd=ROOT,
        env=env,
        log=build_root / "logs/build-tools.log",
    )

    source_env = env | {"PYTHONPATH": str(ROOT / "src")}
    source_tests = verify_tests(
        run(
            [str(python), "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=ROOT,
            env=source_env,
            log=build_root / "logs/tests-source.log",
        )
    )
    run(
        [
            str(python),
            "-m",
            "ssrf_connection_boundary_review.experiment",
            "--output",
            str(build_root / "source_experiment.json"),
        ],
        cwd=ROOT,
        env=source_env,
        log=build_root / "logs/source-experiment.log",
    )
    source_experiment = verify_experiment(build_root / "source_experiment.json")

    stage = build_root / "stage"
    for name in paths:
        dest = stage / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    run(
        [str(python), "-m", "build", "--no-isolation", "--outdir", str(build_root / "dist"), str(stage)],
        cwd=build_root,
        env=env,
        log=build_root / "logs/build.log",
    )
    dist = build_root / "dist"
    sdists = list(dist.glob("ssrf_connection_boundary_review-0.1.0.tar.gz"))
    wheels = list(dist.glob("ssrf_connection_boundary_review-0.1.0-py3-none-any.whl"))
    if len(sdists) != 1 or len(wheels) != 1 or len(list(dist.iterdir())) != 2:
        raise RuntimeError("built artifact set mismatch")
    sdist, wheel = sdists[0], wheels[0]
    compare_sdist(sdist, paths)
    compare_wheel(wheel)

    unpacked = unpack_sdist(sdist, build_root / "unpacked")
    sdist_env = env | {"PYTHONPATH": str(unpacked / "src")}
    sdist_tests = verify_tests(
        run(
            [str(python), "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=unpacked,
            env=sdist_env,
            log=build_root / "logs/tests-sdist.log",
        )
    )

    installed = build_root / "installed"
    run(
        [str(python), "-m", "pip", "install", "--no-deps", "--no-compile", "--target", str(installed), str(wheel)],
        cwd=build_root,
        env=env,
        log=build_root / "logs/install-wheel.log",
    )
    wheel_env = env | {"PYTHONPATH": str(installed)}
    imported_path = run(
        [
            str(python),
            "-c",
            "import ssrf_connection_boundary_review as p; print(p.__file__)",
        ],
        cwd=build_root,
        env=wheel_env,
        log=build_root / "logs/installed-import.log",
    ).strip()
    if not pathlib.Path(imported_path).resolve().is_relative_to(installed):
        raise RuntimeError("isolated test imported source instead of installed wheel")
    wheel_tests = verify_tests(
        run(
            [str(python), "-m", "unittest", "discover", "-s", str(ROOT / "tests"), "-v"],
            cwd=build_root,
            env=wheel_env,
            log=build_root / "logs/tests-wheel.log",
        )
    )
    run(
        [
            str(python),
            "-m",
            "ssrf_connection_boundary_review.experiment",
            "--output",
            str(build_root / "wheel_experiment.json"),
        ],
        cwd=build_root,
        env=wheel_env,
        log=build_root / "logs/wheel-experiment.log",
    )
    wheel_experiment = verify_experiment(build_root / "wheel_experiment.json")

    commit = git_commit()
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha and commit != github_sha:
        raise RuntimeError("CI checkout SHA does not match GITHUB_SHA")
    artifacts = [
        {"file": f"dist/{path.name}", "bytes": path.stat().st_size, "sha256": digest(path.read_bytes())}
        for path in (sdist, wheel)
    ]
    (build_root / "SHA256SUMS").write_text(
        "".join(f"{item['sha256']}  {item['file']}\n" for item in artifacts),
        encoding="utf-8",
    )
    receipt = {
        "schema": "ssrf-connection-boundary-validation-v1",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "project": PROJECT,
        "version": VERSION,
        "author": AUTHOR,
        "status": "PASS_BOUNDED_LAB",
        "python_version": sys.version.split()[0],
        "source_commit": commit,
        "github_sha": github_sha,
        "source_file_count": len(paths),
        "source_manifest_sha256": digest(manifest_bytes),
        "build_tools": list(BUILD_TOOLS),
        "source_tests": source_tests,
        "sdist_tests": sdist_tests,
        "wheel_tests": wheel_tests,
        "source_scenarios": source_experiment["pass_count"],
        "wheel_scenarios": wheel_experiment["pass_count"],
        "fake_internal_http_requests": 0,
        "network_scope": "synthetic 127.0.0.1 UDP/TCP and ::1 TCP only",
        "artifacts": artifacts,
        "open": ["real_authorized_target_evidence", "safeguard_impact_outside_lab", "CVP_eligibility_or_approval"],
    }
    (build_root / "validation.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": receipt["status"], "version": VERSION, "source_tests": source_tests, "sdist_tests": sdist_tests, "wheel_tests": wheel_tests, "scenarios": receipt["source_scenarios"], "receipt": str(build_root / "validation.json")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
