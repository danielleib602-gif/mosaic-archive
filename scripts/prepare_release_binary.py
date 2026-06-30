"""Give a native executable a portable name and verify that it starts."""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
from pathlib import Path


def _normalized_architecture() -> str:
    architecture = platform.machine().lower().replace("amd64", "x86_64")
    return architecture.replace("aarch64", "arm64") or "unknown"


def prepare_binary(source: Path, output_dir: Path, expected_version: str) -> Path:
    if platform.system() == "Windows" and source.suffix.lower() != ".exe":
        source = source.with_suffix(".exe")
    if not source.is_file():
        raise FileNotFoundError(f"built executable not found: {source}")

    suffix = ".exe" if platform.system() == "Windows" else ""
    system = platform.system().lower()
    target = output_dir / f"msc-{system}-{_normalized_architecture()}{suffix}"
    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)

    completed = subprocess.run(
        [str(target.resolve()), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    actual = completed.stdout.strip()
    expected = f"msc {expected_version}"
    if actual != expected:
        raise RuntimeError(f"unexpected executable version: {actual!r}, expected {expected!r}")
    print(f"Verified {target}: {actual}")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--expected-version", required=True)
    arguments = parser.parse_args()
    prepare_binary(arguments.source, arguments.output_dir, arguments.expected_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
