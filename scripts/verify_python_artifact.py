from __future__ import annotations

import argparse
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath


def _normalized_names(names: Iterable[str]) -> frozenset[str]:
    return frozenset(name.replace("\\", "/").lstrip("./") for name in names)


def _require_suffix(names: frozenset[str], suffix: str) -> None:
    normalized_suffix = suffix.lstrip("/")
    if not any(
        name == normalized_suffix or name.endswith(f"/{normalized_suffix}") for name in names
    ):
        raise ValueError(f"artifact is missing required member: {suffix}")


def _validate_names(names: Iterable[str], *, wheel: bool) -> None:
    normalized = _normalized_names(names)
    if not any(PurePosixPath(name).name == "LICENSE" for name in normalized):
        raise ValueError("artifact is missing the MIT LICENSE notice")

    if wheel:
        for required in (
            "mosaic_archive/native_preview.py",
            "mosaic_archive/_native.pyi",
            "mosaic_archive/py.typed",
        ):
            _require_suffix(normalized, required)
        if not any(
            name.startswith("mosaic_archive/_native") and name.endswith((".pyd", ".so"))
            for name in normalized
        ):
            raise ValueError("wheel is missing the native ABI3 extension")
        return

    for required in (
        "Cargo.toml",
        "Cargo.lock",
        "native/msc7-core/Cargo.toml",
        "native/msc7-python/Cargo.toml",
        "src/mosaic_archive/native_preview.py",
    ):
        _require_suffix(normalized, required)
    if any("/.git/" in f"/{name}/" or "/target/" in f"/{name}/" for name in normalized):
        raise ValueError("source distribution contains a build or VCS directory")


def verify_artifact(path: Path) -> None:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            _validate_names(archive.namelist(), wheel=True)
        return
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            _validate_names((member.name for member in archive.getmembers()), wheel=False)
        return
    raise ValueError(f"unsupported Python artifact: {path.name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", type=Path, nargs="+")
    arguments = parser.parse_args(argv)
    for artifact in arguments.artifacts:
        verify_artifact(artifact)
        print(f"verified Python artifact: {artifact.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
