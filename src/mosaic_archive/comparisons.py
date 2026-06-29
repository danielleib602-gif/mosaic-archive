"""Optional benchmark adapters for common mature archive tools."""

from __future__ import annotations

import gzip
import hashlib
import shutil
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    available: bool
    supported: bool
    archive_size: int | None
    ratio: float | None
    encode_seconds: float | None
    decode_seconds: float | None
    verified: bool | None
    note: str


def _digest(path: Path) -> bytes:
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        return digest.digest()
    for entry in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = entry.relative_to(path).as_posix().encode("utf-8")
        digest.update(b"D" if entry.is_dir() else b"F")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        if entry.is_file():
            with entry.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
    return digest.digest()


def _total_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(entry.stat().st_size for entry in path.rglob("*") if entry.is_file())


def _result(
    archive: Path,
    original_size: int,
    encode_seconds: float,
    decode_seconds: float,
    verified: bool,
    note: str,
) -> ComparisonResult:
    archive_size = archive.stat().st_size
    return ComparisonResult(
        available=True,
        supported=True,
        archive_size=archive_size,
        ratio=archive_size / original_size if original_size else 0.0,
        encode_seconds=encode_seconds,
        decode_seconds=decode_seconds,
        verified=verified,
        note=note,
    )


def _compare_zip(source: Path, root: Path) -> ComparisonResult:
    archive = root / "comparison.zip"
    restored = root / "zip-restored"
    started = time.perf_counter()
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as output:
        if source.is_file():
            output.write(source, source.name)
        else:
            for entry in sorted(
                source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()
            ):
                relative = entry.relative_to(source).as_posix()
                output.write(entry, relative + ("/" if entry.is_dir() else ""))
    encode_seconds = time.perf_counter() - started

    restored.mkdir()
    started = time.perf_counter()
    with zipfile.ZipFile(archive, "r") as compressed:
        compressed.extractall(restored)
    decode_seconds = time.perf_counter() - started
    restored_input = restored / source.name if source.is_file() else restored
    return _result(
        archive,
        _total_size(source),
        encode_seconds,
        decode_seconds,
        _digest(source) == _digest(restored_input),
        "ZIP_DEFLATED level 6; compression only, no encryption",
    )


def _compare_gzip(source: Path, root: Path) -> ComparisonResult:
    if not source.is_file():
        return ComparisonResult(
            True, False, None, None, None, None, None, "gzip does not archive folders"
        )
    archive = root / "comparison.gz"
    restored = root / "gzip-restored"
    started = time.perf_counter()
    with source.open("rb") as input_stream, gzip.open(archive, "wb", compresslevel=6) as output:
        shutil.copyfileobj(input_stream, output)
    encode_seconds = time.perf_counter() - started
    started = time.perf_counter()
    with gzip.open(archive, "rb") as input_stream, restored.open("wb") as output:
        shutil.copyfileobj(input_stream, output)
    decode_seconds = time.perf_counter() - started
    return _result(
        archive,
        source.stat().st_size,
        encode_seconds,
        decode_seconds,
        _digest(source) == _digest(restored),
        "gzip level 6; compression only, no encryption",
    )


def _run(command: list[str], *, cwd: Path) -> float:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode(errors="replace").strip()
        raise OSError(message or f"command exited with status {completed.returncode}")
    return time.perf_counter() - started


def _compare_zstd(source: Path, root: Path) -> ComparisonResult:
    executable = shutil.which("zstd")
    if executable is None:
        return ComparisonResult(
            False, False, None, None, None, None, None, "zstd executable not found"
        )
    if not source.is_file():
        return ComparisonResult(
            True, False, None, None, None, None, None, "zstd requires a tar layer for folders"
        )
    archive = root / "comparison.zst"
    restored = root / "zstd-restored"
    encode_seconds = _run(
        [executable, "-q", "-f", str(source), "-o", str(archive)], cwd=root
    )
    decode_seconds = _run(
        [executable, "-q", "-d", "-f", str(archive), "-o", str(restored)], cwd=root
    )
    return _result(
        archive,
        source.stat().st_size,
        encode_seconds,
        decode_seconds,
        _digest(source) == _digest(restored),
        "zstd default level; compression only, no encryption",
    )


def _compare_7z(source: Path, root: Path) -> ComparisonResult:
    executable = next(
        (candidate for name in ("7z", "7zz", "7za") if (candidate := shutil.which(name))),
        None,
    )
    if executable is None:
        return ComparisonResult(
            False, False, None, None, None, None, None, "7-Zip executable not found"
        )
    archive = root / "comparison.7z"
    restored_root = root / "7z-restored"
    restored_root.mkdir()
    encode_seconds = _run(
        [executable, "a", "-bd", "-y", str(archive), source.name],
        cwd=source.parent,
    )
    decode_seconds = _run(
        [executable, "x", "-bd", "-y", f"-o{restored_root}", str(archive)],
        cwd=root,
    )
    restored = restored_root / source.name
    return _result(
        archive,
        _total_size(source),
        encode_seconds,
        decode_seconds,
        _digest(source) == _digest(restored),
        "7z defaults; compression only, no encryption",
    )


def compare_common_tools(source: Path, root: Path) -> dict[str, ComparisonResult]:
    root.mkdir(parents=True, exist_ok=True)
    comparisons: dict[str, ComparisonResult] = {}
    for name, adapter in (
        ("zip", _compare_zip),
        ("gzip", _compare_gzip),
        ("zstd", _compare_zstd),
        ("7z", _compare_7z),
    ):
        try:
            adapter_root = root / name
            adapter_root.mkdir()
            comparisons[name] = adapter(source, adapter_root)
        except (OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
            comparisons[name] = ComparisonResult(
                True,
                True,
                None,
                None,
                None,
                None,
                False,
                f"comparison failed: {error}",
            )
    return comparisons
