"""Deterministic, redistributable benchmark corpus generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import struct
import zlib
from pathlib import Path
from typing import Any

CORPUS_VERSION = 2
DEFAULT_SEED = 20260629
DEFAULT_UNIT_SIZE = 64 * 1024
MANIFEST_NAME = "manifest.json"
CORPUS_MTIME_NS = 1_700_000_000_000_000_000


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repeat_to_size(fragment: bytes, size: int) -> bytes:
    repeats = (size + len(fragment) - 1) // len(fragment)
    return (fragment * repeats)[:size]


def _structured_events(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    output = bytearray()
    index = 0
    levels = ("debug", "info", "warning", "error")
    while len(output) < size:
        event = {
            "duration_ms": rng.randrange(1, 5000),
            "event_id": index,
            "level": levels[index % len(levels)],
            "message": f"mosaic archive event {index % 97}",
            "user_id": rng.randrange(1, 1000),
        }
        output.extend(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        output.append(10)
        index += 1
    return bytes(output[:size])


def _numeric_ramp(size: int) -> bytes:
    count = max(1, (size + 3) // 4)
    data = b"".join(struct.pack("<i", index * 3 - 100_000) for index in range(count))
    return data[:size]


def _sparse_measurements(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    data = bytearray(size)
    for offset in range(0, size, 4096):
        sample = rng.randbytes(min(32, size - offset))
        data[offset : offset + len(sample)] = sample
    return bytes(data)


def _tabular_measurements(size: int) -> bytes:
    output = bytearray(b"timestamp,sensor_id,temperature,pressure,status\n")
    index = 0
    while len(output) < size:
        output.extend(
            (
                f"2026-06-29T12:{index % 60:02d}:{(index * 7) % 60:02d}Z,"
                f"sensor-{index % 23:02d},{18 + (index % 17) / 10:.1f},"
                f"{990 + index % 31},"
                f"{'ok' if index % 19 else 'calibrating'}\n"
            ).encode("ascii")
        )
        index += 1
    return bytes(output[:size])


def _rgba_gradient(size: int) -> bytes:
    output = bytearray()
    pixel = 0
    while len(output) < size:
        x = pixel % 256
        y = (pixel // 256) % 256
        output.extend((x, y, (x + y) // 2, 255))
        pixel += 1
    return bytes(output[:size])


def _valid_utf8_to_size(fragment: str, size: int) -> bytes:
    encoded = fragment.encode("utf-8")
    repeats = size // len(encoded)
    result = encoded * repeats
    return result + (b" " * (size - len(result)))


def generate_corpus(
    root: Path,
    *,
    seed: int = DEFAULT_SEED,
    unit_size: int = DEFAULT_UNIT_SIZE,
    corpus_version: int = CORPUS_VERSION,
) -> dict[str, Any]:
    """Create a deterministic multi-category corpus and return its manifest."""
    if not 1024 <= unit_size <= 16 * 1024 * 1024:
        raise ValueError("unit size must be between 1 KiB and 16 MiB")
    if corpus_version not in {1, 2}:
        raise ValueError("corpus version must be 1 or 2")
    if root.exists():
        if not root.is_dir():
            raise FileExistsError(f"corpus destination is not a directory: {root}")
        if any(root.iterdir()):
            raise FileExistsError(f"corpus destination is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    random_bytes = rng.randbytes(unit_size * 2)
    base = rng.randbytes(unit_size * 2)
    prose = _repeat_to_size(
        (
            b"Compression is prediction. Mosaic chooses the cheapest useful "
            b"description for each local region of a general-purpose archive.\n"
        ),
        unit_size * 2,
    )
    files: list[tuple[str, str, bytes]] = [
        ("text/prose.txt", "text", prose),
        (
            "structured/events.jsonl",
            "structured",
            _structured_events(seed + 1, unit_size * 2),
        ),
        ("numeric/ramp-i32le.bin", "numeric", _numeric_ramp(unit_size * 2)),
        ("dedup/base.bin", "dedup", base),
        ("dedup/copy.bin", "dedup", base),
        ("dedup/shifted.bin", "dedup", b"inserted-prefix\n" + base),
        ("random/random.bin", "random", random_bytes),
        (
            "precompressed/random.zlib",
            "precompressed",
            zlib.compress(random_bytes, level=9),
        ),
        ("empty/empty.bin", "empty", b""),
    ]
    if corpus_version >= 2:
        files.extend(
            [
                (
                    "source/parser.py",
                    "source",
                    _repeat_to_size(
                        (
                            b"def parse_record(record: bytes) -> tuple[int, bytes]:\n"
                            b"    size = int.from_bytes(record[:4], 'big')\n"
                            b"    return size, record[4:4 + size]\n\n"
                        ),
                        unit_size * 2,
                    ),
                ),
                (
                    "sparse/measurements.bin",
                    "sparse",
                    _sparse_measurements(seed + 2, unit_size * 2),
                ),
                (
                    "tabular/sensors.csv",
                    "tabular",
                    _tabular_measurements(unit_size * 2),
                ),
                (
                    "unicode/multilingual.txt",
                    "unicode",
                    _valid_utf8_to_size(
                        "Compression • ضغط البيانات • דחיסת נתונים • 圧縮 • сжатие\n",
                        unit_size * 2,
                    ),
                ),
                (
                    "image-like/gradient-rgba.bin",
                    "image-like",
                    _rgba_gradient(unit_size * 2),
                ),
            ]
        )
        files.extend(
            (
                f"tiny-files/record-{index:03d}.txt",
                "tiny-files",
                f"id={index}\nstate={'active' if index % 3 else 'idle'}\n".encode(),
            )
            for index in range(64)
        )

    entries: list[dict[str, Any]] = []
    for relative, category, data in files:
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append(
            {
                "category": category,
                "path": relative,
                "sha256": _sha256(data),
                "size": len(data),
            }
        )
    (root / "empty" / "empty-dir").mkdir()
    manifest: dict[str, Any] = {
        "corpus_version": corpus_version,
        "directories": ["empty/empty-dir"],
        "files": entries,
        "seed": seed,
        "unit_size": unit_size,
    }
    (root / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for path in root.rglob("*"):
        os.utime(path, ns=(CORPUS_MTIME_NS, CORPUS_MTIME_NS))
    os.utime(root, ns=(CORPUS_MTIME_NS, CORPUS_MTIME_NS))
    return manifest


def verify_corpus(root: Path) -> bool:
    """Verify every declared file and reject undeclared files."""
    try:
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
        declared = {entry["path"]: entry for entry in manifest["files"]}
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False
    try:
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path.name != MANIFEST_NAME
        }
        if actual != set(declared):
            return False
        for relative, entry in declared.items():
            data = root.joinpath(*relative.split("/")).read_bytes()
            if len(data) != entry.get("size") or _sha256(data) != entry.get("sha256"):
                return False
        return all(
            root.joinpath(*path.split("/")).is_dir() for path in manifest["directories"]
        )
    except (OSError, TypeError):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the Mosaic benchmark corpus")
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--unit-size", type=int, default=DEFAULT_UNIT_SIZE)
    parser.add_argument(
        "--corpus-version",
        type=int,
        choices=(1, 2),
        default=CORPUS_VERSION,
    )
    arguments = parser.parse_args(argv)
    manifest = generate_corpus(
        arguments.output,
        seed=arguments.seed,
        unit_size=arguments.unit_size,
        corpus_version=arguments.corpus_version,
    )
    print(
        json.dumps(
            {
                "file_count": len(manifest["files"]),
                "output": str(arguments.output),
                "total_bytes": sum(entry["size"] for entry in manifest["files"]),
                "verified": verify_corpus(arguments.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
