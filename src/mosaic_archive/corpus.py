"""Deterministic, redistributable benchmark corpus generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import zlib
from pathlib import Path
from typing import Any

CORPUS_VERSION = 1
DEFAULT_SEED = 20260629
DEFAULT_UNIT_SIZE = 64 * 1024
MANIFEST_NAME = "manifest.json"


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


def generate_corpus(
    root: Path,
    *,
    seed: int = DEFAULT_SEED,
    unit_size: int = DEFAULT_UNIT_SIZE,
) -> dict[str, Any]:
    """Create a deterministic multi-category corpus and return its manifest."""
    if not 1024 <= unit_size <= 16 * 1024 * 1024:
        raise ValueError("unit size must be between 1 KiB and 16 MiB")
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
    files: tuple[tuple[str, str, bytes], ...] = (
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
        "corpus_version": CORPUS_VERSION,
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
    arguments = parser.parse_args(argv)
    manifest = generate_corpus(
        arguments.output,
        seed=arguments.seed,
        unit_size=arguments.unit_size,
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
