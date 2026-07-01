"""Generate the permanent encrypted decoder fixtures under tests/fixtures/compat."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import tempfile
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from mosaic_archive.archive import encode_file
from mosaic_archive.cdc import ChunkingConfig
from mosaic_archive.dedup_archive import encode_dedup_archive
from mosaic_archive.modes import EncodedBlock
from mosaic_archive.modes.base import CompressionMode
from mosaic_archive.modes.deflate import DeflateMode
from mosaic_archive.modes.delta import Delta8Mode
from mosaic_archive.modes.lz_rans import LzRansMode
from mosaic_archive.modes.lz_simple import LzSimpleMode
from mosaic_archive.modes.rans import ByteRansMode
from mosaic_archive.modes.rle import RleMode
from mosaic_archive.stream_archive import encode_stream_archive

PASSWORD = "public-compatibility-fixture"
FIXED_MTIME_NS = 1_700_000_000_000_000_000
DEFAULT_OUTPUT = Path(__file__).parents[1] / "tests" / "fixtures" / "compat"


class _DeterministicBytes:
    def __init__(self, seed: int) -> None:
        self._random = random.Random(seed)

    def __call__(self, size: int) -> bytes:
        return self._random.randbytes(size)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixed_selector(mode: CompressionMode) -> Callable[..., EncodedBlock]:
    def select(block: bytes, **_: object) -> EncodedBlock:
        return EncodedBlock(mode, mode.encode(block))

    return select


def _source(root: Path, version: int, data: bytes) -> Path:
    source = root / f"msc{version}-source.bin"
    source.write_bytes(data)
    os.utime(source, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS))
    return source


def generate_fixtures(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    fixture_specs: tuple[tuple[int, CompressionMode, bytes], ...] = (
        (1, RleMode(), b"A" * 4096),
        (2, Delta8Mode(), bytes(range(256)) * 16),
        (3, LzSimpleMode(), (b"legacy-lz-window-" * 256)[:4096]),
        (4, ByteRansMode(), (bytes((0, 1, 0, 2, 0, 3, 0, 4)) * 512)[:4096]),
        (5, DeflateMode(), (b'{"event":"compat","value":42}\n' * 160)[:4096]),
        (6, LzRansMode(), (b"split-stream-lz-rans-fixture-" * 160)[:4096]),
    )
    entries: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="msc-compat-source-") as temp_dir:
        source_root = Path(temp_dir)
        for version, mode, content in fixture_specs:
            source = _source(source_root, version, content)
            archive = output / f"msc{version}.msc"
            deterministic_bytes = _DeterministicBytes(10_000 + version)
            with patch("os.urandom", deterministic_bytes):
                if version == 1:
                    with patch(
                        "mosaic_archive.archive.choose_best_mode",
                        _fixed_selector(mode),
                    ):
                        encode_file(
                            source,
                            archive,
                            PASSWORD,
                            chunk_size=8192,
                            padding_size=256,
                            kdf_log_n=14,
                        )
                elif version == 2:
                    with patch(
                        "mosaic_archive.stream_archive.choose_best_mode",
                        _fixed_selector(mode),
                    ):
                        encode_stream_archive(
                            source,
                            archive,
                            PASSWORD,
                            chunk_size=8192,
                            padding_size=256,
                            kdf_log_n=14,
                        )
                else:
                    with (
                        patch("mosaic_archive.dedup_archive.MSC6_VERSION", version),
                        patch(
                            "mosaic_archive.dedup_archive.choose_routed_mode",
                            _fixed_selector(mode),
                        ),
                    ):
                        encode_dedup_archive(
                            source,
                            archive,
                            PASSWORD,
                            config=ChunkingConfig(8192, 8192, 8192),
                            padding_size=256,
                            kdf_log_n=14,
                        )
            archive_bytes = archive.read_bytes()
            entries.append(
                {
                    "archive": archive.name,
                    "archive_sha256": _sha256(archive_bytes),
                    "content_sha256": _sha256(content),
                    "format_version": version,
                    "mode": mode.name,
                }
            )
    manifest: dict[str, object] = {
        "fixture_schema": 1,
        "fixtures": entries,
        "password": PASSWORD,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)
    manifest = generate_fixtures(arguments.output)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
