from __future__ import annotations

import hashlib
import tempfile
import unittest
from collections import Counter
from collections.abc import Callable
from contextlib import AbstractContextManager
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import BinaryIO
from unittest.mock import patch

import mosaic_archive.dedup_archive as dedup_archive
import mosaic_archive.solid_archive as solid_archive
import mosaic_archive.solid_archive_v2 as solid_archive_v2
from mosaic_archive.cdc import ChunkingConfig, iter_content_defined_chunks
from mosaic_archive.dedup_archive import ChunkRecord, DedupEntry, DedupManifest
from mosaic_archive.source_identity import SourceSession
from mosaic_archive.stream_archive import ENTRY_DIRECTORY, ENTRY_FILE, KIND_FILE, scan_input

_CHUNKING = ChunkingConfig(64, 128, 256)
_TEST_KEY = bytes(range(32))
_PASSWORD = "one-pass regression"


def _make_source(root: Path) -> Path:
    source = root / "source"
    (source / "nested" / "deeper").mkdir(parents=True)
    (source / "empty-dir").mkdir()
    payload = bytes(range(256)) * 5 + b"mosaic-one-pass" * 37
    (source / "alpha.bin").write_bytes(payload)
    (source / "nested" / "copy.bin").write_bytes(payload)
    (source / "nested" / "deeper" / "tail.bin").write_bytes(b"shifted-prefix" + payload[:700])
    (source / "empty.bin").write_bytes(b"")
    return source


def _tree_contents(root: Path) -> dict[str, bytes | None]:
    return {
        path.relative_to(root).as_posix(): None if path.is_dir() else path.read_bytes()
        for path in sorted(root.rglob("*"))
    }


def _reference_manifest(
    source: Path,
    config: ChunkingConfig,
) -> tuple[DedupManifest, list[int], list[bytes]]:
    """Reconstruct the pre-optimization scan from the public hashed manifest."""
    base = scan_input(source, config.max_size)
    chunks: list[ChunkRecord] = []
    entries: list[DedupEntry] = []
    canonical: dict[tuple[bytes, int], int] = {}
    owners: list[int] = []
    unique_chunks: list[bytes] = []

    for file_index, entry in enumerate(base.entries):
        if entry.entry_type == ENTRY_DIRECTORY:
            entries.append(
                DedupEntry(
                    entry.entry_type,
                    entry.relative_path,
                    entry.mode,
                    entry.mtime_ns,
                    0,
                    0,
                    0,
                    entry.digest,
                )
            )
            continue

        first_chunk = len(chunks)
        path = (
            source if base.kind == KIND_FILE else source.joinpath(*entry.relative_path.split("/"))
        )
        with path.open("rb") as stream:
            for chunk in iter_content_defined_chunks(stream, config):
                chunk_digest = hashlib.sha256(chunk).digest()
                key = (chunk_digest, len(chunk))
                source_index = canonical.setdefault(key, len(chunks))
                if source_index == len(chunks):
                    unique_chunks.append(chunk)
                chunks.append(ChunkRecord(chunk_digest, len(chunk), source_index))
                owners.append(file_index)
        entries.append(
            DedupEntry(
                entry.entry_type,
                entry.relative_path,
                entry.mode,
                entry.mtime_ns,
                entry.size,
                first_chunk,
                len(chunks) - first_chunk,
                entry.digest,
            )
        )

    return (
        DedupManifest(base.kind, base.root_name, tuple(entries), tuple(chunks)),
        owners,
        unique_chunks,
    )


def _capture_source_opens(operation: Callable[[], object]) -> tuple[object, Counter[str]]:
    opened: Counter[str] = Counter()
    original_open_file = SourceSession.open_file

    def counted_open_file(
        session: SourceSession,
        relative_path: str,
    ) -> AbstractContextManager[BinaryIO]:
        opened[relative_path] += 1
        return original_open_file(session, relative_path)

    with patch.object(SourceSession, "open_file", new=counted_open_file):
        result = operation()
    return result, opened


class OnePassManifestTests(unittest.TestCase):
    def test_one_pass_manifest_matches_hashed_scan_and_reference_reconstruction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = _make_source(Path(temp_dir))
            public_manifest = scan_input(source, _CHUNKING.max_size)
            unique_chunks: list[bytes] = []

            actual, actual_owners = dedup_archive._scan_manifest(
                source,
                _CHUNKING,
                on_unique_chunk=unique_chunks.append,
            )
            expected, expected_owners, expected_unique = _reference_manifest(
                source,
                _CHUNKING,
            )

            self.assertEqual(actual, expected)
            self.assertEqual(actual_owners, expected_owners)
            self.assertEqual(unique_chunks, expected_unique)

            public_files = {
                entry.relative_path: entry
                for entry in public_manifest.entries
                if entry.entry_type == ENTRY_FILE
            }
            actual_files = {
                entry.relative_path: entry
                for entry in actual.entries
                if entry.entry_type == ENTRY_FILE
            }
            self.assertEqual(actual_files.keys(), public_files.keys())
            for relative_path, entry in actual_files.items():
                with self.subTest(relative_path=relative_path):
                    public_entry = public_files[relative_path]
                    self.assertEqual(entry.size, public_entry.size)
                    self.assertEqual(entry.digest, public_entry.digest)
            self.assertEqual(actual_files["empty.bin"].chunk_count, 0)
            self.assertTrue(any(entry.entry_type == ENTRY_DIRECTORY for entry in actual.entries))
            self.assertTrue(
                any(chunk.source_index != index for index, chunk in enumerate(actual.chunks))
            )

    def test_source_files_are_opened_only_for_required_physical_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _make_source(root)
            relative_files = {
                path.relative_to(source).as_posix() for path in source.rglob("*") if path.is_file()
            }

            _, scan_opens = _capture_source_opens(lambda: scan_input(source, _CHUNKING.max_size))
            self.assertEqual(scan_opens, Counter({path: 1 for path in relative_files}))

            cases: tuple[
                tuple[
                    str,
                    ModuleType,
                    int,
                    Callable[[Path], object],
                    Callable[[Path, Path], object],
                ],
                ...,
            ] = (
                (
                    "MSC6",
                    dedup_archive,
                    2,
                    lambda archive: dedup_archive.encode_dedup_archive(
                        source,
                        archive,
                        _PASSWORD,
                        config=_CHUNKING,
                        padding_size=256,
                        kdf_log_n=14,
                        profile="fast",
                    ),
                    lambda archive, output: dedup_archive.decode_dedup_archive(
                        archive, output, _PASSWORD
                    ),
                ),
                (
                    "MSR1",
                    solid_archive,
                    1,
                    lambda archive: solid_archive.encode_solid_archive(
                        source,
                        archive,
                        _PASSWORD,
                        config=_CHUNKING,
                        padding_size=256,
                        kdf_log_n=14,
                    ),
                    lambda archive, output: solid_archive.decode_solid_archive(
                        archive, output, _PASSWORD
                    ),
                ),
                (
                    "MSR2",
                    solid_archive_v2,
                    1,
                    lambda archive: solid_archive_v2.encode_solid_archive_v2(
                        source,
                        archive,
                        _PASSWORD,
                        config=_CHUNKING,
                        frame_payload_size=1024,
                        padding_size=256,
                        kdf_log_n=14,
                    ),
                    lambda archive, output: solid_archive_v2.decode_solid_archive_v2(
                        archive, output, _PASSWORD
                    ),
                ),
            )
            for name, module, passes, encode, decode in cases:
                with self.subTest(format=name):
                    archive = root / f"{name}.archive"
                    restored = root / f"{name}-restored"
                    with patch.object(module, "derive_key", return_value=_TEST_KEY):
                        _, opened = _capture_source_opens(partial(encode, archive))
                        decoded = decode(archive, restored)

                    self.assertEqual(
                        opened,
                        Counter({path: passes for path in relative_files}),
                    )
                    self.assertTrue(decoded.hash_verified)
                    self.assertEqual(_tree_contents(restored), _tree_contents(source))


if __name__ == "__main__":
    unittest.main()
