from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mosaic_archive.dedup_archive import DedupManifest
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.solid_archive_v2 import (
    _compact_metadata,
    decode_solid_archive_v2,
    encode_solid_archive_v2,
)
from mosaic_archive.stream_archive import ENTRY_FILE

PASSWORD = "authenticated MSR2 failure tests"
ManifestMutation = Callable[[DedupManifest], DedupManifest]


def _temporary_outputs(destination: Path) -> list[Path]:
    return list(destination.parent.glob(f".{destination.name}.*"))


def _flipped_digest(digest: bytes) -> bytes:
    corrupted = bytearray(digest)
    corrupted[0] ^= 1
    return bytes(corrupted)


def _encode_with_authenticated_metadata(
    source: Path,
    archive: Path,
    mutate_manifest: ManifestMutation,
) -> None:
    """Have the production encoder authenticate deliberately malformed metadata."""

    def compact_mutation(
        manifest: DedupManifest,
        assignments: bytes,
        frame_counts: tuple[int, int, int],
        lane_codecs: tuple[int, int, int] | None = None,
    ) -> bytes:
        return _compact_metadata(
            mutate_manifest(manifest),
            assignments,
            frame_counts,
            lane_codecs,
        )

    with patch(
        "mosaic_archive.solid_archive_v2._compact_metadata",
        side_effect=compact_mutation,
    ):
        encode_solid_archive_v2(
            source,
            archive,
            PASSWORD,
            padding_size=256,
            kdf_log_n=14,
        )


def _replace_file_entry(
    manifest: DedupManifest,
    index: int,
    **changes: object,
) -> DedupManifest:
    entries = list(manifest.entries)
    if entries[index].entry_type != ENTRY_FILE:
        raise AssertionError("test mutation did not select a file entry")
    entries[index] = replace(entries[index], **changes)
    return replace(manifest, entries=tuple(entries))


class AuthenticatedSolidArchiveV2FailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_authenticated_traversal_metadata_is_rejected_without_escape(self) -> None:
        source = self.root / "source-folder"
        source.mkdir()
        (source / "safe.txt").write_bytes(b"authenticated traversal payload")
        archive = self.root / "traversal.msr"
        destination = self.root / "restored"
        escaped_path = self.root / "escaped.txt"

        _encode_with_authenticated_metadata(
            source,
            archive,
            lambda manifest: _replace_file_entry(
                manifest,
                0,
                relative_path="../escaped.txt",
            ),
        )

        with self.assertRaisesRegex(ArchiveFormatError, "path is unsafe"):
            decode_solid_archive_v2(archive, destination, PASSWORD)
        self.assertFalse(escaped_path.exists())
        self.assertFalse(destination.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_file_digest_mismatch_preserves_existing_file(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"authenticated file digest payload")
        archive = self.root / "file-digest.msr"
        destination = self.root / "existing.bin"
        original_destination = b"pre-existing destination must survive"
        destination.write_bytes(original_destination)

        def corrupt_file_digest(manifest: DedupManifest) -> DedupManifest:
            entry = manifest.entries[0]
            return _replace_file_entry(
                manifest,
                0,
                digest=_flipped_digest(entry.digest),
            )

        _encode_with_authenticated_metadata(source, archive, corrupt_file_digest)

        with self.assertRaisesRegex(IntegrityError, "MSR2 file digest failed"):
            decode_solid_archive_v2(archive, destination, PASSWORD)
        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_late_folder_digest_mismatch_removes_temp_tree(self) -> None:
        source = self.root / "source-folder"
        source.mkdir()
        (source / "a-good.txt").write_bytes(b"restored before the late failure")
        (source / "z-bad.txt").write_bytes(b"digest failure after earlier output")
        archive = self.root / "folder-digest.msr"
        destination = self.root / "restored-folder"

        def corrupt_last_file_digest(manifest: DedupManifest) -> DedupManifest:
            file_indexes = [
                index
                for index, entry in enumerate(manifest.entries)
                if entry.entry_type == ENTRY_FILE
            ]
            if len(file_indexes) != 2:
                raise AssertionError("test folder did not produce two file entries")
            last_index = file_indexes[-1]
            return _replace_file_entry(
                manifest,
                last_index,
                digest=_flipped_digest(manifest.entries[last_index].digest),
            )

        _encode_with_authenticated_metadata(
            source,
            archive,
            corrupt_last_file_digest,
        )

        with self.assertRaisesRegex(IntegrityError, "MSR2 file digest failed: z-bad.txt"):
            decode_solid_archive_v2(archive, destination, PASSWORD)
        self.assertFalse(destination.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_canonical_chunk_digest_mismatch_is_atomic(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"canonical chunk digest payload" * 64)
        archive = self.root / "chunk-digest.msr"
        destination = self.root / "restored.bin"

        def corrupt_canonical_digest(manifest: DedupManifest) -> DedupManifest:
            chunks = list(manifest.chunks)
            canonical_index = next(
                index for index, chunk in enumerate(chunks) if chunk.source_index == index
            )
            chunks[canonical_index] = replace(
                chunks[canonical_index],
                digest=_flipped_digest(chunks[canonical_index].digest),
            )
            return replace(manifest, chunks=tuple(chunks))

        _encode_with_authenticated_metadata(
            source,
            archive,
            corrupt_canonical_digest,
        )

        with self.assertRaisesRegex(IntegrityError, "MSR2 unique chunk digest failed"):
            decode_solid_archive_v2(archive, destination, PASSWORD)
        self.assertFalse(destination.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_trailing_byte_rejection_preserves_existing_file(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"valid payload before an unauthenticated trailing byte")
        archive = self.root / "trailing.msr"
        destination = self.root / "existing.bin"
        original_destination = b"pre-existing bytes"
        destination.write_bytes(original_destination)
        encode_solid_archive_v2(
            source,
            archive,
            PASSWORD,
            padding_size=256,
            kdf_log_n=14,
        )
        with archive.open("ab") as stream:
            stream.write(b"\x00")

        with self.assertRaisesRegex(ArchiveFormatError, "trailing data"):
            decode_solid_archive_v2(archive, destination, PASSWORD)
        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(_temporary_outputs(destination), [])


if __name__ == "__main__":
    unittest.main()
