from __future__ import annotations

import hashlib
import unittest

from mosaic_archive.dedup_archive import (
    ENTRY_FILE,
    KIND_FILE,
    ChunkRecord,
    DedupEntry,
    DedupManifest,
    parse_dedup_manifest,
    serialize_dedup_manifest,
)
from mosaic_archive.dedup_format import MSC3_FLAGS, MSC3_VERSION, Msc3Header
from mosaic_archive.exceptions import ArchiveFormatError


def header(frame_count: int) -> Msc3Header:
    return Msc3Header(
        version=MSC3_VERSION,
        flags=MSC3_FLAGS,
        kdf_id=1,
        aead_id=1,
        min_chunk_size=64,
        avg_chunk_size=256,
        max_chunk_size=1024,
        padding_size=256,
        salt=b"s" * 16,
        nonce_prefix=b"n" * 4,
        kdf_log_n=14,
        kdf_r=8,
        kdf_p=1,
        frame_count=2,
    )


class DedupManifestValidationTests(unittest.TestCase):
    def make_manifest(self, sources: tuple[int, ...]) -> DedupManifest:
        digest = hashlib.sha256(b"x").digest()
        chunks = tuple(ChunkRecord(digest, 1, source) for source in sources)
        entry = DedupEntry(
            entry_type=ENTRY_FILE,
            relative_path="file.bin",
            mode=0o600,
            mtime_ns=0,
            size=len(chunks),
            first_chunk=0,
            chunk_count=len(chunks),
            digest=hashlib.sha256(b"x" * len(chunks)).digest(),
        )
        return DedupManifest(KIND_FILE, "file.bin", (entry,), chunks)

    def parse(self, manifest: DedupManifest) -> DedupManifest:
        return parse_dedup_manifest(
            serialize_dedup_manifest(manifest),
            header(frame_count=2),
        )

    def test_accepts_direct_backward_reference(self) -> None:
        parsed = self.parse(self.make_manifest((0, 0)))
        self.assertEqual(parsed.chunks[1].source_index, 0)

    def test_rejects_forward_reference(self) -> None:
        with self.assertRaises(ArchiveFormatError):
            self.parse(self.make_manifest((1, 1)))

    def test_rejects_reference_chains(self) -> None:
        with self.assertRaises(ArchiveFormatError):
            self.parse(self.make_manifest((0, 0, 1)))

    def test_rejects_reference_with_inconsistent_digest(self) -> None:
        manifest = self.make_manifest((0, 0))
        mismatched = ChunkRecord(hashlib.sha256(b"y").digest(), 1, 0)
        damaged = DedupManifest(
            manifest.kind,
            manifest.root_name,
            manifest.entries,
            (manifest.chunks[0], mismatched),
        )
        with self.assertRaises(ArchiveFormatError):
            self.parse(damaged)


if __name__ == "__main__":
    unittest.main()
