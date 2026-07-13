from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mosaic_archive.archive_api import decode_path
from mosaic_archive.cdc import ChunkingConfig
from mosaic_archive.dedup_archive import encode_dedup_archive
from mosaic_archive.stream_archive import ProgressEvent, encode_stream_archive

PASSWORD = "decoder progress atomicity password"
SMALL_CHUNKING = ChunkingConfig(64, 128, 256)
SENTINEL = b"pre-existing destination must survive"


class ProgressCallbackError(RuntimeError):
    pass


class DecoderProgressAtomicityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _make_source(self, archive_kind: str) -> Path:
        if archive_kind == "file":
            source = self.root / "source.bin"
            source.write_bytes(bytes(range(256)) * 2)
            return source

        source = self.root / "source-folder"
        (source / "nested").mkdir(parents=True)
        (source / "empty").mkdir()
        (source / "nested" / "payload.bin").write_bytes(bytes(range(256)) * 2)
        return source

    def _encode(self, archive_format: str, source: Path, archive: Path) -> None:
        if archive_format == "msc2":
            stats = encode_stream_archive(
                source,
                archive,
                PASSWORD,
                chunk_size=128,
                padding_size=256,
                kdf_log_n=14,
            )
            self.assertEqual(stats.format_version, 2)
            return

        stats = encode_dedup_archive(
            source,
            archive,
            PASSWORD,
            config=SMALL_CHUNKING,
            padding_size=256,
            kdf_log_n=14,
        )
        self.assertEqual(stats.format_version, 6)

    def _assert_first_progress_failure_is_atomic(
        self,
        archive_format: str,
        archive_kind: str,
    ) -> None:
        source = self._make_source(archive_kind)
        archive = self.root / f"{archive_format}-{archive_kind}.msc"
        destination = self.root / f"restored-{archive_format}-{archive_kind}"
        self._encode(archive_format, source, archive)

        if archive_kind == "file":
            destination.write_bytes(SENTINEL)

        events: list[ProgressEvent] = []

        def abort_on_first_progress(event: ProgressEvent) -> None:
            events.append(event)
            raise ProgressCallbackError("decode progress callback aborted")

        with self.assertRaisesRegex(
            ProgressCallbackError,
            "decode progress callback aborted",
        ):
            decode_path(
                archive,
                destination,
                PASSWORD,
                progress=abort_on_first_progress,
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].stage, "decode")
        self.assertEqual(events[0].completed_bytes, 0)
        self.assertEqual(events[0].completed_files, 0)
        if archive_kind == "file":
            self.assertEqual(destination.read_bytes(), SENTINEL)
        else:
            self.assertFalse(destination.exists())
        self.assertEqual(list(destination.parent.glob(f".{destination.name}.*")), [])

    def test_msc2_file_first_progress_exception_is_atomic(self) -> None:
        self._assert_first_progress_failure_is_atomic("msc2", "file")

    def test_msc2_folder_first_progress_exception_is_atomic(self) -> None:
        self._assert_first_progress_failure_is_atomic("msc2", "folder")

    def test_msc6_file_first_progress_exception_is_atomic(self) -> None:
        self._assert_first_progress_failure_is_atomic("msc6", "file")

    def test_msc6_folder_first_progress_exception_is_atomic(self) -> None:
        self._assert_first_progress_failure_is_atomic("msc6", "folder")


if __name__ == "__main__":
    unittest.main()
