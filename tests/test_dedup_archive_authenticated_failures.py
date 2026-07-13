from __future__ import annotations

import io
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from mosaic_archive.cdc import ChunkingConfig
from mosaic_archive.crypto import AEAD_TAG_LENGTH, decrypt, derive_key, encrypt
from mosaic_archive.dedup_archive import (
    CHUNK_RECORD,
    DATA_PREFIX,
    ENTRY_FIXED,
    MANIFEST_PREFIX,
    decode_dedup_archive,
    encode_dedup_archive,
)
from mosaic_archive.dedup_format import MSC3_HEADER, MSC6_VERSION, parse_msc3_header
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.stream_archive import ENTRY_FILE
from mosaic_archive.stream_format import (
    FRAME_DATA,
    FRAME_HEADER,
    FRAME_MANIFEST,
    frame_nonce,
    parse_frame_header,
)

PASSWORD = "authenticated MSC6 failure tests"
TEST_CHUNKING = ChunkingConfig(64, 64, 64)
FramePayloadMutation = Callable[[bytes], bytes]


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise AssertionError(f"test archive is truncated at {description}")
    return data


def _encode(source: Path, archive: Path) -> None:
    stats = encode_dedup_archive(
        source,
        archive,
        PASSWORD,
        config=TEST_CHUNKING,
        padding_size=256,
        kdf_log_n=14,
    )
    if stats.format_version != MSC6_VERSION:
        raise AssertionError("stable encoder did not produce an MSC6 archive")


def _rewrite_authenticated_frame(
    archive: Path,
    *,
    frame_index: int,
    expected_type: int,
    mutate_payload: FramePayloadMutation,
) -> None:
    """Rewrite one authenticated MSC6 frame without changing its header or size."""
    stream = io.BytesIO(archive.read_bytes())
    global_header = _read_exact(stream, MSC3_HEADER.size, "public header")
    header = parse_msc3_header(global_header)
    if header.version != MSC6_VERSION:
        raise AssertionError("test archive is not MSC6")
    key = derive_key(
        PASSWORD,
        header.salt,
        log_n=header.kdf_log_n,
        r=header.kdf_r,
        p=header.kdf_p,
    )
    rebuilt = bytearray(global_header)
    mutation_applied = False

    for expected_index in range(header.frame_count):
        serialized_header = _read_exact(
            stream,
            FRAME_HEADER.size,
            f"frame {expected_index} header",
        )
        frame = parse_frame_header(serialized_header)
        if frame.index != expected_index:
            raise AssertionError("encoder produced an out-of-order test frame")
        ciphertext = _read_exact(
            stream,
            frame.ciphertext_length,
            f"frame {expected_index} ciphertext",
        )

        if expected_index == frame_index:
            if frame.frame_type != expected_type:
                raise AssertionError("target frame has an unexpected type")
            padded = decrypt(
                key,
                frame_nonce(header.nonce_prefix, expected_index),
                ciphertext,
                global_header + serialized_header,
            )
            payload = unpad_payload(padded)
            mutated_padded = pad_payload(mutate_payload(payload), header.padding_size)
            if len(mutated_padded) + AEAD_TAG_LENGTH != frame.ciphertext_length:
                raise AssertionError("structured mutation changed the frame size")
            ciphertext = encrypt(
                key,
                frame_nonce(header.nonce_prefix, expected_index),
                mutated_padded,
                global_header + serialized_header,
            )
            mutation_applied = True

        rebuilt.extend(serialized_header)
        rebuilt.extend(ciphertext)

    if stream.read(1):
        raise AssertionError("encoder produced trailing test archive data")
    if not mutation_applied:
        raise AssertionError("requested frame was not present")
    archive.write_bytes(rebuilt)


def _manifest_layout(
    payload: bytes,
) -> tuple[bytearray, list[tuple[int, int, int]], int, int]:
    if len(payload) < MANIFEST_PREFIX.size:
        raise AssertionError("test manifest is truncated at its prefix")
    _magic, _kind, root_length, entry_count, chunk_count = MANIFEST_PREFIX.unpack_from(
        payload
    )
    position = MANIFEST_PREFIX.size + root_length
    if position > len(payload):
        raise AssertionError("test manifest is truncated at its root name")

    entries: list[tuple[int, int, int]] = []
    for index in range(entry_count):
        fixed_offset = position
        if fixed_offset + ENTRY_FIXED.size > len(payload):
            raise AssertionError(f"test manifest is truncated at entry {index}")
        fields = ENTRY_FIXED.unpack_from(payload, fixed_offset)
        path_length = fields[1]
        path_offset = fixed_offset + ENTRY_FIXED.size
        position = path_offset + path_length
        if position > len(payload):
            raise AssertionError(f"test manifest is truncated at entry {index} path")
        entries.append((fixed_offset, path_offset, path_length))

    chunk_offset = position
    if chunk_offset + chunk_count * CHUNK_RECORD.size != len(payload):
        raise AssertionError("test manifest chunk table has an unexpected size")
    return bytearray(payload), entries, chunk_offset, chunk_count


def _rewrite_first_file_entry(
    payload: bytes,
    *,
    replacement_path: bytes | None = None,
    corrupt_digest: bool = False,
) -> bytes:
    mutable, entries, _chunk_offset, _chunk_count = _manifest_layout(payload)
    for fixed_offset, path_offset, path_length in entries:
        fields = list(ENTRY_FIXED.unpack_from(mutable, fixed_offset))
        if fields[0] != ENTRY_FILE:
            continue
        if replacement_path is not None:
            if len(replacement_path) != path_length:
                raise AssertionError("replacement path must preserve its encoded length")
            mutable[path_offset : path_offset + path_length] = replacement_path
        if corrupt_digest:
            digest = bytearray(fields[-1])
            digest[0] ^= 1
            fields[-1] = bytes(digest)
            ENTRY_FIXED.pack_into(mutable, fixed_offset, *fields)
        return bytes(mutable)
    raise AssertionError("test manifest unexpectedly has no file entry")


def _corrupt_first_chunk_digest(payload: bytes) -> bytes:
    mutable, _entries, chunk_offset, chunk_count = _manifest_layout(payload)
    if chunk_count < 1:
        raise AssertionError("test manifest unexpectedly has no chunk records")
    fields = list(CHUNK_RECORD.unpack_from(mutable, chunk_offset))
    digest = bytearray(fields[0])
    digest[0] ^= 1
    fields[0] = bytes(digest)
    CHUNK_RECORD.pack_into(mutable, chunk_offset, *fields)
    return bytes(mutable)


def _mutate_data_prefix(payload: bytes, field: str) -> bytes:
    if len(payload) < DATA_PREFIX.size:
        raise AssertionError("test data frame is unexpectedly truncated")
    occurrence, original_size, mode_id = DATA_PREFIX.unpack_from(payload)
    if field == "occurrence":
        occurrence += 1
    elif field == "size":
        original_size += 1
    else:
        raise AssertionError(f"unknown data-prefix field: {field}")
    return DATA_PREFIX.pack(occurrence, original_size, mode_id) + payload[DATA_PREFIX.size :]


def _temporary_outputs(destination: Path) -> list[Path]:
    return sorted(destination.parent.glob(f".{destination.name}.*"))


class AuthenticatedDedupArchiveFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_authenticated_traversal_manifest_is_rejected_without_escape(self) -> None:
        source = self.root / "payload"
        source.mkdir()
        (source / "safe.txt").write_bytes(b"authenticated MSC6 traversal payload")
        archive = self.root / "traversal.msc"
        destination = self.root / "restored"
        escaped_path = self.root / "x.txt"
        _encode(source, archive)

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=lambda payload: _rewrite_first_file_entry(
                payload,
                replacement_path=b"../x.txt",
            ),
        )

        with self.assertRaisesRegex(ArchiveFormatError, "path is unsafe"):
            decode_dedup_archive(archive, destination, PASSWORD)
        self.assertFalse(destination.exists())
        self.assertFalse(escaped_path.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_file_digest_mismatch_is_atomic(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"authenticated MSC6 file digest payload")
        archive = self.root / "file-digest-mismatch.msc"
        destination = self.root / "existing.bin"
        original_destination = b"existing destination must survive"
        destination.write_bytes(original_destination)
        _encode(source, archive)

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=lambda payload: _rewrite_first_file_entry(
                payload,
                corrupt_digest=True,
            ),
        )

        with self.assertRaisesRegex(IntegrityError, "file digest failed"):
            decode_dedup_archive(archive, destination, PASSWORD)
        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_folder_digest_mismatch_removes_late_temporary_tree(self) -> None:
        source = self.root / "source-folder"
        source.mkdir()
        payload = b"authenticated MSC6 late folder digest payload"
        (source / "safe.txt").write_bytes(payload)
        archive = self.root / "folder-digest-mismatch.msc"
        destination = self.root / "folder-restored"
        completed_bytes: list[int] = []
        _encode(source, archive)

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=lambda manifest: _rewrite_first_file_entry(
                manifest,
                corrupt_digest=True,
            ),
        )

        with self.assertRaisesRegex(IntegrityError, "file digest failed"):
            decode_dedup_archive(
                archive,
                destination,
                PASSWORD,
                progress=lambda event: completed_bytes.append(event.completed_bytes),
            )
        self.assertIn(len(payload), completed_bytes)
        self.assertFalse(destination.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_data_prefix_failures_are_atomic(self) -> None:
        for field in ("occurrence", "size", "truncated"):
            with self.subTest(field=field):
                case_root = self.root / field
                case_root.mkdir()
                source = case_root / "source.bin"
                source.write_bytes(b"one authenticated MSC6 data frame")
                archive = case_root / "metadata-mismatch.msc"
                destination = case_root / "existing.bin"
                original_destination = f"existing-{field}".encode()
                destination.write_bytes(original_destination)
                _encode(source, archive)

                _rewrite_authenticated_frame(
                    archive,
                    frame_index=1,
                    expected_type=FRAME_DATA,
                    mutate_payload=lambda payload, field=field: (
                        b""
                        if field == "truncated"
                        else _mutate_data_prefix(payload, field)
                    ),
                )

                expected_error = (
                    "data frame is truncated"
                    if field == "truncated"
                    else "metadata is inconsistent"
                )
                with self.assertRaisesRegex(ArchiveFormatError, expected_error):
                    decode_dedup_archive(archive, destination, PASSWORD)
                self.assertEqual(destination.read_bytes(), original_destination)
                self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_chunk_record_digest_mismatch_is_atomic(self) -> None:
        source = self.root / "chunk.bin"
        source.write_bytes(b"authenticated MSC6 chunk digest payload")
        archive = self.root / "chunk-digest-mismatch.msc"
        destination = self.root / "existing.bin"
        original_destination = b"preserve me after chunk digest failure"
        destination.write_bytes(original_destination)
        _encode(source, archive)

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=_corrupt_first_chunk_digest,
        )

        with self.assertRaisesRegex(IntegrityError, "unique chunk digest failed"):
            decode_dedup_archive(archive, destination, PASSWORD)
        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(_temporary_outputs(destination), [])


if __name__ == "__main__":
    unittest.main()
