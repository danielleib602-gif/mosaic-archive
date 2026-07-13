from __future__ import annotations

import io
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from mosaic_archive.crypto import AEAD_TAG_LENGTH, decrypt, derive_key, encrypt
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.stream_archive import (
    DATA_PREFIX,
    ENTRY_FIXED,
    MANIFEST_PREFIX,
    decode_stream_archive,
    encode_stream_archive,
)
from mosaic_archive.stream_format import (
    FRAME_DATA,
    FRAME_HEADER,
    FRAME_MANIFEST,
    MSC2_HEADER,
    frame_nonce,
    parse_frame_header,
    parse_msc2_header,
)

PASSWORD = "authenticated MSC2 failure tests"
FramePayloadMutation = Callable[[bytes], bytes]


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise AssertionError(f"test archive is truncated at {description}")
    return data


def _rewrite_authenticated_frame(
    archive: Path,
    *,
    frame_index: int,
    expected_type: int,
    mutate_payload: FramePayloadMutation,
) -> None:
    """Rewrite one authenticated frame without changing its header or size."""
    stream = io.BytesIO(archive.read_bytes())
    global_header = _read_exact(stream, MSC2_HEADER.size, "public header")
    header = parse_msc2_header(global_header)
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
            mutated_payload = mutate_payload(payload)
            mutated_padded = pad_payload(mutated_payload, header.padding_size)
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


def _rewrite_first_manifest_entry(
    payload: bytes,
    *,
    replacement_path: bytes | None = None,
    corrupt_digest: bool = False,
) -> bytes:
    stream = io.BytesIO(payload)
    prefix = _read_exact(stream, MANIFEST_PREFIX.size, "manifest prefix")
    _magic, _kind, root_length, entry_count = MANIFEST_PREFIX.unpack(prefix)
    if entry_count < 1:
        raise AssertionError("test manifest unexpectedly has no entries")
    root_name = _read_exact(stream, root_length, "manifest root name")
    fixed = _read_exact(stream, ENTRY_FIXED.size, "first manifest entry")
    fields = list(ENTRY_FIXED.unpack(fixed))
    path_length = fields[1]
    if not isinstance(path_length, int):
        raise AssertionError("manifest path length has an unexpected type")
    entry_path = _read_exact(stream, path_length, "first manifest entry path")

    if replacement_path is not None:
        if len(replacement_path) != path_length:
            raise AssertionError("replacement path must preserve the encoded length")
        entry_path = replacement_path
    if corrupt_digest:
        digest = bytearray(fields[-1])
        digest[0] ^= 1
        fields[-1] = bytes(digest)

    return b"".join(
        (
            prefix,
            root_name,
            ENTRY_FIXED.pack(*fields),
            entry_path,
            stream.read(),
        )
    )


def _mutate_data_prefix(payload: bytes, field: str) -> bytes:
    if len(payload) < DATA_PREFIX.size:
        raise AssertionError("test data frame is unexpectedly truncated")
    entry_index, original_size, mode_id = DATA_PREFIX.unpack_from(payload)
    if field == "entry":
        entry_index += 1
    elif field == "size":
        original_size += 1
    else:
        raise AssertionError(f"unknown data-prefix field: {field}")
    return DATA_PREFIX.pack(entry_index, original_size, mode_id) + payload[DATA_PREFIX.size :]


def _temporary_outputs(destination: Path) -> list[Path]:
    return list(destination.parent.glob(f".{destination.name}.*"))


class AuthenticatedStreamArchiveFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_authenticated_traversal_manifest_is_rejected_without_escape(self) -> None:
        source = self.root / "payload"
        source.mkdir()
        (source / "safe.txt").write_bytes(b"authenticated traversal payload")
        archive = self.root / "traversal.msc"
        destination = self.root / "restored"
        escaped_path = self.root / "x.txt"
        encode_stream_archive(
            source,
            archive,
            PASSWORD,
            chunk_size=64,
            padding_size=256,
            kdf_log_n=14,
        )

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=lambda payload: _rewrite_first_manifest_entry(
                payload,
                replacement_path=b"../x.txt",
            ),
        )

        with self.assertRaisesRegex(ArchiveFormatError, "unsafe path"):
            decode_stream_archive(archive, destination, PASSWORD)
        self.assertFalse(destination.exists())
        self.assertFalse(escaped_path.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_digest_mismatch_preserves_destination_and_cleans_temp(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"digest-checked authenticated payload")
        archive = self.root / "digest-mismatch.msc"
        destination = self.root / "existing.bin"
        original_destination = b"existing destination must survive"
        destination.write_bytes(original_destination)
        encode_stream_archive(
            source,
            archive,
            PASSWORD,
            chunk_size=64,
            padding_size=256,
            kdf_log_n=14,
        )

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=lambda payload: _rewrite_first_manifest_entry(
                payload,
                corrupt_digest=True,
            ),
        )

        with self.assertRaisesRegex(IntegrityError, "SHA-256"):
            decode_stream_archive(archive, destination, PASSWORD)
        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_folder_digest_mismatch_removes_temporary_tree(self) -> None:
        source = self.root / "source-folder"
        source.mkdir()
        (source / "safe.txt").write_bytes(b"folder digest payload")
        archive = self.root / "folder-digest-mismatch.msc"
        destination = self.root / "folder-restored"
        encode_stream_archive(
            source,
            archive,
            PASSWORD,
            chunk_size=64,
            padding_size=256,
            kdf_log_n=14,
        )

        _rewrite_authenticated_frame(
            archive,
            frame_index=0,
            expected_type=FRAME_MANIFEST,
            mutate_payload=lambda payload: _rewrite_first_manifest_entry(
                payload,
                corrupt_digest=True,
            ),
        )

        with self.assertRaisesRegex(IntegrityError, "SHA-256"):
            decode_stream_archive(archive, destination, PASSWORD)
        self.assertFalse(destination.exists())
        self.assertEqual(_temporary_outputs(destination), [])

    def test_authenticated_first_data_metadata_mismatch_is_atomic(self) -> None:
        for field in ("entry", "size", "truncated"):
            with self.subTest(field=field):
                case_root = self.root / field
                case_root.mkdir()
                source = case_root / "source.bin"
                source.write_bytes(b"one authenticated data frame")
                archive = case_root / "metadata-mismatch.msc"
                destination = case_root / "existing.bin"
                original_destination = f"existing-{field}".encode()
                destination.write_bytes(original_destination)
                encode_stream_archive(
                    source,
                    archive,
                    PASSWORD,
                    chunk_size=64,
                    padding_size=256,
                    kdf_log_n=14,
                )

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
                    "is truncated"
                    if field == "truncated"
                    else "metadata is inconsistent"
                )
                with self.assertRaisesRegex(ArchiveFormatError, expected_error):
                    decode_stream_archive(archive, destination, PASSWORD)
                self.assertEqual(destination.read_bytes(), original_destination)
                self.assertEqual(_temporary_outputs(destination), [])


if __name__ == "__main__":
    unittest.main()
