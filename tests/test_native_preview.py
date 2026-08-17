from __future__ import annotations

import dataclasses
import importlib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mosaic_archive.exceptions import ArchiveFormatError, AuthenticationError, MosaicError

EXPECTED_STATS = {
    "format_name": "M7A0",
    "archive_kind": "file",
    "status": "non-stable-preview",
    "stable": False,
    "encrypted": True,
    "authenticated": True,
    "hash_verified": True,
    "original_size": 1_024,
    "inner_encoded_size": 800,
    "archive_size": 2_176,
    "segment_count": 1,
    "record_count": 3,
    "deduplicated_records": 0,
    "raw_records": 1,
    "lzma2_records": 1,
    "delta_zstd_records": 0,
    "zstd_records": 1,
    "data_records": 1,
    "padding_bytes": 256,
    "authentication_bytes": 32,
    "inner_ratio": 0.78125,
    "archive_ratio": 2.125,
}


class _BackendAuthenticationError(Exception):
    pass


class _BackendFormatError(Exception):
    pass


class _BackendOptionsError(Exception):
    pass


class _BackendCodecError(Exception):
    pass


def _fake_backend(*, result: dict[str, object] | None = None) -> SimpleNamespace:
    value = dict(EXPECTED_STATS if result is None else result)
    return SimpleNamespace(
        AuthenticationError=_BackendAuthenticationError,
        FormatError=_BackendFormatError,
        OptionsError=_BackendOptionsError,
        CodecError=_BackendCodecError,
        encode_file=Mock(return_value=value),
        decode_file=Mock(return_value=value),
        inspect_file=Mock(return_value=value),
    )


def _module():
    return importlib.import_module("mosaic_archive.native_preview")


class NativePreviewFacadeTests(unittest.TestCase):
    def test_encode_returns_exact_frozen_m7a0_stats_and_forwards_defaults(self) -> None:
        native_preview = _module()
        backend = _fake_backend()

        with patch.object(native_preview, "_backend", backend):
            stats = native_preview.encode_native_preview_file(
                Path("input.bin"),
                Path("archive.m7a"),
                "päss🔐",
            )

        self.assertIsInstance(stats, native_preview.NativePreviewStats)
        self.assertTrue(dataclasses.is_dataclass(stats))
        self.assertEqual(dataclasses.asdict(stats), EXPECTED_STATS)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            stats.stable = True
        backend.encode_file.assert_called_once_with(
            "input.bin",
            "archive.m7a",
            "päss🔐".encode(),
            threads=1,
            kdf_log_n=17,
            max_input_bytes=8 * 1024**3,
        )

    def test_decode_preserves_bytes_password_and_forwards_every_limit(self) -> None:
        native_preview = _module()
        backend = _fake_backend()
        password = b"already-encoded\x00password"

        with patch.object(native_preview, "_backend", backend):
            stats = native_preview.decode_native_preview_file(
                Path("archive.m7a"),
                Path("restored.bin"),
                password,
                max_output_bytes=11,
                max_encoded_bytes=12,
                max_segments=13,
                max_records=14,
                max_expansion_ratio=15,
                max_archive_bytes=16,
                max_data_records=17,
                max_kdf_log_n=18,
            )

        self.assertEqual(stats.format_name, "M7A0")
        backend.decode_file.assert_called_once_with(
            "archive.m7a",
            "restored.bin",
            password,
            max_output_bytes=11,
            max_encoded_bytes=12,
            max_segments=13,
            max_records=14,
            max_expansion_ratio=15,
            max_archive_bytes=16,
            max_data_records=17,
            max_kdf_log_n=18,
        )

    def test_inspect_forwards_conservative_native_defaults(self) -> None:
        native_preview = _module()
        backend = _fake_backend()

        with patch.object(native_preview, "_backend", backend):
            stats = native_preview.inspect_native_preview_file(Path("archive.m7a"), b"password")

        self.assertTrue(stats.hash_verified)
        backend.inspect_file.assert_called_once_with(
            "archive.m7a",
            b"password",
            max_output_bytes=8 * 1024**3,
            max_encoded_bytes=8 * 1024**3 + 16 * 1024**2,
            max_segments=131_072,
            max_records=2_000_000,
            max_expansion_ratio=16_384,
            max_archive_bytes=8 * 1024**3 + 80 * 1024**2,
            max_data_records=1_000_000,
            max_kdf_log_n=17,
        )

    def test_empty_password_is_rejected_before_entering_native_code(self) -> None:
        native_preview = _module()
        backend = _fake_backend()

        with patch.object(native_preview, "_backend", backend):
            for password in ("", b""):
                with (
                    self.subTest(password=password),
                    self.assertRaisesRegex(ValueError, "password must not be empty"),
                ):
                    native_preview.inspect_native_preview_file("archive.m7a", password)

        backend.inspect_file.assert_not_called()

    def test_missing_backend_fails_closed_instead_of_falling_back(self) -> None:
        native_preview = _module()

        with (
            patch.object(native_preview, "_backend", None),
            self.assertRaisesRegex(MosaicError, "native M7A0 preview backend is unavailable"),
        ):
            native_preview.decode_native_preview_file("archive.m7a", "restored.bin", "password")

    def test_backend_errors_are_translated_without_losing_the_cause(self) -> None:
        native_preview = _module()
        cases = (
            (
                _BackendAuthenticationError("backend detail must not escape"),
                AuthenticationError,
                "wrong password or archive was modified",
            ),
            (
                _BackendFormatError("bad authenticated header"),
                ArchiveFormatError,
                "bad authenticated header",
            ),
            (_BackendOptionsError("invalid ceiling"), ValueError, "invalid ceiling"),
            (_BackendCodecError("codec failed"), MosaicError, "codec failed"),
        )

        for backend_error, expected_type, expected_message in cases:
            backend = _fake_backend()
            backend.inspect_file.side_effect = backend_error
            with (
                self.subTest(error=type(backend_error).__name__),
                patch.object(native_preview, "_backend", backend),
                self.assertRaisesRegex(expected_type, expected_message) as raised,
            ):
                native_preview.inspect_native_preview_file("archive.m7a", "password")
            self.assertIs(raised.exception.__cause__, backend_error)

    def test_os_errors_remain_os_errors(self) -> None:
        native_preview = _module()
        backend = _fake_backend()
        failure = FileNotFoundError(2, "missing", "archive.m7a")
        backend.inspect_file.side_effect = failure

        with (
            patch.object(native_preview, "_backend", backend),
            self.assertRaises(FileNotFoundError) as raised,
        ):
            native_preview.inspect_native_preview_file("archive.m7a", "password")

        self.assertIs(raised.exception, failure)

    def test_backend_cannot_spoof_the_fixed_preview_identity(self) -> None:
        native_preview = _module()
        invalid = dict(EXPECTED_STATS)
        invalid["stable"] = True
        backend = _fake_backend(result=invalid)

        with (
            patch.object(native_preview, "_backend", backend),
            self.assertRaisesRegex(MosaicError, "invalid native preview statistics"),
        ):
            native_preview.inspect_native_preview_file("archive.m7a", "password")


if __name__ == "__main__":
    unittest.main()
