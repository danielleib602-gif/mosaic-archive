from __future__ import annotations

import os
import pickle
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from mosaic_archive.exceptions import ArchiveFormatError, AuthenticationError
from mosaic_archive.native_preview import (
    decode_native_preview_file,
    encode_native_preview_file,
    inspect_native_preview_file,
)

try:
    from mosaic_archive import _native
except ImportError as error:
    _native = None
    _native_import_error: ImportError | None = error
else:
    _native_import_error = None

if _native is None and os.environ.get("MOSAIC_REQUIRE_NATIVE_EXTENSION") == "1":
    raise RuntimeError("the required native ABI3 extension could not be imported") from (
        _native_import_error
    )


@unittest.skipIf(_native is None, "native ABI3 extension is not installed")
class NativeExtensionIntegrationTests(unittest.TestCase):
    def test_native_exception_types_are_importable_and_pickleable(self) -> None:
        for error_type in (
            _native.AuthenticationError,
            _native.FormatError,
            _native.OptionsError,
            _native.CodecError,
        ):
            with self.subTest(error_type=error_type.__name__):
                self.assertEqual(error_type.__module__, "mosaic_archive._native")
                original = error_type("round-trip")
                restored = pickle.loads(pickle.dumps(original))
                self.assertIs(type(restored), error_type)
                self.assertEqual(str(restored), "round-trip")

    def test_unicode_round_trip_and_exact_stats(self) -> None:
        with TemporaryDirectory(prefix="mosaic-native-extension-") as raw_directory:
            directory = Path(raw_directory)
            source = directory / "מקור-π.bin"
            archive = directory / "ארכיון-π.m7a"
            restored = directory / "שחזור-π.bin"
            payload = (bytes(range(256)) * 128 + b"native-preview\n" * 257) * 3
            source.write_bytes(payload)

            encoded = encode_native_preview_file(
                source,
                archive,
                "päss🔐",
                threads=2,
                kdf_log_n=14,
            )
            inspected = inspect_native_preview_file(archive, "päss🔐")
            decoded = decode_native_preview_file(archive, restored, "päss🔐".encode())

            self.assertEqual(_native.BINDING_API_VERSION, 1)
            self.assertEqual(restored.read_bytes(), payload)
            self.assertFalse(encoded.hash_verified)
            self.assertTrue(inspected.hash_verified)
            self.assertEqual(replace(encoded, hash_verified=True), inspected)
            self.assertEqual(inspected, decoded)
            self.assertEqual(encoded.original_size, len(payload))
            self.assertEqual(encoded.archive_size, archive.stat().st_size)
            self.assertEqual(encoded.format_name, "M7A0")
            self.assertTrue(encoded.authenticated)
            self.assertFalse(encoded.stable)

    def test_authentication_and_format_failures_preserve_destination(self) -> None:
        with TemporaryDirectory(prefix="mosaic-native-extension-") as raw_directory:
            directory = Path(raw_directory)
            source = directory / "source.bin"
            archive = directory / "archive.m7a"
            protected = directory / "protected.bin"
            source.write_bytes(b"repeatable native payload" * 8_192)
            encode_native_preview_file(source, archive, "correct", kdf_log_n=14)
            protected.write_bytes(b"must survive")

            with self.assertRaisesRegex(
                AuthenticationError, "wrong password or archive was modified"
            ):
                decode_native_preview_file(archive, protected, "wrong")
            self.assertEqual(protected.read_bytes(), b"must survive")

            tampered = bytearray(archive.read_bytes())
            tampered.extend(b"trailing")
            archive.write_bytes(tampered)
            with self.assertRaises(ArchiveFormatError):
                decode_native_preview_file(archive, protected, "correct")
            self.assertEqual(protected.read_bytes(), b"must survive")

    def test_io_errors_preserve_python_exception_identity(self) -> None:
        with TemporaryDirectory(prefix="mosaic-native-extension-") as raw_directory:
            missing = Path(raw_directory) / "missing.m7a"
            with self.assertRaises(FileNotFoundError) as raised:
                inspect_native_preview_file(missing, "password")
            self.assertEqual(raised.exception.errno, 2)

    def test_native_work_releases_the_gil(self) -> None:
        with TemporaryDirectory(prefix="mosaic-native-extension-") as raw_directory:
            directory = Path(raw_directory)
            source = directory / "source.bin"
            archive = directory / "archive.m7a"
            source.write_bytes(b"native GIL release" * 65_536)
            start = threading.Event()
            stop = threading.Event()
            heartbeats: list[float] = []

            def run_python() -> None:
                start.wait()
                while not stop.is_set():
                    heartbeats.append(time.perf_counter())
                    time.sleep(0.001)

            worker = threading.Thread(target=run_python)
            worker.start()
            try:
                start.set()
                call_started = time.perf_counter()
                encode_native_preview_file(source, archive, "password", kdf_log_n=17)
                call_finished = time.perf_counter()
            finally:
                stop.set()
                worker.join(timeout=5)

            self.assertFalse(worker.is_alive())
            call_duration = call_finished - call_started
            self.assertGreater(call_duration, 0.05)
            middle_start = call_started + call_duration * 0.25
            middle_end = call_started + call_duration * 0.75
            self.assertTrue(
                any(middle_start <= heartbeat <= middle_end for heartbeat in heartbeats),
                "Python worker made no progress during the middle half of native work",
            )


if __name__ == "__main__":
    unittest.main()
