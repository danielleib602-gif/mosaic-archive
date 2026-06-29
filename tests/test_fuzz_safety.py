from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.archive_api import encode_path, inspect_path
from mosaic_archive.exceptions import ArchiveFormatError, MosaicError
from mosaic_archive.modes import ALL_MODES


class DecoderFuzzSafetyTests(unittest.TestCase):
    def test_random_mode_payloads_never_escape_domain_errors(self) -> None:
        rng = random.Random(20260629)
        for mode in ALL_MODES:
            for _ in range(100):
                payload = rng.randbytes(rng.randrange(0, 256))
                expected_size = rng.randrange(0, 512)
                try:
                    decoded = mode.decode(payload, expected_size)
                except ArchiveFormatError:
                    continue
                self.assertEqual(len(decoded), expected_size)

    def test_random_inputs_round_trip_every_mode(self) -> None:
        rng = random.Random(991)
        for mode in ALL_MODES:
            for _ in range(30):
                data = rng.randbytes(rng.randrange(0, 2048))
                encoded = mode.encode(data)
                self.assertEqual(mode.decode(encoded, len(data)), data)

    def test_authenticated_archive_mutations_fail_closed(self) -> None:
        rng = random.Random(77)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            source.write_bytes(b"security mutation corpus" * 100)
            archive = root / "source.msc"
            encode_path(
                source,
                archive,
                "mutation-password",
                padding_size=256,
                kdf_log_n=14,
            )
            original = archive.read_bytes()
            for _ in range(20):
                damaged = bytearray(original)
                index = rng.randrange(max(55, len(damaged) // 2), len(damaged))
                damaged[index] ^= 1 << rng.randrange(8)
                archive.write_bytes(damaged)
                with self.assertRaises(MosaicError):
                    inspect_path(archive, "mutation-password")


if __name__ == "__main__":
    unittest.main()
