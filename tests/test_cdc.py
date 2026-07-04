from __future__ import annotations

import hashlib
import io
import random
import unittest
from unittest.mock import patch

from mosaic_archive.cdc import ChunkingConfig, iter_content_defined_chunks


def chunk_digests(data: bytes, config: ChunkingConfig) -> list[bytes]:
    return [
        hashlib.sha256(chunk).digest()
        for chunk in iter_content_defined_chunks(io.BytesIO(data), config)
    ]


class ContentDefinedChunkingTests(unittest.TestCase):
    def test_boundary_signal_uses_one_gear_lookup_per_probe(self) -> None:
        class CountingTable:
            def __init__(self) -> None:
                self.lookups = 0

            def __getitem__(self, index: int) -> int:
                self.lookups += 1
                return 0

        data = random.Random(32).randbytes(8192)
        config = ChunkingConfig(min_size=512, avg_size=2048, max_size=8192)
        table = CountingTable()

        with patch("mosaic_archive.cdc._GEAR_TABLE", table, create=True):
            chunks = list(iter_content_defined_chunks(io.BytesIO(data), config))

        self.assertEqual(b"".join(chunks), data)
        self.assertEqual(table.lookups, 16)

    def test_chunk_storage_avoids_per_byte_buffer_appends(self) -> None:
        class CountingBytearray(bytearray):
            append_calls = 0
            extend_calls = 0

            def append(self, item: int) -> None:
                type(self).append_calls += 1
                super().append(item)

            def extend(self, items: bytes) -> None:
                type(self).extend_calls += 1
                super().extend(items)

        data = random.Random(31).randbytes(200_000)
        config = ChunkingConfig(min_size=512, avg_size=2048, max_size=8192)

        with patch(
            "mosaic_archive.cdc.bytearray",
            CountingBytearray,
            create=True,
        ):
            chunks = list(iter_content_defined_chunks(io.BytesIO(data), config))

        self.assertEqual(b"".join(chunks), data)
        self.assertEqual(CountingBytearray.append_calls, 0)
        self.assertEqual(CountingBytearray.extend_calls, 4)

    def test_subminimum_chunk_skips_unobservable_buzhash_work(self) -> None:
        class CountingTable:
            def __init__(self, values: tuple[int, ...]) -> None:
                self.values = values
                self.lookups = 0

            def __getitem__(self, index: int) -> int:
                self.lookups += 1
                return self.values[index]

        data = random.Random(29).randbytes(511)
        config = ChunkingConfig(min_size=512, avg_size=2048, max_size=8192)
        table = CountingTable(tuple(range(256)))

        with patch("mosaic_archive.cdc._GEAR_TABLE", table):
            chunks = list(iter_content_defined_chunks(io.BytesIO(data), config))

        self.assertEqual(chunks, [data])
        self.assertEqual(table.lookups, 0)

    def test_subminimum_prefix_is_not_iterated_byte_by_byte(self) -> None:
        class NonIterableBytes(bytes):
            def __iter__(self):
                raise AssertionError("subminimum prefix entered the byte loop")

        class OneBlockStream:
            def __init__(self, data: bytes) -> None:
                self.data = NonIterableBytes(data)

            def read(self, _size: int) -> bytes:
                data, self.data = self.data, NonIterableBytes()
                return data

        data = random.Random(33).randbytes(511)
        config = ChunkingConfig(min_size=512, avg_size=2048, max_size=8192)

        chunks = list(iter_content_defined_chunks(OneBlockStream(data), config))

        self.assertEqual(chunks, [data])

    def test_hot_loop_does_not_call_a_generic_rotation_helper(self) -> None:
        data = random.Random(28).randbytes(32 * 1024)
        config = ChunkingConfig(min_size=256, avg_size=1024, max_size=4096)

        with patch(
            "mosaic_archive.cdc._rotate_left",
            side_effect=AssertionError("generic rotation entered the byte hot loop"),
            create=True,
        ):
            chunks = list(iter_content_defined_chunks(io.BytesIO(data), config))

        self.assertEqual(b"".join(chunks), data)

    def test_round_trip_and_size_bounds(self) -> None:
        data = random.Random(20260629).randbytes(200_000)
        config = ChunkingConfig(min_size=512, avg_size=2048, max_size=8192)

        chunks = list(iter_content_defined_chunks(io.BytesIO(data), config))

        self.assertEqual(b"".join(chunks), data)
        self.assertTrue(all(len(chunk) >= config.min_size for chunk in chunks[:-1]))
        self.assertTrue(all(len(chunk) <= config.max_size for chunk in chunks))

    def test_chunking_is_deterministic(self) -> None:
        data = (bytes(range(256)) * 1000) + b"tail"
        config = ChunkingConfig(min_size=256, avg_size=1024, max_size=4096)
        first = list(iter_content_defined_chunks(io.BytesIO(data), config))
        second = list(iter_content_defined_chunks(io.BytesIO(data), config))
        self.assertEqual(first, second)

    def test_inserted_prefix_recovers_chunk_alignment(self) -> None:
        original = random.Random(42).randbytes(300_000)
        modified = original[:1000] + (b"inserted-prefix-" * 17) + original[1000:]
        config = ChunkingConfig(min_size=512, avg_size=2048, max_size=8192)

        original_chunks = set(chunk_digests(original, config))
        modified_chunks = set(chunk_digests(modified, config))
        overlap = len(original_chunks & modified_chunks) / len(original_chunks)

        self.assertGreater(overlap, 0.85)

    def test_empty_input_has_no_chunks(self) -> None:
        config = ChunkingConfig(min_size=256, avg_size=1024, max_size=4096)
        self.assertEqual(list(iter_content_defined_chunks(io.BytesIO(b""), config)), [])

    def test_rejects_unsafe_configuration(self) -> None:
        invalid = (
            (0, 1024, 4096),
            (1024, 512, 4096),
            (256, 1000, 4096),
            (256, 1024, 512),
            (256, 1024, 32 * 1024 * 1024),
        )
        for minimum, average, maximum in invalid:
            with self.subTest(config=(minimum, average, maximum)), self.assertRaises(
                ValueError
            ):
                ChunkingConfig(minimum, average, maximum)


if __name__ == "__main__":
    unittest.main()
