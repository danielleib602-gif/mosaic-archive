from __future__ import annotations

from itertools import pairwise

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId
from mosaic_archive.modes.rle import RleMode


class Delta8Mode(CompressionMode):
    """Wrapping byte deltas followed by RLE.

    A raw delta transform cannot shrink data by itself. RLE makes the mode useful
    for ramps and other signals whose first difference repeats.
    """

    id = ModeId.DELTA8
    name = "DELTA8"

    def __init__(self) -> None:
        self._rle = RleMode()

    def encode(self, block: bytes) -> bytes:
        if not block:
            return b""
        deltas = bytes(
            (current - previous) % 256 for previous, current in pairwise(block)
        )
        return block[:1] + self._rle.encode(deltas)

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        if expected_size == 0:
            if payload:
                raise ArchiveFormatError("empty DELTA8 block has a payload")
            return b""
        if not payload:
            raise ArchiveFormatError("DELTA8 block is missing its first byte")
        deltas = self._rle.decode(payload[1:], expected_size - 1)
        output = bytearray(payload[:1])
        for delta in deltas:
            output.append((output[-1] + delta) % 256)
        if len(output) != expected_size:
            raise ArchiveFormatError("DELTA8 block size does not match its metadata")
        return bytes(output)
