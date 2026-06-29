"""Fast C-backed DEFLATE baseline mode."""

from __future__ import annotations

import zlib

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId


class DeflateMode(CompressionMode):
    id = ModeId.DEFLATE
    name = "DEFLATE"

    def encode(self, block: bytes) -> bytes:
        return zlib.compress(block, level=6) if block else b""

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        if expected_size == 0:
            if payload:
                raise ArchiveFormatError("empty DEFLATE block has a payload")
            return b""
        try:
            decoder = zlib.decompressobj()
            output = decoder.decompress(payload, expected_size + 1)
            if len(output) > expected_size or decoder.unconsumed_tail:
                raise ArchiveFormatError("DEFLATE block exceeds its declared size")
            output += decoder.flush(expected_size + 1 - len(output))
        except zlib.error as error:
            raise ArchiveFormatError("DEFLATE payload is malformed") from error
        if (
            len(output) != expected_size
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            raise ArchiveFormatError("DEFLATE payload has inconsistent size or trailing data")
        return output

