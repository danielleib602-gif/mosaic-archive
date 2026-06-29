from __future__ import annotations

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId


class RawMode(CompressionMode):
    id = ModeId.RAW
    name = "RAW"

    def encode(self, block: bytes) -> bytes:
        return block

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        if len(payload) != expected_size:
            raise ArchiveFormatError("RAW block size does not match its metadata")
        return payload

