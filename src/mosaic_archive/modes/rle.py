from __future__ import annotations

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId


class RleMode(CompressionMode):
    id = ModeId.RLE
    name = "RLE"

    def encode(self, block: bytes) -> bytes:
        if not block:
            return b""
        output = bytearray()
        run_byte = block[0]
        run_length = 1
        for byte in block[1:]:
            if byte == run_byte and run_length < 255:
                run_length += 1
                continue
            output.extend((run_length, run_byte))
            run_byte = byte
            run_length = 1
        output.extend((run_length, run_byte))
        return bytes(output)

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        if len(payload) % 2:
            raise ArchiveFormatError("RLE payload has a truncated run")
        output = bytearray()
        for index in range(0, len(payload), 2):
            run_length = payload[index]
            if run_length == 0:
                raise ArchiveFormatError("RLE payload contains a zero-length run")
            if len(output) + run_length > expected_size:
                raise ArchiveFormatError("RLE block expands beyond its declared size")
            output.extend(bytes((payload[index + 1],)) * run_length)
        if len(output) != expected_size:
            raise ArchiveFormatError("RLE block size does not match its metadata")
        return bytes(output)

