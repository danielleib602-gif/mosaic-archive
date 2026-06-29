from __future__ import annotations

import struct
from collections import defaultdict

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId

_LITERAL = 0
_MATCH = 1
_U16 = struct.Struct(">H")
_MATCH_FIELDS = struct.Struct(">HH")


class LzSimpleMode(CompressionMode):
    """Small LZSS-style codec intended as an understandable v0.1 baseline."""

    id = ModeId.LZ_SIMPLE
    name = "LZ_SIMPLE"
    minimum_match = 6
    maximum_match = 65_535
    maximum_distance = 65_535
    candidate_limit = 32

    @staticmethod
    def _emit_literals(output: bytearray, literals: bytearray) -> None:
        offset = 0
        while offset < len(literals):
            chunk = literals[offset : offset + 65_535]
            output.append(_LITERAL)
            output.extend(_U16.pack(len(chunk)))
            output.extend(chunk)
            offset += len(chunk)
        literals.clear()

    def encode(self, block: bytes) -> bytes:
        output = bytearray()
        literals = bytearray()
        positions: dict[bytes, list[int]] = defaultdict(list)
        position = 0
        block_length = len(block)

        def index_position(index: int) -> None:
            if index + 3 <= block_length:
                entries = positions[block[index : index + 3]]
                entries.append(index)
                if len(entries) > self.candidate_limit * 4:
                    del entries[: -self.candidate_limit * 2]

        while position < block_length:
            best_length = 0
            best_distance = 0
            if position + self.minimum_match <= block_length:
                key = block[position : position + 3]
                candidates = positions.get(key, ())
                for candidate in reversed(candidates[-self.candidate_limit :]):
                    distance = position - candidate
                    if distance <= 0 or distance > self.maximum_distance:
                        continue
                    limit = min(self.maximum_match, block_length - position)
                    match_length = 3
                    while (
                        match_length < limit
                        and block[candidate + (match_length % distance)]
                        == block[position + match_length]
                    ):
                        match_length += 1
                    if match_length > best_length:
                        best_length = match_length
                        best_distance = distance
                        if match_length == limit:
                            break

            if best_length >= self.minimum_match:
                self._emit_literals(output, literals)
                output.append(_MATCH)
                output.extend(_MATCH_FIELDS.pack(best_distance, best_length))
                for consumed in range(best_length):
                    index_position(position + consumed)
                position += best_length
            else:
                literals.append(block[position])
                index_position(position)
                position += 1
                if len(literals) == 65_535:
                    self._emit_literals(output, literals)

        self._emit_literals(output, literals)
        return bytes(output)

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        output = bytearray()
        position = 0
        while position < len(payload):
            tag = payload[position]
            position += 1
            if tag == _LITERAL:
                if position + _U16.size > len(payload):
                    raise ArchiveFormatError("LZ literal token is truncated")
                (literal_length,) = _U16.unpack_from(payload, position)
                position += _U16.size
                if literal_length == 0 or position + literal_length > len(payload):
                    raise ArchiveFormatError("LZ literal payload is invalid")
                if len(output) + literal_length > expected_size:
                    raise ArchiveFormatError("LZ literal exceeds the declared block size")
                output.extend(payload[position : position + literal_length])
                position += literal_length
            elif tag == _MATCH:
                if position + _MATCH_FIELDS.size > len(payload):
                    raise ArchiveFormatError("LZ match token is truncated")
                distance, match_length = _MATCH_FIELDS.unpack_from(payload, position)
                position += _MATCH_FIELDS.size
                if (
                    distance == 0
                    or distance > len(output)
                    or match_length < self.minimum_match
                    or len(output) + match_length > expected_size
                ):
                    raise ArchiveFormatError("LZ match token is invalid")
                for _ in range(match_length):
                    output.append(output[-distance])
            else:
                raise ArchiveFormatError(f"unknown LZ token tag: {tag}")

        if len(output) != expected_size:
            raise ArchiveFormatError("LZ block size does not match its metadata")
        return bytes(output)

