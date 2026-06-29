"""LZ parsing with separately entropy-coded token streams."""

from __future__ import annotations

import struct
from collections import defaultdict

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId
from mosaic_archive.modes.rans import ByteRansMode

_MAGIC = b"LZR1"
_HEADER = struct.Struct(">4sIIIIIIIIII")
_LITERAL = 0
_MATCH = 1
_MINIMUM_MATCH = 4
_MAXIMUM_MATCH = 65_535
_MAXIMUM_DISTANCE = 65_535
_CANDIDATE_LIMIT = 64


def _encode_varint(value: int, output: bytearray) -> None:
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)


def _decode_varints(data: bytes, count: int) -> list[int]:
    values: list[int] = []
    position = 0
    for _ in range(count):
        value = 0
        shift = 0
        while True:
            if position >= len(data) or shift > 28:
                raise ArchiveFormatError("LZ_RANS varint stream is malformed")
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        values.append(value)
    if position != len(data):
        raise ArchiveFormatError("LZ_RANS varint stream has trailing values")
    return values


class LzRansMode(CompressionMode):
    id = ModeId.LZ_RANS
    name = "LZ_RANS"

    def __init__(self) -> None:
        self._rans = ByteRansMode()

    def _tokenize(self, block: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        tokens = bytearray()
        literals = bytearray()
        literal_lengths = bytearray()
        match_lengths = bytearray()
        distances = bytearray()
        pending_literals = bytearray()
        positions: dict[bytes, list[int]] = defaultdict(list)
        block_size = len(block)
        position = 0

        def index_at(index: int) -> None:
            if index + 3 <= block_size:
                entries = positions[block[index : index + 3]]
                entries.append(index)
                if len(entries) > _CANDIDATE_LIMIT * 4:
                    del entries[: -_CANDIDATE_LIMIT * 2]

        def flush_literals() -> None:
            if pending_literals:
                tokens.append(_LITERAL)
                _encode_varint(len(pending_literals), literal_lengths)
                literals.extend(pending_literals)
                pending_literals.clear()

        while position < block_size:
            best_length = 0
            best_distance = 0
            if position + _MINIMUM_MATCH <= block_size:
                candidates = positions.get(block[position : position + 3], ())
                for candidate in reversed(candidates[-_CANDIDATE_LIMIT:]):
                    distance = position - candidate
                    if not 0 < distance <= _MAXIMUM_DISTANCE:
                        continue
                    limit = min(_MAXIMUM_MATCH, block_size - position)
                    length = 3
                    while (
                        length < limit
                        and block[position + length] == block[position + length - distance]
                    ):
                        length += 1
                    if length > best_length:
                        best_length, best_distance = length, distance
                        if length == limit:
                            break
            if best_length >= _MINIMUM_MATCH:
                flush_literals()
                tokens.append(_MATCH)
                _encode_varint(best_length, match_lengths)
                _encode_varint(best_distance, distances)
                for consumed in range(best_length):
                    index_at(position + consumed)
                position += best_length
            else:
                pending_literals.append(block[position])
                index_at(position)
                position += 1
        flush_literals()
        return (
            bytes(tokens),
            bytes(literals),
            bytes(literal_lengths),
            bytes(match_lengths),
            bytes(distances),
        )

    def encode(self, block: bytes) -> bytes:
        if not block:
            return b""
        raw_streams = self._tokenize(block)
        encoded_streams = tuple(self._rans.encode(stream) for stream in raw_streams)
        descriptor: list[int] = []
        for raw, encoded in zip(raw_streams, encoded_streams, strict=True):
            descriptor.extend((len(raw), len(encoded)))
        return _HEADER.pack(_MAGIC, *descriptor) + b"".join(encoded_streams)

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        if expected_size == 0:
            if payload:
                raise ArchiveFormatError("empty LZ_RANS block has a payload")
            return b""
        if len(payload) < _HEADER.size:
            raise ArchiveFormatError("LZ_RANS header is truncated")
        values = _HEADER.unpack_from(payload)
        if values[0] != _MAGIC:
            raise ArchiveFormatError("LZ_RANS magic is invalid")
        descriptors = values[1:]
        raw_lengths = descriptors[0::2]
        encoded_lengths = descriptors[1::2]
        if sum(encoded_lengths) != len(payload) - _HEADER.size:
            raise ArchiveFormatError("LZ_RANS stream sizes are inconsistent")

        streams: list[bytes] = []
        position = _HEADER.size
        for raw_length, encoded_length in zip(
            raw_lengths, encoded_lengths, strict=True
        ):
            encoded = payload[position : position + encoded_length]
            position += encoded_length
            streams.append(self._rans.decode(encoded, raw_length))
        tokens, literals, literal_data, match_data, distance_data = streams
        literal_count = tokens.count(_LITERAL)
        match_count = tokens.count(_MATCH)
        if literal_count + match_count != len(tokens):
            raise ArchiveFormatError("LZ_RANS token stream contains an unknown token")
        literal_lengths = _decode_varints(literal_data, literal_count)
        match_lengths = _decode_varints(match_data, match_count)
        distances = _decode_varints(distance_data, match_count)

        output = bytearray()
        literal_position = literal_index = match_index = 0
        for token in tokens:
            if token == _LITERAL:
                length = literal_lengths[literal_index]
                literal_index += 1
                if length == 0 or literal_position + length > len(literals):
                    raise ArchiveFormatError("LZ_RANS literal token is invalid")
                if len(output) + length > expected_size:
                    raise ArchiveFormatError("LZ_RANS literal exceeds declared size")
                output.extend(literals[literal_position : literal_position + length])
                literal_position += length
            else:
                length = match_lengths[match_index]
                distance = distances[match_index]
                match_index += 1
                if (
                    length < _MINIMUM_MATCH
                    or distance == 0
                    or distance > len(output)
                    or len(output) + length > expected_size
                ):
                    raise ArchiveFormatError("LZ_RANS match token is invalid")
                for _ in range(length):
                    output.append(output[-distance])
        if literal_position != len(literals) or len(output) != expected_size:
            raise ArchiveFormatError("LZ_RANS decoded size is inconsistent")
        return bytes(output)

