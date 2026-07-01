"""Small byte-alphabet range Asymmetric Numeral Systems codec."""

from __future__ import annotations

import struct
from collections import Counter

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes.base import CompressionMode, ModeId

_SCALE_BITS = 12
_SCALE = 1 << _SCALE_BITS
_SCALE_MASK = _SCALE - 1
_RANS_L = 1 << 23
_SYMBOL_COUNT = struct.Struct(">H")
_FREQUENCY = struct.Struct(">BH")
_STATE = struct.Struct("<I")


def _normalize_counts(data: bytes) -> dict[int, int]:
    counts = Counter(data)
    total = len(data)
    frequencies = {
        symbol: max(1, (count * _SCALE) // total) for symbol, count in counts.items()
    }
    difference = _SCALE - sum(frequencies.values())
    remainders = {
        symbol: (counts[symbol] * _SCALE) % total for symbol in counts
    }
    if difference > 0:
        order = sorted(counts, key=lambda symbol: (-remainders[symbol], symbol))
        for index in range(difference):
            frequencies[order[index % len(order)]] += 1
    elif difference < 0:
        order = sorted(counts, key=lambda symbol: (-frequencies[symbol], symbol))
        remaining = -difference
        index = 0
        while remaining:
            symbol = order[index % len(order)]
            if frequencies[symbol] > 1:
                frequencies[symbol] -= 1
                remaining -= 1
            index += 1
    return frequencies


def _cumulative(frequencies: dict[int, int]) -> dict[int, int]:
    result: dict[int, int] = {}
    start = 0
    for symbol in sorted(frequencies):
        result[symbol] = start
        start += frequencies[symbol]
    if start != _SCALE:
        raise RuntimeError("internal rANS normalization error")
    return result


class ByteRansMode(CompressionMode):
    id = ModeId.BYTE_RANS
    name = "BYTE_RANS"

    def encode(self, block: bytes) -> bytes:
        if not block:
            return b""
        frequencies = _normalize_counts(block)
        starts = _cumulative(frequencies)
        state = _RANS_L
        renormalized = bytearray()
        for symbol in reversed(block):
            frequency = frequencies[symbol]
            maximum_state = ((_RANS_L >> _SCALE_BITS) << 8) * frequency
            while state >= maximum_state:
                renormalized.append(state & 0xFF)
                state >>= 8
            state = (
                (state // frequency) << _SCALE_BITS
            ) + (state % frequency) + starts[symbol]

        output = bytearray(_SYMBOL_COUNT.pack(len(frequencies)))
        for symbol in sorted(frequencies):
            output.extend(_FREQUENCY.pack(symbol, frequencies[symbol]))
        output.extend(_STATE.pack(state))
        output.extend(reversed(renormalized))
        return bytes(output)

    def decode(self, payload: bytes, expected_size: int) -> bytes:
        if expected_size == 0:
            if payload:
                raise ArchiveFormatError("empty BYTE_RANS block has a payload")
            return b""
        if len(payload) < _SYMBOL_COUNT.size:
            raise ArchiveFormatError("BYTE_RANS frequency header is truncated")
        (symbol_count,) = _SYMBOL_COUNT.unpack_from(payload)
        if not 1 <= symbol_count <= 256:
            raise ArchiveFormatError("BYTE_RANS symbol count is invalid")
        table_end = _SYMBOL_COUNT.size + symbol_count * _FREQUENCY.size
        if len(payload) < table_end + _STATE.size:
            raise ArchiveFormatError("BYTE_RANS payload is truncated")

        frequencies: dict[int, int] = {}
        position = _SYMBOL_COUNT.size
        for _ in range(symbol_count):
            symbol, frequency = _FREQUENCY.unpack_from(payload, position)
            position += _FREQUENCY.size
            if symbol in frequencies or frequency == 0:
                raise ArchiveFormatError("BYTE_RANS frequency table is invalid")
            frequencies[symbol] = frequency
        try:
            starts = _cumulative(frequencies)
        except RuntimeError as error:
            raise ArchiveFormatError("BYTE_RANS frequencies do not sum to 4096") from error

        (state,) = _STATE.unpack_from(payload, position)
        position += _STATE.size
        if state < _RANS_L:
            raise ArchiveFormatError("BYTE_RANS initial state is invalid")
        lookup = [0] * _SCALE
        for symbol, start in starts.items():
            lookup[start : start + frequencies[symbol]] = [symbol] * frequencies[symbol]

        output = bytearray()
        for _ in range(expected_size):
            slot = state & _SCALE_MASK
            symbol = lookup[slot]
            output.append(symbol)
            state = frequencies[symbol] * (state >> _SCALE_BITS) + slot - starts[symbol]
            while state < _RANS_L:
                if position >= len(payload):
                    raise ArchiveFormatError("BYTE_RANS renormalization stream is truncated")
                state = (state << 8) | payload[position]
                position += 1
        if position != len(payload) or state != _RANS_L:
            raise ArchiveFormatError("BYTE_RANS payload has inconsistent trailing state")
        return bytes(output)

