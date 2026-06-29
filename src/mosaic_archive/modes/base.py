"""Compression mode interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum


class ModeId(IntEnum):
    RAW = 0
    RLE = 1
    DELTA8 = 2
    LZ_SIMPLE = 3
    BYTE_RANS = 4


class CompressionMode(ABC):
    id: ModeId
    name: str

    @abstractmethod
    def encode(self, block: bytes) -> bytes:
        """Encode one independent block."""

    @abstractmethod
    def decode(self, payload: bytes, expected_size: int) -> bytes:
        """Decode one block and enforce its expected output size."""
