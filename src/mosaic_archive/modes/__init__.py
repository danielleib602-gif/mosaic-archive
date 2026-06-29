from __future__ import annotations

from dataclasses import dataclass

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.features import analyze_block
from mosaic_archive.modes.base import CompressionMode, ModeId
from mosaic_archive.modes.deflate import DeflateMode
from mosaic_archive.modes.delta import Delta8Mode
from mosaic_archive.modes.lz_simple import LzSimpleMode
from mosaic_archive.modes.rans import ByteRansMode
from mosaic_archive.modes.raw import RawMode
from mosaic_archive.modes.rle import RleMode

ALL_MODES: tuple[CompressionMode, ...] = (
    RawMode(),
    RleMode(),
    Delta8Mode(),
    LzSimpleMode(),
    ByteRansMode(),
    DeflateMode(),
)
_MODE_BY_ID = {mode.id: mode for mode in ALL_MODES}


@dataclass(frozen=True, slots=True)
class EncodedBlock:
    mode: CompressionMode
    payload: bytes


def get_mode(mode_id: int | ModeId) -> CompressionMode:
    try:
        normalized = ModeId(mode_id)
        return _MODE_BY_ID[normalized]
    except (ValueError, KeyError) as error:
        raise ArchiveFormatError(f"unknown compression mode: {mode_id}") from error


def choose_best_mode(block: bytes) -> EncodedBlock:
    """Try every cheap v0.1 mode and retain the smallest exact representation."""
    candidates = (EncodedBlock(mode, mode.encode(block)) for mode in ALL_MODES)
    return min(candidates, key=lambda candidate: len(candidate.payload))


def choose_routed_mode(block: bytes) -> EncodedBlock:
    """Try a cheap, feature-routed candidate set for the default encoder."""
    features = analyze_block(block)
    candidate_ids = {ModeId.RAW, ModeId.RLE, ModeId.DEFLATE}
    if features.delta_smoothness_ratio >= 0.55:
        candidate_ids.add(ModeId.DELTA8)
    if len(block) >= 256 and features.entropy_bits_per_byte < 7.75:
        candidate_ids.add(ModeId.BYTE_RANS)
    candidates = (
        EncodedBlock(mode, mode.encode(block))
        for mode in ALL_MODES
        if mode.id in candidate_ids
    )
    return min(candidates, key=lambda candidate: len(candidate.payload))


__all__ = [
    "ALL_MODES",
    "CompressionMode",
    "EncodedBlock",
    "ModeId",
    "choose_best_mode",
    "choose_routed_mode",
    "get_mode",
]
