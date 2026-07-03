"""Shared caller-overridable resource limits for archive decoding."""

from __future__ import annotations

DEFAULT_MAX_OUTPUT_SIZE = 1024 * 1024 * 1024 * 1024
DEFAULT_MAX_FRAME_COUNT = 1_000_000
DEFAULT_MAX_LEGACY_ARCHIVE_SIZE = 1024 * 1024 * 1024


def validate_decode_limits(
    max_output_size: int,
    max_frame_count: int,
    max_legacy_archive_size: int,
) -> None:
    if max_output_size < 0:
        raise ValueError("maximum restored size must not be negative")
    if max_frame_count <= 0:
        raise ValueError("maximum frame count must be positive")
    if max_legacy_archive_size <= 0:
        raise ValueError("maximum legacy archive size must be positive")
