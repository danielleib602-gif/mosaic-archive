"""Portable archive-path validation shared by folder encoders and decoders."""

from __future__ import annotations

import unicodedata
from pathlib import PurePosixPath

_INVALID_WINDOWS_CHARS = frozenset('<>:"\\|?*')
_RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def validate_relative_path(value: str) -> str:
    """Return an NFC-normalized portable relative path or raise ``ValueError``."""
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or normalized in {".", ".."}:
        raise ValueError("archive path must not be empty or relative-dot only")
    if "\x00" in normalized or "\\" in normalized:
        raise ValueError("archive paths must use safe POSIX separators")
    if len(normalized.encode("utf-8")) > 65_535:
        raise ValueError("archive path is too long")

    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts:
        raise ValueError("archive path must be relative")
    for part in path.parts:
        if part in {"", ".", ".."}:
            raise ValueError("archive path contains traversal components")
        if part.endswith((" ", ".")):
            raise ValueError("archive path has a platform-unsafe trailing character")
        if any(character in _INVALID_WINDOWS_CHARS or ord(character) < 32 for character in part):
            raise ValueError("archive path contains platform-unsafe characters")
        stem = part.split(".", 1)[0].upper()
        if stem in _RESERVED_WINDOWS_NAMES:
            raise ValueError("archive path uses a reserved platform name")
    return normalized

