"""Mosaic Archive public API."""

from mosaic_archive.archive import (
    ArchiveInfo,
    DecodeStats,
    EncodeStats,
    decode_file,
    encode_file,
    inspect_archive,
)
from mosaic_archive.archive_api import decode_path, encode_path, inspect_path
from mosaic_archive.native_preview import (
    NativePreviewStats,
    decode_native_preview_file,
    encode_native_preview_file,
    inspect_native_preview_file,
)

__all__ = [
    "ArchiveInfo",
    "DecodeStats",
    "EncodeStats",
    "NativePreviewStats",
    "decode_file",
    "decode_native_preview_file",
    "decode_path",
    "encode_file",
    "encode_native_preview_file",
    "encode_path",
    "inspect_archive",
    "inspect_native_preview_file",
    "inspect_path",
]

__version__ = "0.39.0"
