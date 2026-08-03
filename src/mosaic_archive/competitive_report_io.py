"""Stable bounded JSON loading for competitive development reports."""

from __future__ import annotations

import json
import math
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Final, NoReturn, cast

MAX_REPORT_JSON_BYTES: Final = 8 * 1024 * 1024
READ_CHUNK_BYTES: Final = 64 * 1024
MAX_JSON_NESTING: Final = 64


class ReportValidationError(ValueError):
    """Raised when report-v1 input is incomplete, ambiguous, or untrustworthy."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ReportValidationError(f"non-finite JSON constant is forbidden: {value}")


def _parse_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ReportValidationError(f"non-finite JSON number is forbidden: {value}")
    return result


def _validate_json_nesting(payload: str) -> None:
    """Reject excessive structural nesting without interpreting string contents."""
    depth = 0
    in_string = False
    escaped = False
    for character in payload:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise ReportValidationError("competitive report JSON is too deeply nested")
        elif character in "]}":
            depth -= 1


def _metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _path_metadata_matches_descriptor(
    path_metadata: os.stat_result,
    descriptor_metadata: os.stat_result,
) -> bool:
    """Compare path identity without unstable pre-open Windows timestamps."""
    return (
        path_metadata.st_dev,
        path_metadata.st_ino,
        path_metadata.st_mode,
        path_metadata.st_nlink,
        path_metadata.st_size,
    ) == (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
        descriptor_metadata.st_mode,
        descriptor_metadata.st_nlink,
        descriptor_metadata.st_size,
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = cast(int, getattr(metadata, "st_file_attributes", 0))
    reparse_flag = cast(int, getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(reparse_flag and attributes & reparse_flag)


def _require_single_link_regular_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_ino == 0
        or _is_reparse_point(metadata)
        or metadata.st_nlink != 1
    ):
        raise ReportValidationError(
            "competitive report path must identify a stable single-link regular file"
        )


def _read_report_bytes(path: str | Path, max_bytes: int) -> bytes:
    """Read one stable regular file through a bounded no-follow descriptor."""
    try:
        path_value = os.fspath(path)
        path_before = os.lstat(path_value)
        _require_single_link_regular_file(path_before)
        if path_before.st_size > max_bytes:
            raise ReportValidationError(f"report JSON exceeds {max_bytes} bytes")

        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_BINARY", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOINHERIT", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
            | int(getattr(os, "O_NONBLOCK", 0))
        )
        descriptor = os.open(path_value, flags)
        try:
            opened = os.fstat(descriptor)
            _require_single_link_regular_file(opened)
            if not _path_metadata_matches_descriptor(path_before, opened):
                raise ReportValidationError(
                    "competitive report changed while it was being opened; stable file required"
                )
            if opened.st_size > max_bytes:
                raise ReportValidationError(f"report JSON exceeds {max_bytes} bytes")

            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise ReportValidationError(
                        "competitive report changed while it was being read; stable file required"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)

            descriptor_after = os.fstat(descriptor)
            _require_single_link_regular_file(descriptor_after)
            if _metadata_changed(opened, descriptor_after):
                raise ReportValidationError(
                    "competitive report changed while it was being read; stable file required"
                )

            path_after = os.lstat(path_value)
            _require_single_link_regular_file(path_after)
            if not _path_metadata_matches_descriptor(path_after, descriptor_after):
                raise ReportValidationError(
                    "competitive report path changed while it was being read; stable file required"
                )
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except ReportValidationError:
        raise
    except (OSError, OverflowError, TypeError, ValueError) as error:
        raise ReportValidationError("could not safely read competitive report") from error


def load_competitive_report_payload(
    path: str | Path,
    *,
    max_bytes: int = MAX_REPORT_JSON_BYTES,
) -> Mapping[str, object]:
    """Load one strict JSON object from a stable bounded regular file."""
    if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > MAX_REPORT_JSON_BYTES:
        raise ValueError(f"max_bytes must be an integer from 1 through {MAX_REPORT_JSON_BYTES}")
    payload_bytes = _read_report_bytes(path, max_bytes)
    try:
        payload_text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReportValidationError("report JSON must be valid UTF-8") from error
    _validate_json_nesting(payload_text)
    try:
        payload = json.loads(
            payload_text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_parse_json_float,
        )
    except ReportValidationError:
        raise
    except json.JSONDecodeError as error:
        raise ReportValidationError("invalid JSON in competitive report") from error
    except ValueError as error:
        raise ReportValidationError("invalid JSON value in competitive report") from error
    except RecursionError as error:
        raise ReportValidationError("competitive report JSON is too deeply nested") from error
    if not isinstance(payload, Mapping):
        raise ReportValidationError("report must be an object")
    return cast(Mapping[str, object], payload)
