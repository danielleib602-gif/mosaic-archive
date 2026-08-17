"""Typed Python facade for the non-stable authenticated M7A0 preview."""

from __future__ import annotations

import math
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar, cast

from mosaic_archive.exceptions import ArchiveFormatError, AuthenticationError, MosaicError

DEFAULT_MAX_INPUT_BYTES = 8 * 1024**3
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024**3
DEFAULT_MAX_ENCODED_BYTES = DEFAULT_MAX_OUTPUT_BYTES + 16 * 1024**2
DEFAULT_MAX_SEGMENTS = 131_072
DEFAULT_MAX_RECORDS = 2_000_000
DEFAULT_MAX_EXPANSION_RATIO = 16_384
DEFAULT_MAX_ARCHIVE_BYTES = DEFAULT_MAX_OUTPUT_BYTES + 80 * 1024**2
DEFAULT_MAX_DATA_RECORDS = 1_000_000
DEFAULT_KDF_LOG_N = 17
_EXPECTED_BINDING_API_VERSION = 1
_MAX_U8 = (1 << 8) - 1
_MAX_U32 = (1 << 32) - 1
_MAX_U64 = (1 << 64) - 1


class _NativeBackend(Protocol):
    BINDING_API_VERSION: int
    AuthenticationError: type[Exception]
    FormatError: type[Exception]
    OptionsError: type[Exception]
    CodecError: type[Exception]

    def encode_file(
        self,
        input_path: str,
        output_path: str,
        password: bytes,
        *,
        threads: int,
        kdf_log_n: int,
        max_input_bytes: int,
    ) -> dict[str, object]: ...

    def decode_file(
        self,
        archive_path: str,
        output_path: str,
        password: bytes,
        *,
        max_output_bytes: int,
        max_encoded_bytes: int,
        max_segments: int,
        max_records: int,
        max_expansion_ratio: int,
        max_archive_bytes: int,
        max_data_records: int,
        max_kdf_log_n: int,
    ) -> dict[str, object]: ...

    def inspect_file(
        self,
        archive_path: str,
        password: bytes,
        *,
        max_output_bytes: int,
        max_encoded_bytes: int,
        max_segments: int,
        max_records: int,
        max_expansion_ratio: int,
        max_archive_bytes: int,
        max_data_records: int,
        max_kdf_log_n: int,
    ) -> dict[str, object]: ...


try:
    from mosaic_archive import _native as _loaded_backend
except ImportError as error:
    _backend: _NativeBackend | None = None
    _backend_import_error: ImportError | None = error
else:
    _backend = cast(_NativeBackend, _loaded_backend)
    _backend_import_error = None


@dataclass(frozen=True, slots=True)
class NativePreviewStats:
    """Exact identity, integrity flags, and counters returned by M7A0 operations."""

    format_name: str
    archive_kind: str
    status: str
    stable: bool
    encrypted: bool
    authenticated: bool
    hash_verified: bool
    original_size: int
    inner_encoded_size: int
    archive_size: int
    segment_count: int
    record_count: int
    deduplicated_records: int
    raw_records: int
    lzma2_records: int
    delta_zstd_records: int
    zstd_records: int
    data_records: int
    padding_bytes: int
    authentication_bytes: int
    inner_ratio: float
    archive_ratio: float


_IDENTITY_FIELDS: dict[str, object] = {
    "format_name": "M7A0",
    "archive_kind": "file",
    "status": "non-stable-preview",
    "stable": False,
    "encrypted": True,
    "authenticated": True,
}
_INTEGER_FIELDS = (
    "original_size",
    "inner_encoded_size",
    "archive_size",
    "segment_count",
    "record_count",
    "deduplicated_records",
    "raw_records",
    "lzma2_records",
    "delta_zstd_records",
    "zstd_records",
    "data_records",
    "padding_bytes",
    "authentication_bytes",
)
_RATIO_FIELDS = ("inner_ratio", "archive_ratio")
_STATS_FIELDS = frozenset(
    (*_IDENTITY_FIELDS, "hash_verified", *_INTEGER_FIELDS, *_RATIO_FIELDS)
)


def _password_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        encoded = password.encode("utf-8")
    elif isinstance(password, bytes):
        encoded = password
    else:
        raise TypeError("password must be str or bytes")
    if not encoded:
        raise ValueError("password must not be empty")
    return encoded


def _path_text(path: str | os.PathLike[str]) -> str:
    value = os.fspath(path)
    if not isinstance(value, str):
        raise TypeError("native preview paths must resolve to text")
    return value


def _bounded_integer(name: str, value: int, maximum: int, *, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in {minimum}..={maximum}")


def _validate_decode_arguments(
    *,
    max_output_bytes: int,
    max_encoded_bytes: int,
    max_segments: int,
    max_records: int,
    max_expansion_ratio: int,
    max_archive_bytes: int,
    max_data_records: int,
    max_kdf_log_n: int,
) -> None:
    _bounded_integer("max_output_bytes", max_output_bytes, _MAX_U64)
    _bounded_integer("max_encoded_bytes", max_encoded_bytes, _MAX_U64)
    _bounded_integer("max_segments", max_segments, _MAX_U32)
    _bounded_integer("max_records", max_records, _MAX_U64)
    _bounded_integer("max_expansion_ratio", max_expansion_ratio, _MAX_U64)
    _bounded_integer("max_archive_bytes", max_archive_bytes, _MAX_U64)
    _bounded_integer("max_data_records", max_data_records, _MAX_U64)
    _bounded_integer("max_kdf_log_n", max_kdf_log_n, _MAX_U8)


def _backend_exception_types(
    backend: object,
) -> tuple[type[Exception], type[Exception], type[Exception], type[Exception]]:
    try:
        candidates = tuple(
            getattr(backend, name)
            for name in ("AuthenticationError", "FormatError", "OptionsError", "CodecError")
        )
    except Exception as error:
        raise MosaicError("native M7A0 preview backend has an incompatible API surface") from error
    if not all(
        isinstance(candidate, type) and issubclass(candidate, Exception)
        for candidate in candidates
    ):
        raise MosaicError("native M7A0 preview backend has an incompatible API surface")
    authentication, format_error, options, codec = candidates
    return authentication, format_error, options, codec


def _require_backend() -> _NativeBackend:
    if _backend is None:
        failure = MosaicError(
            "native M7A0 preview backend is unavailable; install a supported native build"
        )
        if _backend_import_error is not None:
            raise failure from _backend_import_error
        raise failure
    try:
        version = _backend.BINDING_API_VERSION
    except Exception as error:
        raise MosaicError("native M7A0 preview backend has an incompatible API version") from error
    if type(version) is not int or version != _EXPECTED_BINDING_API_VERSION:
        raise MosaicError("native M7A0 preview backend has an incompatible API version")
    try:
        methods = tuple(
            getattr(_backend, name) for name in ("encode_file", "decode_file", "inspect_file")
        )
    except Exception as error:
        raise MosaicError("native M7A0 preview backend has an incompatible API surface") from error
    if not all(callable(method) for method in methods):
        raise MosaicError("native M7A0 preview backend has an incompatible API surface")
    _backend_exception_types(_backend)
    return _backend


T = TypeVar("T")


def _call_backend(action: Callable[[], T], backend: _NativeBackend) -> T:
    authentication_error, format_error, options_error, codec_error = (
        _backend_exception_types(backend)
    )
    try:
        return action()
    except OSError:
        raise
    except Exception as error:
        if isinstance(error, authentication_error):
            raise AuthenticationError("wrong password or archive was modified") from error
        if isinstance(error, format_error):
            raise ArchiveFormatError(str(error)) from error
        if isinstance(error, options_error):
            raise ValueError(str(error)) from error
        if isinstance(error, codec_error):
            raise MosaicError(str(error)) from error
        raise


def _invalid_stats(message: str) -> MosaicError:
    return MosaicError(f"invalid native preview statistics: {message}")


def _stats_from_backend(
    value: object, *, expected_hash_verified: bool
) -> NativePreviewStats:
    if not isinstance(value, dict) or set(value) != _STATS_FIELDS:
        raise _invalid_stats("the backend returned an unexpected schema")
    for field, expected in _IDENTITY_FIELDS.items():
        actual = value[field]
        if type(actual) is not type(expected) or actual != expected:
            raise _invalid_stats(f"the backend returned an invalid {field}")
    if (
        type(value["hash_verified"]) is not bool
        or value["hash_verified"] is not expected_hash_verified
    ):
        raise _invalid_stats("the backend returned an invalid hash_verified")
    for field in _INTEGER_FIELDS:
        actual = value[field]
        if type(actual) is not int or actual < 0:
            raise _invalid_stats(f"the backend returned an invalid {field}")
    for field in _RATIO_FIELDS:
        actual = value[field]
        if type(actual) is not float or not math.isfinite(actual) or actual < 0.0:
            raise _invalid_stats(f"the backend returned an invalid {field}")

    original_size = value["original_size"]
    inner_encoded_size = value["inner_encoded_size"]
    archive_size = value["archive_size"]
    assert isinstance(original_size, int)
    assert isinstance(inner_encoded_size, int)
    assert isinstance(archive_size, int)
    expected_inner_ratio = inner_encoded_size / original_size if original_size else 0.0
    expected_archive_ratio = archive_size / original_size if original_size else 0.0
    if not math.isclose(value["inner_ratio"], expected_inner_ratio, rel_tol=1e-12):
        raise _invalid_stats("inner_ratio is inconsistent")
    if not math.isclose(value["archive_ratio"], expected_archive_ratio, rel_tol=1e-12):
        raise _invalid_stats("archive_ratio is inconsistent")
    classified_records = sum(
        value[field]
        for field in (
            "deduplicated_records",
            "raw_records",
            "lzma2_records",
            "delta_zstd_records",
            "zstd_records",
        )
    )
    if value["record_count"] != classified_records:
        raise _invalid_stats("record counters are inconsistent")

    return NativePreviewStats(**value)


def encode_native_preview_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    threads: int = 1,
    kdf_log_n: int = DEFAULT_KDF_LOG_N,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
) -> NativePreviewStats:
    """Encode one regular file into the explicitly non-stable M7A0 preview."""

    _bounded_integer("threads", threads, 64, minimum=1)
    _bounded_integer("kdf_log_n", kdf_log_n, 18, minimum=14)
    _bounded_integer("max_input_bytes", max_input_bytes, _MAX_U64)
    backend = _require_backend()
    result = _call_backend(
        lambda: backend.encode_file(
            _path_text(input_path),
            _path_text(output_path),
            _password_bytes(password),
            threads=threads,
            kdf_log_n=kdf_log_n,
            max_input_bytes=max_input_bytes,
        ),
        backend,
    )
    return _stats_from_backend(result, expected_hash_verified=False)


def decode_native_preview_file(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_encoded_bytes: int = DEFAULT_MAX_ENCODED_BYTES,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_expansion_ratio: int = DEFAULT_MAX_EXPANSION_RATIO,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_data_records: int = DEFAULT_MAX_DATA_RECORDS,
    max_kdf_log_n: int = DEFAULT_KDF_LOG_N,
) -> NativePreviewStats:
    """Authenticate and transactionally restore one M7A0 regular file."""

    _validate_decode_arguments(
        max_output_bytes=max_output_bytes,
        max_encoded_bytes=max_encoded_bytes,
        max_segments=max_segments,
        max_records=max_records,
        max_expansion_ratio=max_expansion_ratio,
        max_archive_bytes=max_archive_bytes,
        max_data_records=max_data_records,
        max_kdf_log_n=max_kdf_log_n,
    )
    backend = _require_backend()
    result = _call_backend(
        lambda: backend.decode_file(
            _path_text(archive_path),
            _path_text(output_path),
            _password_bytes(password),
            max_output_bytes=max_output_bytes,
            max_encoded_bytes=max_encoded_bytes,
            max_segments=max_segments,
            max_records=max_records,
            max_expansion_ratio=max_expansion_ratio,
            max_archive_bytes=max_archive_bytes,
            max_data_records=max_data_records,
            max_kdf_log_n=max_kdf_log_n,
        ),
        backend,
    )
    return _stats_from_backend(result, expected_hash_verified=True)


def inspect_native_preview_file(
    archive_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_encoded_bytes: int = DEFAULT_MAX_ENCODED_BYTES,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_expansion_ratio: int = DEFAULT_MAX_EXPANSION_RATIO,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_data_records: int = DEFAULT_MAX_DATA_RECORDS,
    max_kdf_log_n: int = DEFAULT_KDF_LOG_N,
) -> NativePreviewStats:
    """Fully authenticate an M7A0 archive without publishing restored output."""

    _validate_decode_arguments(
        max_output_bytes=max_output_bytes,
        max_encoded_bytes=max_encoded_bytes,
        max_segments=max_segments,
        max_records=max_records,
        max_expansion_ratio=max_expansion_ratio,
        max_archive_bytes=max_archive_bytes,
        max_data_records=max_data_records,
        max_kdf_log_n=max_kdf_log_n,
    )
    backend = _require_backend()
    result = _call_backend(
        lambda: backend.inspect_file(
            _path_text(archive_path),
            _password_bytes(password),
            max_output_bytes=max_output_bytes,
            max_encoded_bytes=max_encoded_bytes,
            max_segments=max_segments,
            max_records=max_records,
            max_expansion_ratio=max_expansion_ratio,
            max_archive_bytes=max_archive_bytes,
            max_data_records=max_data_records,
            max_kdf_log_n=max_kdf_log_n,
        ),
        backend,
    )
    return _stats_from_backend(result, expected_hash_verified=True)
