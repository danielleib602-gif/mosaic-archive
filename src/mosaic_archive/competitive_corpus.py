"""Strict local lock-file verification for the competitive-v1 corpus suite.

This module deliberately does not download or prepare corpus data. A corpus lock only
becomes authoritative when a separately reviewed ``corpora.lock.json`` exists and is
successfully loaded. ``manifest_sha256`` is the SHA-256 of the exact lock-file bytes;
after local files verify against the identities in those bytes, that digest can be
bound to a release tag without introducing a second manifest identity.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final, NoReturn, cast
from urllib.parse import urlsplit

SCHEMA_VERSION: Final = 1
EXPECTED_CONTRACT_ID: Final = "mosaic-competitive-contract-v1"
MIN_PREPARED_BYTES = 67_108_864
MAX_LOCK_BYTES: Final = 1_048_576
MAX_RELATIVE_PATH_BYTES: Final = 4_096
MAX_PATH_COMPONENT_BYTES: Final = 255
MAX_TEXT_BYTES: Final = 4_096
MAX_CORPUS_FILE_BYTES: Final = 16 * 1024**3
MAX_TOTAL_DECLARED_BYTES: Final = 64 * 1024**3
READ_CHUNK_BYTES: Final = 1_048_576
REQUIRED_CORPUS_IDS: Final = (
    "silesia-mixed",
    "enwik8-text",
    "linux-v6.12-v6.13-source-tree",
    "gharchive-utc-hour-json",
    "geonames-allcountries",
    "wikimedia-precompressed-media",
)

_TOP_LEVEL_KEYS: Final = frozenset({"schema_version", "contract_id", "corpora"})
_CORPUS_KEYS: Final = frozenset(
    {"id", "snapshot_id", "source", "prepared", "preparation", "license"}
)
_SOURCE_KEYS: Final = frozenset({"path", "bytes", "sha256", "url"})
_LOCKED_FILE_KEYS: Final = frozenset({"path", "bytes", "sha256"})
_PREPARATION_KEYS: Final = frozenset({"recipe_id", "parameters"})
_PARAMETER_KEYS: Final = frozenset({"name", "value"})
_LICENSE_KEYS: Final = frozenset(
    {
        "name",
        "spdx_id",
        "non_spdx_explanation",
        "url",
        "attribution",
        "attribution_url",
        "redistribution_approved",
        "human_approver",
        "approval_date",
        "evidence",
    }
)
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_SNAPSHOT_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+()-]{2,255}\Z")
_STABLE_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_SPDX_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{1,127}\Z")
_DATE_RE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_MOVING_IDENTIFIERS: Final = frozenset(
    {"current", "head", "latest", "main", "master", "stable", "tip", "trunk"}
)
_OS_OPEN_SUPPORTS_DIR_FD: Final = os.open in os.supports_dir_fd

ParameterValue = str | int | bool


class CorpusLockValidationError(ValueError):
    """Raised when a competitive corpus lock is not exact and trustworthy."""


class CorpusVerificationError(ValueError):
    """Raised when locked local corpus bytes cannot be verified safely."""


@dataclass(frozen=True, slots=True)
class LockedFile:
    """Immutable local file identity declared by the lock."""

    path: str
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    """Immutable source-file identity and its HTTPS provenance URL."""

    path: str
    bytes: int
    sha256: str
    url: str


@dataclass(frozen=True, slots=True)
class PreparationParameter:
    """One explicit scalar input to a deterministic preparation recipe."""

    name: str
    value: ParameterValue


@dataclass(frozen=True, slots=True)
class PreparationRecipe:
    """Stable recipe identity and immutable parameter sequence."""

    recipe_id: str
    parameters: tuple[PreparationParameter, ...]


@dataclass(frozen=True, slots=True)
class LicenseRecord:
    """License, attribution, evidence, and human redistribution approval."""

    name: str
    spdx_id: str | None
    non_spdx_explanation: str | None
    url: str
    attribution: str
    attribution_url: str
    redistribution_approved: bool
    human_approver: str
    approval_date: date
    evidence: LockedFile


@dataclass(frozen=True, slots=True)
class CompetitiveCorpus:
    """One immutable competitive corpus snapshot."""

    id: str
    snapshot_id: str
    source: SourceArtifact
    prepared: LockedFile
    preparation: PreparationRecipe
    license: LicenseRecord


@dataclass(frozen=True, slots=True)
class CompetitiveCorpusLock:
    """Parsed corpus lock plus the identity of its exact source bytes."""

    schema_version: int
    contract_id: str
    corpora: tuple[CompetitiveCorpus, ...]
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedFile:
    """A local regular file verified against one or more lock declarations."""

    path: str
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class CompetitiveCorpusVerification:
    """Successful local verification bound to the exact lock-file digest."""

    contract_id: str
    manifest_sha256: str
    corpus_ids: tuple[str, ...]
    files: tuple[VerifiedFile, ...]
    total_verified_bytes: int


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusLockValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise CorpusLockValidationError(f"non-finite JSON constant is forbidden: {value}")


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CorpusLockValidationError(f"non-finite JSON number is forbidden: {value}")
    return parsed


def secure_local_verification_supported() -> bool:
    """Return whether stdlib offers atomic descriptor-relative no-follow opens."""

    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    return (
        os.name == "posix"
        and _OS_OPEN_SUPPORTS_DIR_FD
        and all(
            isinstance(getattr(os, name, None), int) and getattr(os, name) != 0
            for name in required_flags
        )
    )


def _require_secure_access(
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> None:
    if not secure_local_verification_supported():
        raise error_type("atomic no-follow local file access is unavailable on this platform")


def _os_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        raise RuntimeError(f"required secure-open flag disappeared: {name}")
    return value


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | _os_open_flag("O_CLOEXEC")
        | _os_open_flag("O_DIRECTORY")
        | _os_open_flag("O_NOFOLLOW")
    )


def _regular_file_open_flags() -> int:
    return os.O_RDONLY | _os_open_flag("O_CLOEXEC") | _os_open_flag("O_NOFOLLOW")


def _secure_path_parts(
    path: Path,
    context: str,
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
    *,
    allow_anchor_only: bool,
) -> tuple[str, tuple[str, ...]]:
    path_text = os.fspath(path)
    if not path_text or "\x00" in path_text or path_text.startswith("//"):
        raise error_type(f"{context} must be a normalized local path")
    if path_text == "/":
        if not allow_anchor_only:
            raise error_type(f"{context} must name a regular file")
        return "/", ()
    if path_text == ".":
        if not allow_anchor_only:
            raise error_type(f"{context} must name a regular file")
        return ".", ()
    absolute = path_text.startswith("/")
    raw_parts = path_text.split("/")
    parts = raw_parts[1:] if absolute else raw_parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise error_type(f"{context} must be a normalized local path")
    return ("/" if absolute else "."), tuple(parts)


def _open_anchor_directory(
    anchor: str,
    context: str,
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> int:
    try:
        descriptor = os.open(anchor, _directory_open_flags())
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise error_type(
            f"could not securely open {context} directory; symlinks are forbidden"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise error_type(f"{context} is not a directory")
    return descriptor


def _open_directory_path_secure(
    path: Path,
    context: str,
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> int:
    _require_secure_access(error_type)
    anchor, parts = _secure_path_parts(
        path,
        context,
        error_type,
        allow_anchor_only=True,
    )
    current = _open_anchor_directory(anchor, context, error_type)
    try:
        for part in parts:
            try:
                following = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=current,
                )
            except OSError as exc:
                raise error_type(
                    f"could not securely open {context} directory; symlinks are forbidden"
                ) from exc
            os.close(current)
            current = following
        metadata = os.fstat(current)
        if not stat.S_ISDIR(metadata.st_mode):
            raise error_type(f"{context} is not a directory")
        return current
    except BaseException:
        os.close(current)
        raise


def _open_regular_path_secure(
    path: Path,
    context: str,
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> tuple[int, os.stat_result]:
    _require_secure_access(error_type)
    anchor, parts = _secure_path_parts(
        path,
        context,
        error_type,
        allow_anchor_only=False,
    )
    current = _open_anchor_directory(anchor, context, error_type)
    try:
        for part in parts[:-1]:
            try:
                following = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=current,
                )
            except OSError as exc:
                raise error_type(
                    f"could not securely open {context} parent directory; symlinks are forbidden"
                ) from exc
            os.close(current)
            current = following
        try:
            descriptor = os.open(
                parts[-1],
                _regular_file_open_flags(),
                dir_fd=current,
            )
        except OSError as exc:
            raise error_type(
                f"could not securely open {context} regular file; symlinks are forbidden"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise error_type(f"{context} is not a regular file")
            return descriptor, metadata
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(current)


def _metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    )


def _read_lock_bytes_secure(path: Path, max_bytes: int) -> bytes:
    descriptor, initial_metadata = _open_regular_path_secure(
        path,
        "corpus lock",
        CorpusLockValidationError,
    )
    try:
        if initial_metadata.st_size > max_bytes:
            raise CorpusLockValidationError(f"corpus lock exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            try:
                chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
            except OSError as exc:
                raise CorpusLockValidationError("could not read corpus lock") from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise CorpusLockValidationError(f"corpus lock exceeds {max_bytes} bytes")
        final_metadata = os.fstat(descriptor)
        if (
            _metadata_changed(initial_metadata, final_metadata)
            or len(raw) != final_metadata.st_size
        ):
            raise CorpusLockValidationError("corpus lock changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def _expect_object(
    value: object,
    expected_keys: frozenset[str],
    context: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CorpusLockValidationError(f"{context} must be a JSON object")
    actual_keys = frozenset(value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise CorpusLockValidationError(
            f"{context} keys must be exact; missing={missing}, extra={extra}"
        )
    return cast(dict[str, object], value)


def _expect_array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise CorpusLockValidationError(f"{context} must be a JSON array")
    return cast(list[object], value)


def _expect_string(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > MAX_TEXT_BYTES
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        raise CorpusLockValidationError(
            f"{context} must be a bounded canonical string without control characters"
        )
    return value


def _expect_positive_int(value: object, context: str) -> int:
    if type(value) is not int or value <= 0:
        raise CorpusLockValidationError(f"{context} must be a positive integer")
    return value


def _expect_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CorpusLockValidationError(
            f"{context} sha256 must be 64 lowercase hexadecimal characters"
        )
    return value


def _expect_relative_path(value: object, context: str) -> str:
    path = _expect_string(value, f"{context} path")
    raw_parts = path.split("/")
    posix_path = PurePosixPath(path)
    windows_path = PureWindowsPath(path)
    if (
        "\\" in path
        or "\x00" in path
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or any(part in {"", ".", ".."} for part in raw_parts)
        or posix_path.as_posix() != path
        or path != path.strip()
        or unicodedata.normalize("NFC", path) != path
        or len(path.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES
        or any(len(part.encode("utf-8")) > MAX_PATH_COMPONENT_BYTES for part in raw_parts)
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in path)
    ):
        raise CorpusLockValidationError(f"{context} path must be a normalized relative POSIX path")
    return path


def _expect_https_url(value: object, context: str) -> str:
    url = _expect_string(value, context)
    if any(character.isspace() or ord(character) < 32 for character in url):
        raise CorpusLockValidationError(f"{context} must be a safe HTTPS URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CorpusLockValidationError(f"{context} must be a safe HTTPS URL") from exc
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise CorpusLockValidationError(f"{context} must be a safe HTTPS URL")
    return url


def _expect_stable_identifier(value: object, context: str) -> str:
    identifier = _expect_string(value, context)
    if _STABLE_ID_RE.fullmatch(identifier) is None or identifier.casefold() in _MOVING_IDENTIFIERS:
        raise CorpusLockValidationError(f"{context} must be a stable identifier")
    return identifier


def _expect_snapshot_id(value: object, context: str) -> str:
    identifier = _expect_string(value, context)
    if (
        _SNAPSHOT_ID_RE.fullmatch(identifier) is None
        or identifier.casefold() in _MOVING_IDENTIFIERS
    ):
        raise CorpusLockValidationError(f"{context} must be an explicit immutable snapshot_id")
    return identifier


def _parse_locked_file(
    raw: object,
    context: str,
    *,
    minimum_bytes: int = 1,
) -> LockedFile:
    value = _expect_object(raw, _LOCKED_FILE_KEYS, context)
    byte_length = _expect_positive_int(value["bytes"], f"{context}.bytes")
    if byte_length < minimum_bytes:
        raise CorpusLockValidationError(
            f"{context}.bytes is below the minimum of {minimum_bytes} bytes"
        )
    if byte_length > MAX_CORPUS_FILE_BYTES:
        raise CorpusLockValidationError(
            f"{context}.bytes exceeds the per-file limit of {MAX_CORPUS_FILE_BYTES}"
        )
    return LockedFile(
        path=_expect_relative_path(value["path"], context),
        bytes=byte_length,
        sha256=_expect_sha256(value["sha256"], context),
    )


def _parse_source(raw: object, context: str) -> SourceArtifact:
    value = _expect_object(raw, _SOURCE_KEYS, context)
    byte_length = _expect_positive_int(value["bytes"], f"{context}.bytes")
    if byte_length > MAX_CORPUS_FILE_BYTES:
        raise CorpusLockValidationError(
            f"{context}.bytes exceeds the per-file limit of {MAX_CORPUS_FILE_BYTES}"
        )
    return SourceArtifact(
        path=_expect_relative_path(value["path"], context),
        bytes=byte_length,
        sha256=_expect_sha256(value["sha256"], context),
        url=_expect_https_url(value["url"], f"{context}.url"),
    )


def _parse_parameter_value(value: object, context: str) -> ParameterValue:
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if isinstance(value, str):
        return _expect_string(value, context)
    raise CorpusLockValidationError(f"{context} value must be a string, integer, or boolean")


def _parse_preparation(raw: object, context: str) -> PreparationRecipe:
    value = _expect_object(raw, _PREPARATION_KEYS, context)
    parameters_raw = _expect_array(value["parameters"], f"{context}.parameters")
    parameters: list[PreparationParameter] = []
    names: set[str] = set()
    for index, parameter_raw in enumerate(parameters_raw):
        parameter_context = f"{context}.parameters[{index}]"
        parameter = _expect_object(parameter_raw, _PARAMETER_KEYS, parameter_context)
        name = _expect_stable_identifier(parameter["name"], f"{parameter_context}.name")
        if name in names:
            raise CorpusLockValidationError(
                f"{context}.parameters has duplicate parameter name: {name!r}"
            )
        names.add(name)
        parameters.append(
            PreparationParameter(
                name=name,
                value=_parse_parameter_value(parameter["value"], f"{parameter_context}.value"),
            )
        )
    return PreparationRecipe(
        recipe_id=_expect_stable_identifier(value["recipe_id"], f"{context}.recipe_id"),
        parameters=tuple(parameters),
    )


def _parse_approval_date(value: object, context: str) -> date:
    raw = _expect_string(value, context)
    if _DATE_RE.fullmatch(raw) is None:
        raise CorpusLockValidationError(f"{context} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise CorpusLockValidationError(f"{context} is not a valid calendar date") from exc


def _parse_license(raw: object, context: str) -> LicenseRecord:
    value = _expect_object(raw, _LICENSE_KEYS, context)
    raw_spdx_id = value["spdx_id"]
    raw_explanation = value["non_spdx_explanation"]
    if raw_spdx_id is not None and not isinstance(raw_spdx_id, str):
        raise CorpusLockValidationError(f"{context}.spdx_id must be a string or null")
    if raw_explanation is not None and not isinstance(raw_explanation, str):
        raise CorpusLockValidationError(f"{context}.non_spdx_explanation must be a string or null")
    has_spdx_id = isinstance(raw_spdx_id, str) and bool(raw_spdx_id.strip())
    has_explanation = isinstance(raw_explanation, str) and bool(raw_explanation.strip())
    if has_spdx_id == has_explanation:
        raise CorpusLockValidationError(
            f"{context} requires exactly one of spdx_id or non_spdx_explanation"
        )
    spdx_id = cast(str, raw_spdx_id) if has_spdx_id else None
    explanation = cast(str, raw_explanation) if has_explanation else None
    if spdx_id is not None and _SPDX_ID_RE.fullmatch(spdx_id) is None:
        raise CorpusLockValidationError(f"{context}.spdx_id is not a valid SPDX ID")
    approved = value["redistribution_approved"]
    if approved is not True:
        raise CorpusLockValidationError(
            f"{context}.redistribution_approved must be the boolean true"
        )
    return LicenseRecord(
        name=_expect_string(value["name"], f"{context}.name"),
        spdx_id=spdx_id,
        non_spdx_explanation=explanation,
        url=_expect_https_url(value["url"], f"{context}.url"),
        attribution=_expect_string(value["attribution"], f"{context}.attribution"),
        attribution_url=_expect_https_url(value["attribution_url"], f"{context}.attribution_url"),
        redistribution_approved=True,
        human_approver=_expect_string(value["human_approver"], f"{context}.human_approver"),
        approval_date=_parse_approval_date(value["approval_date"], f"{context}.approval_date"),
        evidence=_parse_locked_file(value["evidence"], f"{context}.evidence"),
    )


def _parse_corpus(raw: object, index: int) -> CompetitiveCorpus:
    context = f"corpora[{index}]"
    value = _expect_object(raw, _CORPUS_KEYS, context)
    corpus_id = _expect_string(value["id"], f"{context}.id")
    return CompetitiveCorpus(
        id=corpus_id,
        snapshot_id=_expect_snapshot_id(value["snapshot_id"], f"{context}.snapshot_id"),
        source=_parse_source(value["source"], f"{context}.source"),
        prepared=_parse_locked_file(
            value["prepared"],
            f"{context}.prepared",
            minimum_bytes=MIN_PREPARED_BYTES,
        ),
        preparation=_parse_preparation(value["preparation"], f"{context}.preparation"),
        license=_parse_license(value["license"], f"{context}.license"),
    )


def _check_declared_identity_collisions(
    corpora: tuple[CompetitiveCorpus, ...],
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> None:
    identities: dict[str, tuple[int, str]] = {}
    for corpus in corpora:
        files = (corpus.source, corpus.prepared, corpus.license.evidence)
        for locked_file in files:
            identity = (locked_file.bytes, locked_file.sha256)
            previous = identities.setdefault(locked_file.path, identity)
            if previous != identity:
                raise error_type(
                    f"path has conflicting identities in corpus lock: {locked_file.path!r}"
                )


def _check_distinct_prepared_inputs(
    corpora: tuple[CompetitiveCorpus, ...],
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> None:
    prepared_paths = tuple(corpus.prepared.path for corpus in corpora)
    if len(set(prepared_paths)) != len(prepared_paths):
        raise error_type("prepared paths must be distinct across corpus IDs")
    prepared_digests = tuple(corpus.prepared.sha256 for corpus in corpora)
    if len(set(prepared_digests)) != len(prepared_digests):
        raise error_type("prepared sha256s must be distinct across corpus IDs")


def _check_declared_resource_limits(
    corpora: tuple[CompetitiveCorpus, ...],
    error_type: type[CorpusLockValidationError | CorpusVerificationError],
) -> None:
    declared_by_path: dict[str, int] = {}
    for corpus in corpora:
        for locked_file in (corpus.source, corpus.prepared, corpus.license.evidence):
            declared_by_path.setdefault(locked_file.path, locked_file.bytes)
    total_bytes = sum(declared_by_path.values())
    if total_bytes > MAX_TOTAL_DECLARED_BYTES:
        raise error_type(
            f"declared corpus bytes exceed the total limit of {MAX_TOTAL_DECLARED_BYTES}"
        )


def load_competitive_corpus_lock(
    path: Path,
    *,
    max_bytes: int = MAX_LOCK_BYTES,
) -> CompetitiveCorpusLock:
    """Load a strict v1 corpus lock and retain its exact byte-level SHA-256.

    The loader rejects duplicate keys, non-standard/non-finite numbers, unknown or
    missing keys, type coercions (including booleans as integers), and all schema
    deviations. It never downloads corpus data.
    """

    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    lock_path = Path(path)
    raw = _read_lock_bytes_secure(lock_path, max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusLockValidationError("corpus lock must be valid UTF-8") from exc
    try:
        parsed = cast(
            object,
            json.loads(
                text,
                object_pairs_hook=_duplicate_rejecting_object,
                parse_constant=_reject_json_constant,
                parse_float=_parse_json_float,
            ),
        )
    except json.JSONDecodeError as exc:
        raise CorpusLockValidationError("corpus lock contains invalid JSON") from exc
    root = _expect_object(parsed, _TOP_LEVEL_KEYS, "corpus lock")
    schema_version = root["schema_version"]
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise CorpusLockValidationError(f"schema_version must be the integer {SCHEMA_VERSION}")
    contract_id = root["contract_id"]
    if not isinstance(contract_id, str) or contract_id != EXPECTED_CONTRACT_ID:
        raise CorpusLockValidationError(f"contract_id must be {EXPECTED_CONTRACT_ID!r}")
    raw_corpora = _expect_array(root["corpora"], "corpora")
    corpora = tuple(
        _parse_corpus(raw_corpus, index) for index, raw_corpus in enumerate(raw_corpora)
    )
    corpus_ids = tuple(corpus.id for corpus in corpora)
    if len(corpus_ids) != len(REQUIRED_CORPUS_IDS) or set(corpus_ids) != set(REQUIRED_CORPUS_IDS):
        raise CorpusLockValidationError(
            "corpus IDs must be exactly: " + ", ".join(REQUIRED_CORPUS_IDS)
        )
    by_id = {corpus.id: corpus for corpus in corpora}
    normalized_corpora = tuple(by_id[corpus_id] for corpus_id in REQUIRED_CORPUS_IDS)
    _check_distinct_prepared_inputs(normalized_corpora, CorpusLockValidationError)
    _check_declared_identity_collisions(normalized_corpora, CorpusLockValidationError)
    _check_declared_resource_limits(normalized_corpora, CorpusLockValidationError)
    return CompetitiveCorpusLock(
        schema_version=SCHEMA_VERSION,
        contract_id=contract_id,
        corpora=normalized_corpora,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _open_relative_regular_secure(
    root_descriptor: int,
    locked_file: LockedFile | SourceArtifact,
) -> tuple[int, os.stat_result]:
    try:
        normalized = _expect_relative_path(locked_file.path, "locked file")
    except CorpusLockValidationError as exc:
        raise CorpusVerificationError(str(exc)) from exc
    parts = normalized.split("/")
    current = root_descriptor
    owns_current = False
    try:
        for part in parts[:-1]:
            try:
                following = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=current,
                )
            except OSError as exc:
                raise CorpusVerificationError(
                    f"could not securely open parent of {locked_file.path!r}; "
                    "symlinks are forbidden"
                ) from exc
            if owns_current:
                os.close(current)
            current = following
            owns_current = True
        try:
            descriptor = os.open(
                parts[-1],
                _regular_file_open_flags(),
                dir_fd=current,
            )
        except OSError as exc:
            raise CorpusVerificationError(
                f"could not securely open locked file {locked_file.path!r}; symlinks are forbidden"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CorpusVerificationError(
                    f"locked path is not a regular file: {locked_file.path!r}"
                )
            return descriptor, metadata
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        if owns_current:
            os.close(current)


def _verify_file_once(
    root_descriptor: int,
    locked_file: LockedFile | SourceArtifact,
) -> VerifiedFile:
    descriptor, initial_metadata = _open_relative_regular_secure(
        root_descriptor,
        locked_file,
    )
    digest = hashlib.sha256()
    remaining = locked_file.bytes
    try:
        if initial_metadata.st_size != locked_file.bytes:
            raise CorpusVerificationError(
                f"byte length mismatch for {locked_file.path!r}: "
                f"expected {locked_file.bytes}, got {initial_metadata.st_size}"
            )
        while remaining:
            try:
                chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
            except OSError as exc:
                raise CorpusVerificationError(
                    f"could not read locked file: {locked_file.path!r}"
                ) from exc
            if not chunk:
                actual = locked_file.bytes - remaining
                raise CorpusVerificationError(
                    f"byte length mismatch for {locked_file.path!r}: "
                    f"expected {locked_file.bytes}, got {actual}"
                )
            if len(chunk) > remaining:
                raise CorpusVerificationError(
                    f"bounded read exceeded declared size for {locked_file.path!r}"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        try:
            extra = os.read(descriptor, 1)
            final_metadata = os.fstat(descriptor)
        except OSError as exc:
            raise CorpusVerificationError(
                f"could not finish reading locked file: {locked_file.path!r}"
            ) from exc
        if extra or _metadata_changed(initial_metadata, final_metadata):
            raise CorpusVerificationError(
                f"byte length or metadata changed while reading {locked_file.path!r}"
            )
    finally:
        os.close(descriptor)
    actual_digest = digest.hexdigest()
    if actual_digest != locked_file.sha256:
        raise CorpusVerificationError(
            f"SHA-256 mismatch for {locked_file.path!r}: "
            f"expected {locked_file.sha256}, got {actual_digest}"
        )
    return VerifiedFile(
        path=locked_file.path,
        bytes=locked_file.bytes,
        sha256=actual_digest,
    )


def _verification_declarations(
    lock: CompetitiveCorpusLock,
) -> tuple[LockedFile | SourceArtifact, ...]:
    declarations: list[LockedFile | SourceArtifact] = []
    seen: set[str] = set()
    for corpus in lock.corpora:
        for locked_file in (corpus.source, corpus.prepared, corpus.license.evidence):
            if locked_file.path not in seen:
                seen.add(locked_file.path)
                declarations.append(locked_file)
    return tuple(declarations)


def verify_competitive_corpus(
    lock_path: Path | str,
    root: Path | str,
    *,
    max_lock_bytes: int = MAX_LOCK_BYTES,
) -> CompetitiveCorpusVerification:
    """Securely reload a lock path and verify every declared local file.

    The API intentionally accepts a path, not a parsed dataclass. It atomically opens
    and reparses the exact manifest bytes used for this verification. On supported
    POSIX hosts, the lock, root, every intermediate directory, and every final file
    are opened descriptor-relatively with no-follow flags. Other platforms fail
    closed rather than reverting to path-based checks.
    """

    if isinstance(lock_path, CompetitiveCorpusLock) or not isinstance(lock_path, str | os.PathLike):
        raise TypeError("lock_path must be a filesystem path, not a parsed lock")
    if not isinstance(root, str | os.PathLike):
        raise TypeError("root must be a filesystem path")
    if type(max_lock_bytes) is not int or max_lock_bytes <= 0:
        raise ValueError("max_lock_bytes must be a positive integer")
    _require_secure_access(CorpusVerificationError)
    lock = load_competitive_corpus_lock(
        Path(lock_path),
        max_bytes=max_lock_bytes,
    )
    root_descriptor = _open_directory_path_secure(
        Path(root),
        "corpus root",
        CorpusVerificationError,
    )
    try:
        files = tuple(
            _verify_file_once(root_descriptor, locked_file)
            for locked_file in _verification_declarations(lock)
        )
    finally:
        os.close(root_descriptor)
    return CompetitiveCorpusVerification(
        contract_id=lock.contract_id,
        manifest_sha256=lock.manifest_sha256,
        corpus_ids=tuple(corpus.id for corpus in lock.corpora),
        files=files,
        total_verified_bytes=sum(verified.bytes for verified in files),
    )


__all__ = [
    "EXPECTED_CONTRACT_ID",
    "MAX_LOCK_BYTES",
    "MIN_PREPARED_BYTES",
    "REQUIRED_CORPUS_IDS",
    "CompetitiveCorpus",
    "CompetitiveCorpusLock",
    "CompetitiveCorpusVerification",
    "CorpusLockValidationError",
    "CorpusVerificationError",
    "LicenseRecord",
    "LockedFile",
    "PreparationParameter",
    "PreparationRecipe",
    "SourceArtifact",
    "VerifiedFile",
    "load_competitive_corpus_lock",
    "secure_local_verification_supported",
    "verify_competitive_corpus",
]
