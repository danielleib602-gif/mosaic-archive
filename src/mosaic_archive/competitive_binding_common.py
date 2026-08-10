"""Shared fail-closed control primitives for the binding runner."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import NoReturn, TypeVar

from .competitive_binding_io import _MAX_CONTROL_BYTES, _BindingBackend

_MAX_CPUSET_ITEMS = 65_536
_CPUSET_COMPONENT_RE = re.compile(r"([0-9]+)(?:-([0-9]+))?\Z")

_T = TypeVar("_T")


class BindingRunnerHostError(RuntimeError):
    """The host or delegated cgroup cannot satisfy the fixed runner policy."""


class BindingRunnerCleanupError(BindingRunnerHostError):
    """A primary operation and its required cleanup both failed."""

    def __init__(
        self,
        context: str,
        *,
        primary_error: BaseException,
        cleanup_error: BaseException,
    ) -> None:
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error
        super().__init__(
            f"{context}: primary {type(primary_error).__name__}: {primary_error}; "
            f"cleanup {type(cleanup_error).__name__}: {cleanup_error}"
        )


def _raise_combined_failures(
    context: str,
    *,
    primary_error: BaseException,
    cleanup_error: BaseException,
) -> NoReturn:
    if isinstance(primary_error, Exception) and isinstance(cleanup_error, Exception):
        raise BindingRunnerCleanupError(
            context,
            primary_error=primary_error,
            cleanup_error=cleanup_error,
        ) from cleanup_error
    raise BaseExceptionGroup(context, [primary_error, cleanup_error]) from cleanup_error


def _backend_call(context: str, operation: Callable[[], _T]) -> _T:
    try:
        return operation()
    except BindingRunnerHostError:
        raise
    except Exception as error:
        raise BindingRunnerHostError(f"{context}: {error}") from error


def _single_line(value: str, context: str) -> str:
    if type(value) is not str:
        raise BindingRunnerHostError(f"{context} did not return text")
    if len(value.encode("utf-8")) > _MAX_CONTROL_BYTES:
        raise BindingRunnerHostError(f"{context} exceeds the bounded read limit")
    if value.endswith("\n"):
        value = value[:-1]
    if "\n" in value or "\r" in value or "\x00" in value:
        raise BindingRunnerHostError(f"{context} is not canonical single-line text")
    return value


def _parse_id_set(value: str, context: str) -> tuple[int, ...]:
    text = _single_line(value, context)
    if not text:
        raise BindingRunnerHostError(f"{context} set is empty")
    result: list[int] = []
    for component in text.split(","):
        match = _CPUSET_COMPONENT_RE.fullmatch(component)
        if match is None:
            raise BindingRunnerHostError(f"{context} set is malformed")
        start = int(match.group(1))
        end = int(match.group(2) or match.group(1))
        if start > end:
            raise BindingRunnerHostError(f"{context} range is descending")
        count = end - start + 1
        if count > _MAX_CPUSET_ITEMS or len(result) + count > _MAX_CPUSET_ITEMS:
            raise BindingRunnerHostError(f"{context} set exceeds the supported bound")
        result.extend(range(start, end + 1))
    parsed = tuple(result)
    if tuple(sorted(set(parsed))) != parsed or _format_id_set(parsed) != text:
        raise BindingRunnerHostError(f"{context} set is not canonical")
    return parsed


def _format_id_set(values: tuple[int, ...]) -> str:
    if not values:
        return ""
    ranges: list[str] = []
    start = values[0]
    previous = start
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = value
        previous = value
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _controller_names(value: str, context: str) -> frozenset[str]:
    text = _single_line(value, context)
    if not text:
        return frozenset()
    names = text.split(" ")
    if any(not name or re.fullmatch(r"[a-z0-9_]+", name) is None for name in names) or len(
        set(names)
    ) != len(names):
        raise BindingRunnerHostError(f"{context} is malformed")
    return frozenset(names)


def _control_scalar(value: str, filename: str) -> str:
    return _single_line(value, filename)


def _write_exact(
    backend: _BindingBackend,
    leaf: object,
    filename: str,
    value: str,
) -> None:
    expected_bytes = len(value.encode("ascii"))
    written = _backend_call(
        f"exact write to {filename} failed",
        lambda: backend.write_leaf(leaf, filename, value),
    )
    if type(written) is not int or written != expected_bytes:
        raise BindingRunnerHostError(
            f"exact write to {filename} wrote {written!r} of {expected_bytes} bytes"
        )


def _write_and_verify(
    backend: _BindingBackend,
    leaf: object,
    filename: str,
    value: str,
) -> None:
    _write_exact(backend, leaf, filename, value)
    observed = _backend_call(
        f"readback of {filename} failed",
        lambda: backend.read_leaf(leaf, filename),
    )
    if _control_scalar(observed, filename) != value:
        raise BindingRunnerHostError(f"exact readback mismatch for {filename}")


def _verify_effective_id_set(
    backend: _BindingBackend,
    leaf: object,
    *,
    filename: str,
    expected: tuple[int, ...],
    context: str,
) -> None:
    observed = _backend_call(
        f"failed to read {filename}",
        lambda: backend.read_leaf(leaf, filename),
    )
    actual = _parse_id_set(observed, context)
    if actual != expected:
        raise BindingRunnerHostError(
            f"{context} effective-set mismatch: expected "
            f"{_format_id_set(expected)!r}, observed {_format_id_set(actual)!r}"
        )
