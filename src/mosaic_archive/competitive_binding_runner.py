"""Fail-closed cgroup-v2 foundations for future binding benchmark evidence.

This module deliberately stops short of launching measured processes.  It qualifies a
Linux x86-64 host, creates an exact delegated cgroup leaf, and exposes population-safe
``memory.peak`` reads.  Those controls are necessary but not sufficient for binding
Competitive Contract v1 evidence: a native PID-namespace launcher and complete descendant
executable identity capture are still required.  Every value exposed here therefore remains
structurally non-binding.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from threading import RLock
from typing import Literal, NoReturn, TypeVar, cast

from .competitive_binding_io import (
    _MAX_CONTROL_BYTES,
    _BindingBackend,
    _DescriptorRelativeFilesystemBackend,
    _validate_leaf_name,
)
from .competitive_binding_policy import (
    _REQUIRED_CONTROLLERS,
    _THREAD_TIERS,
    BindingRunnerPolicy,
    fixed_binding_policy,
)

_MAX_CPUSET_ITEMS = 65_536
_MAX_SIGNED_64 = (1 << 63) - 1
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")
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


@dataclass(frozen=True, slots=True)
class BindingHostFacts:
    """Minimal host facts used to qualify an exact CPU lane."""

    os_name: str
    machine: str
    allowed_cpu_affinity: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.os_name) is not str or not self.os_name:
            raise TypeError("host OS name must be a non-empty string")
        if type(self.machine) is not str or not self.machine:
            raise TypeError("host machine must be a non-empty string")
        affinity = self.allowed_cpu_affinity
        if type(affinity) is not tuple or not affinity:
            raise ValueError("allowed CPU affinity must be a non-empty tuple")
        if any(type(cpu) is not int or cpu < 0 for cpu in affinity):
            raise ValueError("allowed CPU affinity must contain non-negative exact integers")
        if len(set(affinity)) != len(affinity):
            raise ValueError("allowed CPU affinity must not contain duplicates")


@dataclass(frozen=True, slots=True)
class BindingHostQualification:
    """A pinned host/cgroup qualification that remains explicitly non-binding."""

    policy: BindingRunnerPolicy
    cgroup_root: Path
    facts: BindingHostFacts
    requested_threads: int
    selected_cpus: tuple[int, ...]
    cpuset_cpus: str
    selected_mems: tuple[int, ...]
    cpuset_mems: str
    binding_eligible: Literal[False] = False
    _backend: _BindingBackend = field(repr=False, compare=False, default=None)  # type: ignore[assignment]
    _root_handle: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self.binding_eligible is not False:
            raise ValueError("cgroup host qualification is never binding-eligible")
        if type(self.policy) is not BindingRunnerPolicy:
            raise TypeError("qualification policy must be a BindingRunnerPolicy")
        if not isinstance(self.cgroup_root, Path) or not self.cgroup_root.is_absolute():
            raise ValueError("qualification cgroup root must be an absolute Path")
        if not isinstance(self.facts, BindingHostFacts):
            raise TypeError("qualification facts must be BindingHostFacts")
        if type(self.requested_threads) is not int or self.requested_threads not in _THREAD_TIERS:
            raise ValueError(f"requested threads must be exactly one of {_THREAD_TIERS!r}")
        if (
            type(self.selected_cpus) is not tuple
            or len(self.selected_cpus) != self.requested_threads
            or any(type(cpu) is not int or cpu < 0 for cpu in self.selected_cpus)
            or tuple(sorted(set(self.selected_cpus))) != self.selected_cpus
        ):
            raise ValueError("selected CPUs must be a sorted exact thread-count tuple")
        if not set(self.selected_cpus).issubset(self.facts.allowed_cpu_affinity):
            raise ValueError("selected CPUs must be within the allowed host affinity")
        if self.cpuset_cpus != _format_id_set(self.selected_cpus):
            raise ValueError("cpuset CPU text is not canonical")
        if (
            type(self.selected_mems) is not tuple
            or not self.selected_mems
            or any(type(node) is not int or node < 0 for node in self.selected_mems)
            or tuple(sorted(set(self.selected_mems))) != self.selected_mems
        ):
            raise ValueError("selected memory nodes must be a sorted non-empty tuple")
        if self.cpuset_mems != _format_id_set(self.selected_mems):
            raise ValueError("cpuset memory-node text is not canonical")
        if self._backend is None or self._root_handle is None:
            raise ValueError("qualification must retain its inspected cgroup root")


class _FilesystemBindingBackend(_DescriptorRelativeFilesystemBackend):
    def __init__(self) -> None:
        super().__init__(raise_combined_failures=_raise_combined_failures)


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


def _validate_requested_threads(requested_threads: int) -> None:
    if type(requested_threads) is not int or requested_threads not in _THREAD_TIERS:
        raise ValueError(f"requested threads must be exactly one of {_THREAD_TIERS!r}")


def qualify_binding_host(
    cgroup_root: Path,
    requested_threads: int,
    *,
    facts: BindingHostFacts | None = None,
    backend: object | None = None,
) -> BindingHostQualification:
    """Qualify a delegated cgroup-v2 root and select an exact 1/8-thread CPU lane."""
    _validate_requested_threads(requested_threads)
    if not isinstance(cgroup_root, Path):
        raise TypeError("cgroup root must be a Path")
    if not cgroup_root.is_absolute():
        raise ValueError("cgroup root must be absolute")
    selected_backend = cast(
        _BindingBackend,
        _FilesystemBindingBackend() if backend is None else backend,
    )
    if facts is None:
        os_name = _backend_call("failed to inspect host OS", selected_backend.system)
        machine = _backend_call("failed to inspect host machine", selected_backend.machine)
        affinity = _backend_call(
            "failed to inspect allowed CPU affinity",
            selected_backend.allowed_cpu_affinity,
        )
        facts = BindingHostFacts(
            os_name=os_name,
            machine=machine,
            allowed_cpu_affinity=affinity,
        )
    elif not isinstance(facts, BindingHostFacts):
        raise TypeError("facts must be BindingHostFacts")
    if facts.os_name != "Linux":
        raise BindingRunnerHostError("binding runner qualification requires Linux")
    if facts.machine.lower() not in {"x86_64", "amd64"}:
        raise BindingRunnerHostError("binding runner qualification requires x86_64")
    if len(facts.allowed_cpu_affinity) < requested_threads:
        raise BindingRunnerHostError(
            f"host affinity cannot supply the exact {requested_threads}-thread tier"
        )

    root_handle = _backend_call(
        "cgroup v2 delegated-root inspection failed",
        lambda: selected_backend.inspect_root(cgroup_root),
    )
    root_values: dict[str, str] = {}
    for filename in (
        "cgroup.controllers",
        "cgroup.subtree_control",
        "cgroup.type",
        "cpuset.cpus.effective",
        "cpuset.mems.effective",
    ):
        root_values[filename] = _backend_call(
            f"cgroup v2 root read failed for {filename}",
            partial(selected_backend.read_root, root_handle, filename),
        )

    controllers = _controller_names(
        root_values["cgroup.controllers"],
        "cgroup.controllers",
    )
    delegated = _controller_names(
        root_values["cgroup.subtree_control"],
        "cgroup.subtree_control",
    )
    for controller in _REQUIRED_CONTROLLERS:
        if controller not in controllers:
            raise BindingRunnerHostError(f"cgroup v2 root is missing the {controller} controller")
        if controller not in delegated:
            raise BindingRunnerHostError(f"cgroup v2 subtree delegation is missing {controller}")
    if _single_line(root_values["cgroup.type"], "cgroup.type") != "domain":
        raise BindingRunnerHostError("cgroup v2 root must be a domain cgroup")

    effective_cpus = _parse_id_set(
        root_values["cpuset.cpus.effective"],
        "effective CPU",
    )
    allowed = set(facts.allowed_cpu_affinity)
    candidates = tuple(cpu for cpu in effective_cpus if cpu in allowed)
    if len(candidates) < requested_threads:
        raise BindingRunnerHostError(
            f"effective CPU set cannot supply the exact {requested_threads}-thread tier"
        )
    selected_cpus = candidates[:requested_threads]
    selected_mems = _parse_id_set(
        root_values["cpuset.mems.effective"],
        "effective memory-node",
    )
    return BindingHostQualification(
        policy=fixed_binding_policy(),
        cgroup_root=cgroup_root,
        facts=facts,
        requested_threads=requested_threads,
        selected_cpus=selected_cpus,
        cpuset_cpus=_format_id_set(selected_cpus),
        selected_mems=selected_mems,
        cpuset_mems=_format_id_set(selected_mems),
        binding_eligible=False,
        _backend=selected_backend,
        _root_handle=root_handle,
    )


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


class BindingCgroupLease:
    """A fresh cgroup leaf with fail-closed lifecycle and memory-peak operations."""

    __slots__ = (
        "_backend",
        "_closed",
        "_leaf_handle",
        "_lock",
        "_root_handle",
        "_state",
        "leaf_name",
        "qualification",
    )

    def __init__(
        self,
        *,
        qualification: BindingHostQualification,
        leaf_name: str,
        backend: _BindingBackend,
        root_handle: object,
        leaf_handle: object,
    ) -> None:
        self.qualification = qualification
        self.leaf_name = leaf_name
        self._backend = backend
        self._root_handle = root_handle
        self._leaf_handle = leaf_handle
        self._closed = False
        self._lock = RLock()
        self._state = "ready"

    @property
    def binding_eligible(self) -> Literal[False]:
        return False

    def _require_open(self) -> None:
        if self._closed:
            raise BindingRunnerHostError("cgroup lease is closed")

    def _require_state(self, expected: str, operation: str) -> None:
        if self._state != expected:
            raise BindingRunnerHostError(
                f"cannot {operation} while cgroup lease state is {self._state!r}"
            )

    def _read_leaf(self, filename: str) -> str:
        return _backend_call(
            f"failed to read {filename}",
            lambda: self._backend.read_leaf(self._leaf_handle, filename),
        )

    def _is_populated(self) -> bool:
        value = self._read_leaf("cgroup.events")
        if type(value) is not str or len(value.encode("utf-8")) > _MAX_CONTROL_BYTES:
            raise BindingRunnerHostError("cgroup.events is not bounded text")
        populated: int | None = None
        for line in value.splitlines():
            fields = line.split(" ")
            if len(fields) != 2 or not fields[0] or fields[1] not in {"0", "1"}:
                raise BindingRunnerHostError("cgroup.events is malformed")
            if fields[0] == "populated":
                if populated is not None:
                    raise BindingRunnerHostError("cgroup.events repeats populated")
                populated = int(fields[1])
        if populated is None:
            raise BindingRunnerHostError("cgroup.events does not report populated")
        return populated == 1

    def attach_process(self, pid: int) -> None:
        if type(pid) is not int or pid <= 0:
            raise ValueError("process ID must be a positive exact integer")
        with self._lock:
            self._require_open()
            self._require_state("ready", "attach a process")
            self.verify_effective_cpuset()
            self._state = "attachment-uncertain"
            value = str(pid)
            _write_exact(self._backend, self._leaf_handle, "cgroup.procs", value)
            observed = self._read_leaf("cgroup.procs")
            members: set[int] = set()
            for line in observed.splitlines():
                if _POSITIVE_INTEGER_RE.fullmatch(line) is None:
                    raise BindingRunnerHostError("cgroup.procs membership readback is malformed")
                members.add(int(line))
            if pid not in members:
                raise BindingRunnerHostError(
                    f"cgroup.procs membership readback does not contain process {pid}"
                )
            self._state = "attached"

    def verify_effective_cpuset(self) -> None:
        with self._lock:
            self._require_open()
            _verify_effective_id_set(
                self._backend,
                self._leaf_handle,
                filename="cpuset.cpus.effective",
                expected=self.qualification.selected_cpus,
                context="child CPU",
            )
            _verify_effective_id_set(
                self._backend,
                self._leaf_handle,
                filename="cpuset.mems.effective",
                expected=self.qualification.selected_mems,
                context="child memory-node",
            )

    def read_memory_peak_bytes(self) -> int:
        with self._lock:
            self._require_open()
            self._require_state("attached", "finalize memory.peak")
            self._state = "finalizing"
            self.await_unpopulated()
            self.verify_effective_cpuset()
            if self._is_populated():
                raise BindingRunnerHostError("cgroup became populated before memory.peak capture")
            value = _control_scalar(self._read_leaf("memory.peak"), "memory.peak")
            if self._is_populated():
                raise BindingRunnerHostError("cgroup became populated during memory.peak capture")
            self.verify_effective_cpuset()
            if _POSITIVE_INTEGER_RE.fullmatch(value) is None:
                raise BindingRunnerHostError("memory.peak is not a canonical positive integer")
            result = int(value)
            if result > _MAX_SIGNED_64:
                raise BindingRunnerHostError("memory.peak exceeds the signed 64-bit bound")
            self._state = "measured"
            return result

    def await_unpopulated(self) -> None:
        with self._lock:
            self._require_open()
            policy = self.qualification.policy
            deadline = (
                _backend_call(
                    "failed to read cleanup clock",
                    self._backend.monotonic,
                )
                + policy.cleanup_timeout_seconds
            )
            poll_seconds = policy.cleanup_poll_interval_milliseconds / 1000
            while self._is_populated():
                now = _backend_call(
                    "failed to read cleanup clock",
                    self._backend.monotonic,
                )
                if now >= deadline:
                    raise BindingRunnerHostError(
                        "cgroup cleanup timed out while the leaf remained populated"
                    )
                _backend_call(
                    "cgroup cleanup polling failed",
                    lambda: self._backend.sleep(poll_seconds),
                )

    def kill(self) -> None:
        with self._lock:
            self._require_open()
            self._state = "termination-requested"
            _write_exact(self._backend, self._leaf_handle, "cgroup.kill", "1")

    def cleanup(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._is_populated():
                self.kill()
            self.await_unpopulated()
            _backend_call(
                "failed to remove cgroup leaf",
                lambda: self._backend.remove_leaf(self._root_handle, self._leaf_handle),
            )
            self._closed = True

    def __enter__(self) -> BindingCgroupLease:
        with self._lock:
            self._require_open()
            return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> Literal[False]:
        try:
            self.cleanup()
        except BaseException as cleanup_error:
            if _exception is None:
                raise
            _raise_combined_failures(
                "cgroup body and cleanup both failed",
                primary_error=_exception,
                cleanup_error=cleanup_error,
            )
        return False


def create_binding_cgroup(
    qualification: BindingHostQualification,
    *,
    leaf_name: str,
    backend: object | None = None,
) -> BindingCgroupLease:
    """Refuse production mutation until the native isolation capability exists."""
    if not isinstance(qualification, BindingHostQualification):
        raise TypeError("qualification must be BindingHostQualification")
    selected_backend = qualification._backend
    if backend is not None and backend is not selected_backend:
        raise ValueError("cgroup creation must use the backend that inspected the root")
    _validate_leaf_name(leaf_name, qualification.policy)
    raise BindingRunnerHostError(
        "production cgroup creation is disabled until the native supervisor "
        "supplies an exclusive delegated-root capability with workload UID "
        "or mount-namespace isolation"
    )


def _create_binding_cgroup_for_testing(
    qualification: BindingHostQualification,
    *,
    leaf_name: str,
    backend: object,
) -> BindingCgroupLease:
    """Exercise qualification-only lifecycle logic without a production mutation API."""
    if not isinstance(qualification, BindingHostQualification):
        raise TypeError("qualification must be BindingHostQualification")
    selected_backend = qualification._backend
    if backend is not selected_backend:
        raise ValueError("cgroup creation must use the backend that inspected the root")
    _validate_leaf_name(leaf_name, qualification.policy)
    leaf_handle = _backend_call(
        "fresh cgroup leaf creation failed",
        lambda: selected_backend.create_leaf(qualification._root_handle, leaf_name),
    )
    try:
        for filename, value in (
            ("cpuset.mems", qualification.cpuset_mems),
            ("cpuset.cpus", qualification.cpuset_cpus),
            ("pids.max", str(qualification.policy.pids_max)),
            ("memory.max", str(qualification.policy.memory_max_bytes)),
            ("memory.swap.max", str(qualification.policy.memory_swap_max_bytes)),
        ):
            _write_and_verify(selected_backend, leaf_handle, filename, value)
        _verify_effective_id_set(
            selected_backend,
            leaf_handle,
            filename="cpuset.cpus.effective",
            expected=qualification.selected_cpus,
            context="child CPU",
        )
        _verify_effective_id_set(
            selected_backend,
            leaf_handle,
            filename="cpuset.mems.effective",
            expected=qualification.selected_mems,
            context="child memory-node",
        )
        initial_peak = _backend_call(
            "initial memory.peak read failed",
            lambda: selected_backend.read_leaf(leaf_handle, "memory.peak"),
        )
        if _control_scalar(initial_peak, "memory.peak") != "0":
            raise BindingRunnerHostError("fresh unpopulated cgroup memory.peak must start at zero")
    except BaseException as setup_error:
        try:
            selected_backend.remove_leaf(qualification._root_handle, leaf_handle)
        except BaseException as cleanup_error:
            _raise_combined_failures(
                "cgroup setup and fresh-leaf cleanup both failed",
                primary_error=setup_error,
                cleanup_error=cleanup_error,
            )
        if isinstance(setup_error, BindingRunnerHostError):
            raise
        if not isinstance(setup_error, Exception):
            raise
        raise BindingRunnerHostError(f"cgroup leaf setup failed: {setup_error}") from setup_error
    return BindingCgroupLease(
        qualification=qualification,
        leaf_name=leaf_name,
        backend=selected_backend,
        root_handle=qualification._root_handle,
        leaf_handle=leaf_handle,
    )
