"""Fail-closed provisional diagnostics for Competitive Contract v1 development.

The sampler is intentionally non-binding. It observes a Linux process group from ``/proc``,
but sampling cannot prove containment, enforce the requested CPU/thread tier, or retain the
complete environment and descendant executable identities required by the contract. Its
results therefore cannot complete the competitive readiness gate. A future authoritative
runner must add kernel-enforced cgroup/PID containment and fixed evidence collection.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import platform
import re
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

_VALID_THREAD_TIERS = frozenset((1, 8))
_MIN_SAMPLE_INTERVAL_SECONDS = 0.001
_MAX_SAMPLE_INTERVAL_SECONDS = 0.250
_KILL_WAIT_SECONDS = 5.0
_READ_CHUNK_BYTES = 1024 * 1024
_MAX_LINUX_FACT_BYTES = 16 * 1024 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_PUBLIC_ENV_POLICY_ID = "public-diagnostic-env-v1"
_PUBLIC_ENV_KEYS = frozenset(
    {
        "BLIS_NUM_THREADS",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "OMP_NUM_THREADS",
        "OMP_THREAD_LIMIT",
        "OPENBLAS_NUM_THREADS",
        "PATH",
        "PYTHONHASHSEED",
        "PYTHONUTF8",
        "RAYON_NUM_THREADS",
        "SOURCE_DATE_EPOCH",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "VECLIB_MAXIMUM_THREADS",
        "XDG_CONFIG_HOME",
        "ZSTD_NBTHREADS",
    }
)

TerminationReason = Literal[
    "exited",
    "timeout",
    "process-group-escape",
    "daemonization",
]


class _BinaryDigestStream(Protocol):
    def flush(self) -> None: ...

    def seek(self, offset: int, whence: int = 0) -> int: ...

    def read(self, size: int = -1) -> bytes: ...


class CompetitiveRunnerError(RuntimeError):
    """Base class for provisional competitive-runner failures."""


class ProvisionalRunnerHostError(CompetitiveRunnerError):
    """The current host cannot produce provisional Linux diagnostics."""


class MeasurementVerificationError(CompetitiveRunnerError):
    """A process result or restored payload failed exact verification."""


class ProcessIsolationError(CompetitiveRunnerError):
    """A measured process violated, or could not prove, process-group isolation."""

    def __init__(self, message: str, *, result: ProcessRunResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True, slots=True)
class ProvisionalHardwareFingerprint:
    """Hardware and kernel facts retained with a provisional diagnostic."""

    os_name: str
    kernel_release: str
    kernel_version: str
    machine: str
    cpu_model: str | None
    logical_cpu_count: int
    allowed_cpu_count: int
    allowed_cpu_affinity: tuple[int, ...]
    total_ram_bytes: int
    cpu_governors: tuple[tuple[int, str], ...]

    def __post_init__(self) -> None:
        if self.allowed_cpu_count != len(self.allowed_cpu_affinity):
            raise ValueError("allowed CPU count must match the recorded affinity")


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Identity of the fresh process leading a measurement session."""

    pid: int
    process_group_id: int
    session_id: int
    start_time_ticks: int
    executable: str
    executable_sha256: str


@dataclass(frozen=True, slots=True)
class StreamDigest:
    """A bounded-memory summary of one captured byte stream."""

    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.sha256) is None:
            raise ValueError("stream SHA-256 must be 64 lowercase hexadecimal characters")
        if self.byte_count < 0:
            raise ValueError("stream byte count cannot be negative")


@dataclass(frozen=True, slots=True)
class ProcessRunResult:
    """Immutable, non-binding observation from one fresh measured process."""

    argv: tuple[str, ...]
    cwd: str
    requested_threads: int
    hardware: ProvisionalHardwareFingerprint
    identity: ProcessIdentity
    wall_time_seconds: float
    peak_process_tree_rss_bytes: int
    returncode: int
    timed_out: bool
    termination_reason: TerminationReason
    observed_pids: tuple[int, ...]
    stdout: StreamDigest
    stderr: StreamDigest
    sample_interval_seconds: float = 0.010
    environment_policy_id: str = _PUBLIC_ENV_POLICY_ID
    public_environment: tuple[tuple[str, str], ...] = ()
    public_environment_sha256: str = _EMPTY_SHA256
    evidence_class: Literal["diagnostic"] = "diagnostic"
    binding_eligible: Literal[False] = False

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("process result argv cannot be empty")
        validate_requested_threads(self.requested_threads)
        if not math.isfinite(self.wall_time_seconds) or self.wall_time_seconds < 0:
            raise ValueError("wall time must be a finite non-negative number")
        if self.peak_process_tree_rss_bytes < 0:
            raise ValueError("peak process-tree RSS cannot be negative")
        if self.timed_out != (self.termination_reason == "timeout"):
            raise ValueError("timeout flag and termination reason disagree")
        if tuple(sorted(set(self.observed_pids))) != self.observed_pids:
            raise ValueError("observed PIDs must be sorted and unique")
        if (
            not math.isfinite(self.sample_interval_seconds)
            or not _MIN_SAMPLE_INTERVAL_SECONDS
            <= self.sample_interval_seconds
            <= _MAX_SAMPLE_INTERVAL_SECONDS
        ):
            raise ValueError("sample interval is outside the diagnostic runner bounds")
        if self.environment_policy_id != _PUBLIC_ENV_POLICY_ID:
            raise ValueError("environment policy ID is not the fixed public policy")
        if tuple(sorted(self.public_environment)) != self.public_environment:
            raise ValueError("public environment must be sorted by key")
        if len({key for key, _value in self.public_environment}) != len(
            self.public_environment
        ):
            raise ValueError("public environment keys must be unique")
        if any(key not in _PUBLIC_ENV_KEYS for key, _value in self.public_environment):
            raise ValueError("public environment contains a key outside its policy")
        if _SHA256_RE.fullmatch(self.public_environment_sha256) is None:
            raise ValueError("public environment SHA-256 is not canonical")
        if self.public_environment_sha256 != _environment_sha256(
            dict(self.public_environment)
        ):
            raise ValueError("public environment digest does not match its recorded values")
        if self.evidence_class != "diagnostic":
            raise ValueError("provisional process observations must be diagnostic")
        if self.binding_eligible is not False:
            raise ValueError("provisional process observations are never binding-eligible")


@dataclass(frozen=True, slots=True, init=False)
class ProvisionalMeasurement:
    """A non-binding process observation coupled to restored-payload verification.

    Construction rejects a result that reports timeout, non-zero exit, or isolation failure,
    and it verifies the restored payload hash. This structural/hash check is not attestation,
    and exact restoration does not make the sampled process observation binding-eligible.
    """

    process: ProcessRunResult
    restored_payload_path: str
    expected_payload_sha256: str
    restored_payload_sha256: str
    restored_payload_bytes: int
    binding_eligible: Literal[False]

    def __init__(
        self,
        *,
        process: ProcessRunResult,
        restored_payload: str | os.PathLike[str],
        expected_payload_sha256: str,
    ) -> None:
        if process.timed_out:
            raise MeasurementVerificationError("measured process timed out")
        if process.termination_reason != "exited":
            raise MeasurementVerificationError(
                f"measured process ended due to {process.termination_reason}"
            )
        if process.returncode != 0:
            raise MeasurementVerificationError(
                f"measured process returned exit status {process.returncode}"
            )
        _require_sha256(expected_payload_sha256, label="expected payload")
        try:
            payload_path = Path(restored_payload).resolve(strict=True)
            actual_sha256, payload_bytes = _sha256_file(payload_path)
        except (OSError, ValueError) as error:
            raise MeasurementVerificationError(
                f"restored payload could not be verified: {error}"
            ) from error
        if not hmac.compare_digest(actual_sha256, expected_payload_sha256):
            raise MeasurementVerificationError(
                "restored payload hash mismatch: "
                f"expected {expected_payload_sha256}, observed {actual_sha256}"
            )
        object.__setattr__(self, "process", process)
        object.__setattr__(self, "restored_payload_path", str(payload_path))
        object.__setattr__(self, "expected_payload_sha256", expected_payload_sha256)
        object.__setattr__(self, "restored_payload_sha256", actual_sha256)
        object.__setattr__(self, "restored_payload_bytes", payload_bytes)
        object.__setattr__(self, "binding_eligible", False)


@dataclass(frozen=True, slots=True)
class _ProcSnapshot:
    pid: int
    parent_pid: int
    process_group_id: int
    session_id: int
    state: str
    start_time_ticks: int
    rss_bytes: int

    @property
    def identity(self) -> tuple[int, int]:
        return (self.pid, self.start_time_ticks)


@dataclass(frozen=True, slots=True)
class _ProcessObservation:
    process_group_rss_bytes: int
    group_member_identities: tuple[tuple[int, int], ...]
    live_group_member_identities: tuple[tuple[int, int], ...]
    escaped_identities: tuple[tuple[int, int], ...]
    known_identities: frozenset[tuple[int, int]]

    @property
    def group_member_pids(self) -> tuple[int, ...]:
        return tuple(pid for pid, _start_time in self.group_member_identities)

    @property
    def live_group_member_pids(self) -> tuple[int, ...]:
        return tuple(pid for pid, _start_time in self.live_group_member_identities)

    @property
    def escaped_pids(self) -> tuple[int, ...]:
        return tuple(pid for pid, _start_time in self.escaped_identities)


def validate_requested_threads(requested_threads: int) -> int:
    """Validate contract thread-tier metadata without claiming CPU enforcement."""

    if type(requested_threads) is not int or requested_threads not in _VALID_THREAD_TIERS:
        raise ValueError("requested_threads must be exactly 1 or 8")
    return requested_threads


def capture_provisional_hardware() -> ProvisionalHardwareFingerprint:
    """Capture current host facts without inferring unavailable Linux information."""

    affinity = _current_allowed_affinity()
    logical_cpu_count = os.cpu_count()
    if logical_cpu_count is None or logical_cpu_count < 1:
        raise ProvisionalRunnerHostError("logical CPU count is unavailable")
    cpuinfo = _read_text(Path("/proc/cpuinfo"))
    meminfo = _read_text(Path("/proc/meminfo"))
    total_ram_bytes = _parse_mem_total_bytes(meminfo or "")
    if total_ram_bytes is None:
        raise ProvisionalRunnerHostError("total RAM is unavailable from /proc/meminfo")
    governors: list[tuple[int, str]] = []
    for cpu in affinity:
        governor_path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
        governor_text = _read_text(governor_path)
        if governor_text is not None and (governor := governor_text.strip()):
            governors.append((cpu, governor))
    return ProvisionalHardwareFingerprint(
        os_name=platform.system(),
        kernel_release=platform.release(),
        kernel_version=platform.version(),
        machine=platform.machine(),
        cpu_model=_parse_cpu_model(cpuinfo or ""),
        logical_cpu_count=logical_cpu_count,
        allowed_cpu_count=len(affinity),
        allowed_cpu_affinity=affinity,
        total_ram_bytes=total_ram_bytes,
        cpu_governors=tuple(governors),
    )


def validate_provisional_host(
    requested_threads: int,
    *,
    fingerprint: ProvisionalHardwareFingerprint | None = None,
) -> ProvisionalHardwareFingerprint:
    """Validate and return the current provisional host fingerprint.

    ``fingerprint`` exists for pure validation and tests.  ``run_provisional_process`` never
    supplies it and therefore always captures the current host immediately before spawning.
    """

    threads = validate_requested_threads(requested_threads)
    if fingerprint is None:
        current_system = platform.system()
        if current_system.lower() != "linux":
            raise ProvisionalRunnerHostError(
                f"provisional measurement requires Linux; found {current_system or 'unknown'}"
            )
        current_machine = platform.machine()
        if current_machine.lower() not in {"x86_64", "amd64"}:
            raise ProvisionalRunnerHostError(
                "provisional measurement requires x86_64/AMD64; "
                f"found {current_machine or 'unknown'}"
            )
        fingerprint = capture_provisional_hardware()
    if fingerprint.os_name.lower() != "linux":
        raise ProvisionalRunnerHostError(
            f"provisional measurement requires Linux; found {fingerprint.os_name or 'unknown'}"
        )
    if fingerprint.machine.lower() not in {"x86_64", "amd64"}:
        raise ProvisionalRunnerHostError(
            "provisional measurement requires x86_64/AMD64; "
            f"found {fingerprint.machine or 'unknown'}"
        )
    affinity = fingerprint.allowed_cpu_affinity
    if (
        not affinity
        or any(type(cpu) is not int or cpu < 0 for cpu in affinity)
        or len(set(affinity)) != len(affinity)
    ):
        raise ProvisionalRunnerHostError("current allowed CPU affinity is invalid or unavailable")
    if fingerprint.logical_cpu_count < 1:
        raise ProvisionalRunnerHostError("logical CPU count is invalid or unavailable")
    if fingerprint.total_ram_bytes < 1:
        raise ProvisionalRunnerHostError("total RAM is invalid or unavailable")
    if fingerprint.allowed_cpu_count < threads:
        raise ProvisionalRunnerHostError(
            f"{threads}-thread provisional tier requires at least {threads} CPUs in the "
            f"current allowed affinity; found {fingerprint.allowed_cpu_count}"
        )
    return fingerprint


def run_provisional_process(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str],
    env: Mapping[str, str],
    requested_threads: int,
    timeout_seconds: float,
    sample_interval_seconds: float = 0.010,
) -> ProcessRunResult:
    """Run one process and sample its observable Linux process group.

    Standard streams go to temporary files and are hashed using fixed-size reads after the
    process has ended. No output payload is accumulated in Python memory. Unobserved escapes,
    CPU/thread enforcement, and complete configuration retention remain out of scope, so the
    result is explicitly non-binding.
    """

    normalized_argv = _normalize_argv(argv)
    normalized_cwd = _normalize_cwd(cwd)
    normalized_env = _normalize_env(env)
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a finite positive number")
    if (
        not math.isfinite(sample_interval_seconds)
        or not _MIN_SAMPLE_INTERVAL_SECONDS
        <= sample_interval_seconds
        <= _MAX_SAMPLE_INTERVAL_SECONDS
    ):
        raise ValueError(
            "sample_interval_seconds must be between "
            f"{_MIN_SAMPLE_INTERVAL_SECONDS} and {_MAX_SAMPLE_INTERVAL_SECONDS}"
        )
    hardware = validate_provisional_host(requested_threads)
    threads = validate_requested_threads(requested_threads)

    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        identity: ProcessIdentity | None = None
        known_identities: frozenset[tuple[int, int]] = frozenset()
        observed_pids: set[int] = set()
        peak_rss = 0
        termination_reason: TerminationReason = "exited"
        isolation_message: str | None = None
        latest_escaped_identities: tuple[tuple[int, int], ...] = ()
        try:
            process = subprocess.Popen(
                normalized_argv,
                cwd=str(normalized_cwd),
                env=normalized_env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                close_fds=True,
                restore_signals=True,
                start_new_session=True,
            )
            identity = _capture_process_identity(process.pid, process.pid)
            if (
                identity.pid != process.pid
                or identity.process_group_id != process.pid
                or identity.session_id != process.pid
            ):
                raise ProcessIsolationError(
                    "fresh process did not lead its requested process group and session"
                )
            deadline = started + timeout_seconds
            while True:
                observation = _observe_processes(
                    _read_proc_snapshots(),
                    root_pid=identity.pid,
                    root_start_time_ticks=identity.start_time_ticks,
                    known_identities=known_identities,
                )
                known_identities = observation.known_identities
                observed_pids.update(pid for pid, _start_time in known_identities)
                peak_rss = max(peak_rss, observation.process_group_rss_bytes)
                latest_escaped_identities = observation.escaped_identities
                if observation.escaped_pids:
                    termination_reason = "process-group-escape"
                    isolation_message = "measured descendant escaped process group: " + ", ".join(
                        str(pid) for pid in observation.escaped_pids
                    )
                    _kill_measured_processes(process, observation.escaped_identities)
                    break

                returncode = process.poll()
                if returncode is not None:
                    identities_known_before_root_exit = known_identities
                    final_observation = _observe_processes(
                        _read_proc_snapshots(),
                        root_pid=identity.pid,
                        root_start_time_ticks=identity.start_time_ticks,
                        known_identities=known_identities,
                    )
                    known_identities = final_observation.known_identities
                    observed_pids.update(pid for pid, _start_time in known_identities)
                    peak_rss = max(peak_rss, final_observation.process_group_rss_bytes)
                    latest_escaped_identities = final_observation.escaped_identities
                    if final_observation.escaped_pids:
                        termination_reason = "process-group-escape"
                        isolation_message = (
                            "measured descendant escaped process group: "
                            + ", ".join(str(pid) for pid in final_observation.escaped_pids)
                        )
                        for escaped_identity in final_observation.escaped_identities:
                            if escaped_identity in identities_known_before_root_exit:
                                _send_identity_sigkill(escaped_identity)
                    else:
                        leftover_identities = tuple(
                            member_identity
                            for member_identity in final_observation.live_group_member_identities
                            if member_identity != (identity.pid, identity.start_time_ticks)
                        )
                        if leftover_identities:
                            termination_reason = "daemonization"
                            isolation_message = (
                                "measured process exited while descendants remained: "
                                + ", ".join(str(pid) for pid, _start_time in leftover_identities)
                            )
                            for leftover_identity in leftover_identities:
                                if leftover_identity in identities_known_before_root_exit:
                                    _send_identity_sigkill(leftover_identity)
                    break

                now = time.monotonic()
                if now >= deadline:
                    termination_reason = "timeout"
                    identities_known_before_timeout_kill = known_identities
                    _kill_measured_processes(process, ())
                    final_observation = _observe_processes(
                        _read_proc_snapshots(),
                        root_pid=identity.pid,
                        root_start_time_ticks=identity.start_time_ticks,
                        known_identities=known_identities,
                    )
                    known_identities = final_observation.known_identities
                    observed_pids.update(pid for pid, _start_time in known_identities)
                    peak_rss = max(peak_rss, final_observation.process_group_rss_bytes)
                    if final_observation.escaped_identities:
                        for escaped_identity in final_observation.escaped_identities:
                            if escaped_identity in identities_known_before_timeout_kill:
                                _send_identity_sigkill(escaped_identity)
                        raise ProcessIsolationError(
                            "measured descendant escaped during timeout cleanup: "
                            + ", ".join(str(pid) for pid in final_observation.escaped_pids)
                        )
                    timeout_leftover_identities = tuple(
                        member_identity
                        for member_identity in final_observation.live_group_member_identities
                        if member_identity != (identity.pid, identity.start_time_ticks)
                    )
                    if timeout_leftover_identities:
                        for leftover_identity in timeout_leftover_identities:
                            if leftover_identity in identities_known_before_timeout_kill:
                                _send_identity_sigkill(leftover_identity)
                        raise ProcessIsolationError(
                            "measured descendants remained after timeout SIGKILL: "
                            + ", ".join(
                                str(pid) for pid, _start_time in timeout_leftover_identities
                            )
                        )
                    break
                time.sleep(min(sample_interval_seconds, deadline - now))
        except BaseException:
            if process is not None and process.poll() is None:
                with suppress(CompetitiveRunnerError):
                    _kill_measured_processes(process, latest_escaped_identities)
            raise

        if process is None or identity is None or process.returncode is None:
            raise ProcessIsolationError("measured process did not yield a complete exit status")
        wall_time_seconds = time.monotonic() - started
        result = ProcessRunResult(
            argv=normalized_argv,
            cwd=str(normalized_cwd),
            requested_threads=threads,
            hardware=hardware,
            identity=identity,
            wall_time_seconds=wall_time_seconds,
            peak_process_tree_rss_bytes=peak_rss,
            returncode=process.returncode,
            timed_out=termination_reason == "timeout",
            termination_reason=termination_reason,
            observed_pids=tuple(sorted(observed_pids | {identity.pid})),
            stdout=_digest_stream(stdout_file),
            stderr=_digest_stream(stderr_file),
            sample_interval_seconds=sample_interval_seconds,
            public_environment=tuple(sorted(normalized_env.items())),
            public_environment_sha256=_environment_sha256(normalized_env),
        )
        if isolation_message is not None:
            raise ProcessIsolationError(isolation_message, result=result)
        return result


def _normalize_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, str | bytes):
        raise TypeError("argv must be a sequence of strings, not a shell command")
    normalized = tuple(argv)
    if not normalized:
        raise ValueError("argv cannot be empty")
    for index, argument in enumerate(normalized):
        if not isinstance(argument, str):
            raise TypeError(f"argv[{index}] must be a string")
        if "\x00" in argument:
            raise ValueError(f"argv[{index}] contains a null byte")
    if not normalized[0]:
        raise ValueError("argv[0] cannot be empty")
    return normalized


def _normalize_cwd(cwd: str | os.PathLike[str]) -> Path:
    try:
        normalized = Path(cwd).resolve(strict=True)
    except OSError as error:
        raise ValueError(f"cwd does not exist: {cwd}") from error
    if not normalized.is_dir():
        raise ValueError(f"cwd is not a directory: {normalized}")
    return normalized


def _normalize_env(env: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("environment keys and values must be strings")
        if not key or "=" in key or "\x00" in key:
            raise ValueError(f"invalid environment key: {key!r}")
        if "\x00" in value:
            raise ValueError(f"environment value for {key!r} contains a null byte")
        if key not in _PUBLIC_ENV_KEYS:
            raise ValueError(
                f"environment key {key!r} is not allowed by {_PUBLIC_ENV_POLICY_ID}"
            )
        normalized[key] = value
    return normalized


def _environment_sha256(env: Mapping[str, str]) -> str:
    """Hash the explicitly public environment that is also retained in the result."""

    digest = hashlib.sha256()
    for key, value in sorted(env.items()):
        for field in (key, value):
            encoded = field.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def _require_sha256(value: str, *, label: str) -> None:
    if _SHA256_RE.fullmatch(value) is None:
        raise MeasurementVerificationError(
            f"{label} SHA-256 must be 64 lowercase hexadecimal characters"
        )


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"not a regular file: {path}")
        while chunk := stream.read(_READ_CHUNK_BYTES):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def _sha256_fd(file_descriptor: int) -> tuple[str, int]:
    metadata = os.fstat(file_descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("executable file descriptor is not a regular file")
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    byte_count = 0
    while chunk := os.read(file_descriptor, _READ_CHUNK_BYTES):
        digest.update(chunk)
        byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def _digest_stream(stream: _BinaryDigestStream) -> StreamDigest:
    stream.flush()
    stream.seek(0)
    digest = hashlib.sha256()
    byte_count = 0
    while chunk := stream.read(_READ_CHUNK_BYTES):
        digest.update(chunk)
        byte_count += len(chunk)
    return StreamDigest(sha256=digest.hexdigest(), byte_count=byte_count)


def _read_text(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_LINUX_FACT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_LINUX_FACT_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def _current_allowed_affinity() -> tuple[int, ...]:
    get_affinity = getattr(os, "sched_getaffinity", None)
    if get_affinity is None:
        raise ProvisionalRunnerHostError("current allowed CPU affinity is unavailable")
    try:
        affinity = tuple(sorted(int(cpu) for cpu in get_affinity(0)))
    except (OSError, TypeError, ValueError) as error:
        raise ProvisionalRunnerHostError("current allowed CPU affinity is unavailable") from error
    if not affinity:
        raise ProvisionalRunnerHostError("current allowed CPU affinity is empty")
    return affinity


def _parse_cpu_model(cpuinfo: str) -> str | None:
    for line in cpuinfo.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "model name" and value.strip():
            return value.strip()
    return None


def _parse_mem_total_bytes(meminfo: str) -> int | None:
    for line in meminfo.splitlines():
        match = re.fullmatch(r"MemTotal:\s*([0-9]+)\s+kB\s*", line)
        if match is not None:
            kibibytes = int(match.group(1))
            return kibibytes * 1024 if kibibytes > 0 else None
    return None


def _parse_proc_stat(stat_text: str, *, page_size: int) -> _ProcSnapshot:
    """Parse the stable fields needed from Linux ``/proc/<pid>/stat``."""

    if page_size <= 0:
        raise ValueError("page size must be positive")
    opening = stat_text.find("(")
    closing = stat_text.rfind(")")
    if opening <= 0 or closing <= opening:
        raise ValueError("malformed /proc stat record")
    try:
        pid = int(stat_text[:opening].strip())
    except ValueError as error:
        raise ValueError("malformed /proc stat PID") from error
    fields = stat_text[closing + 1 :].split()
    if len(fields) < 22:
        raise ValueError("truncated /proc stat record")
    try:
        parent_pid = int(fields[1])
        process_group_id = int(fields[2])
        session_id = int(fields[3])
        start_time_ticks = int(fields[19])
        resident_pages = int(fields[21])
    except ValueError as error:
        raise ValueError("invalid numeric field in /proc stat record") from error
    if pid <= 0 or parent_pid < 0 or start_time_ticks < 0:
        raise ValueError("invalid process identity in /proc stat record")
    return _ProcSnapshot(
        pid=pid,
        parent_pid=parent_pid,
        process_group_id=process_group_id,
        session_id=session_id,
        state=fields[0],
        start_time_ticks=start_time_ticks,
        rss_bytes=max(0, resident_pages) * page_size,
    )


def _page_size() -> int:
    sysconf = getattr(os, "sysconf", None)
    if sysconf is None:
        raise ProcessIsolationError("Linux page size is unavailable")
    try:
        value = cast(Callable[[str], object], sysconf)("SC_PAGE_SIZE")
    except (OSError, ValueError) as error:
        raise ProcessIsolationError("Linux page size is unavailable") from error
    if not isinstance(value, int) or value <= 0:
        raise ProcessIsolationError("Linux page size is invalid")
    return value


def _read_proc_snapshots() -> tuple[_ProcSnapshot, ...]:
    proc_root = Path("/proc")
    try:
        entries = tuple(proc_root.iterdir())
    except OSError as error:
        raise ProcessIsolationError("cannot enumerate /proc for process-tree RSS") from error
    page_size = _page_size()
    snapshots: list[_ProcSnapshot] = []
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        stat_text = _read_text(entry / "stat")
        if stat_text is None:
            continue
        try:
            snapshots.append(_parse_proc_stat(stat_text, page_size=page_size))
        except ValueError:
            continue
    return tuple(snapshots)


def _observe_processes(
    snapshots: Sequence[_ProcSnapshot],
    *,
    root_pid: int,
    root_start_time_ticks: int,
    known_identities: frozenset[tuple[int, int]],
) -> _ProcessObservation:
    """Observe group RSS and descendants without confusing a reused PID for one seen before."""

    current_by_identity = {snapshot.identity: snapshot for snapshot in snapshots}
    known = set(known_identities)
    root_identity = (root_pid, root_start_time_ticks)
    if root_identity in current_by_identity:
        known.add(root_identity)
    for snapshot in snapshots:
        if snapshot.process_group_id == root_pid:
            known.add(snapshot.identity)

    changed = True
    while changed:
        changed = False
        current_known_pids = {
            pid for pid, start_time in known if (pid, start_time) in current_by_identity
        }
        for snapshot in snapshots:
            if snapshot.parent_pid in current_known_pids and snapshot.identity not in known:
                known.add(snapshot.identity)
                changed = True

    current_known = tuple(snapshot for snapshot in snapshots if snapshot.identity in known)
    group_members = tuple(
        snapshot for snapshot in snapshots if snapshot.process_group_id == root_pid
    )
    escaped = tuple(
        sorted(
            snapshot.identity
            for snapshot in current_known
            if snapshot.process_group_id != root_pid and snapshot.pid != root_pid
        )
    )
    return _ProcessObservation(
        process_group_rss_bytes=sum(snapshot.rss_bytes for snapshot in group_members),
        group_member_identities=tuple(sorted(snapshot.identity for snapshot in group_members)),
        live_group_member_identities=tuple(
            sorted(snapshot.identity for snapshot in group_members if snapshot.state != "Z")
        ),
        escaped_identities=escaped,
        known_identities=frozenset(known),
    )


def _capture_process_identity(pid: int, expected_process_group_id: int) -> ProcessIdentity:
    stat_text = _read_text(Path(f"/proc/{pid}/stat"))
    if stat_text is None:
        raise ProcessIsolationError("could not capture root process identity from /proc")
    snapshot = _parse_proc_stat(stat_text, page_size=_page_size())
    if (
        snapshot.pid != pid
        or snapshot.process_group_id != expected_process_group_id
        or snapshot.session_id != expected_process_group_id
    ):
        raise ProcessIsolationError("root process identity or process group changed during capture")
    executable_link = Path(f"/proc/{pid}/exe")
    open_flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
    try:
        executable_fd = os.open(executable_link, open_flags)
    except (OSError, ValueError) as error:
        raise ProcessIsolationError("could not fingerprint measured executable") from error
    try:
        executable = os.readlink(Path(f"/proc/self/fd/{executable_fd}"))
        executable_sha256, _byte_count = _sha256_fd(executable_fd)
    except (OSError, ValueError) as error:
        raise ProcessIsolationError("could not fingerprint measured executable") from error
    finally:
        os.close(executable_fd)

    final_stat_text = _read_text(Path(f"/proc/{pid}/stat"))
    if final_stat_text is None:
        raise ProcessIsolationError("root process changed while its identity was captured")
    final_snapshot = _parse_proc_stat(final_stat_text, page_size=_page_size())
    if (
        final_snapshot.identity != snapshot.identity
        or final_snapshot.process_group_id != expected_process_group_id
        or final_snapshot.session_id != expected_process_group_id
    ):
        raise ProcessIsolationError("root process changed while its identity was captured")
    return ProcessIdentity(
        pid=pid,
        process_group_id=snapshot.process_group_id,
        session_id=snapshot.session_id,
        start_time_ticks=snapshot.start_time_ticks,
        executable=executable,
        executable_sha256=executable_sha256,
    )


def _send_group_sigkill(process_group_id: int) -> None:
    killpg = getattr(os, "killpg", None)
    if killpg is None:
        raise ProcessIsolationError("process-group signaling is unavailable")
    try:
        killpg(process_group_id, _sigkill_number())
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ProcessIsolationError(
            f"could not kill measured process group {process_group_id}"
        ) from error


def _open_pidfd(pid: int) -> int:
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None:
        raise ProcessIsolationError("pidfd identity binding is unavailable")
    try:
        return cast(Callable[[int, int], int], pidfd_open)(pid, 0)
    except ProcessLookupError:
        raise
    except OSError as error:
        raise ProcessIsolationError(
            f"could not bind escaped measured process identity {pid}"
        ) from error


def _send_pidfd_sigkill(pidfd: int, pid: int) -> None:
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_send_signal is None:
        raise ProcessIsolationError("pidfd signaling is unavailable")
    try:
        cast(Callable[[int, int, None, int], None], pidfd_send_signal)(
            pidfd,
            _sigkill_number(),
            None,
            0,
        )
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ProcessIsolationError(f"could not kill escaped measured process {pid}") from error


def _send_identity_sigkill(identity: tuple[int, int]) -> None:
    """Signal an escaped process through a pidfd after proving its Linux start time."""

    pid, expected_start_time = identity
    try:
        pidfd = _open_pidfd(pid)
    except ProcessLookupError:
        return
    proc_directory = Path(f"/proc/{pid}")
    try:
        stat_text = _read_text(proc_directory / "stat")
        if stat_text is None:
            if not proc_directory.exists():
                return
            raise ProcessIsolationError(
                f"could not revalidate escaped measured process identity {pid}"
            )
        try:
            snapshot = _parse_proc_stat(stat_text, page_size=_page_size())
        except ValueError as error:
            raise ProcessIsolationError(
                f"could not revalidate escaped measured process identity {pid}"
            ) from error
        if snapshot.start_time_ticks != expected_start_time:
            return
        _send_pidfd_sigkill(pidfd, pid)
    finally:
        os.close(pidfd)


def _sigkill_number() -> int:
    sigkill = getattr(signal, "SIGKILL", None)
    if not isinstance(sigkill, int):
        raise ProcessIsolationError("SIGKILL is unavailable")
    return sigkill


def _kill_measured_processes(
    process: subprocess.Popen[bytes],
    escaped_identities: Sequence[tuple[int, int]],
) -> None:
    first_error: ProcessIsolationError | None = None
    try:
        _send_group_sigkill(process.pid)
    except ProcessIsolationError as error:
        first_error = error
    for identity in escaped_identities:
        try:
            _send_identity_sigkill(identity)
        except ProcessIsolationError as error:
            if first_error is None:
                first_error = error
    try:
        process.wait(timeout=_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise ProcessIsolationError("measured process did not exit after SIGKILL") from error
    if first_error is not None:
        raise first_error
