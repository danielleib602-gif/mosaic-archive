"""Run the opt-in Rust lifecycle test with one inherited cgroup directory FD."""

from __future__ import annotations

import errno
import os
import re
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import NoReturn

_CGROUP_ROOT = PurePosixPath("/sys/fs/cgroup")
_PARENT_NAME = re.compile(r"mosaic-native-ci-[0-9]+-[0-9]+\Z")


def _validated_parent(raw_parent: str) -> Path:
    candidate = PurePosixPath(raw_parent)
    if not candidate.is_absolute() or candidate.parent != _CGROUP_ROOT:
        raise ValueError("integration parent must be a direct child of /sys/fs/cgroup")
    if _PARENT_NAME.fullmatch(candidate.name) is None:
        raise ValueError("integration parent name is outside the fixed CI namespace")
    return Path(raw_parent)


def _run_direct_lifecycle_test(descriptor: int) -> int:
    environment = os.environ.copy()
    environment["MOSAIC_BINDING_SUPERVISOR_INTEGRATION"] = "1"
    environment["MOSAIC_BINDING_SUPERVISOR_PARENT_FD"] = str(descriptor)
    completed = subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "test",
            "--package",
            "mosaic-binding-supervisor",
            "--lib",
            "--locked",
            "linux::tests::real_delegated_parent_setup_and_cleanup",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ],
        check=False,
        env=environment,
        pass_fds=(descriptor,),
    )
    return completed.returncode


DescriptorBackup = tuple[int, bool] | None


def _raise_failures(context: str, failures: list[BaseException]) -> NoReturn:
    if len(failures) == 1:
        raise failures[0]
    raise BaseExceptionGroup(context, failures)


def _capture_failure(failures: list[BaseException], operation: Callable[[], object]) -> None:
    try:
        operation()
    except BaseException as error:
        failures.append(error)


def _backup_descriptor(descriptor: int) -> DescriptorBackup:
    import fcntl

    try:
        inheritable = os.get_inheritable(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        return None
    backup = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 5)
    return backup, inheritable


def _restore_descriptor(descriptor: int, backup: DescriptorBackup) -> None:
    if backup is None:
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        return
    backup_descriptor, inheritable = backup
    failures: list[BaseException] = []
    try:
        os.dup2(backup_descriptor, descriptor, inheritable=inheritable)
    except BaseException as error:
        failures.append(error)
    try:
        os.close(backup_descriptor)
    except BaseException as error:
        failures.append(error)
    if failures:
        _raise_failures(f"cannot restore descriptor {descriptor}", failures)


def _terminate_and_reap(process: subprocess.Popen[str]) -> None:
    failures: list[BaseException] = []
    try:
        running = process.poll() is None
    except BaseException as error:
        failures.append(error)
        running = True
    if running:
        _capture_failure(failures, process.terminate)
    try:
        process.communicate(timeout=10)
    except BaseException as error:
        if not isinstance(error, subprocess.TimeoutExpired):
            failures.append(error)
        _capture_failure(failures, process.kill)
        _capture_failure(failures, lambda: process.communicate(timeout=10))
    try:
        if process.poll() is None:
            failures.append(RuntimeError("native supervisor remained unreaped after forced kill"))
    except BaseException as error:
        failures.append(error)
    if failures:
        _raise_failures("cannot terminate and reap native supervisor", failures)


def _wait_for_supervisor(process: subprocess.Popen[str]) -> None:
    try:
        _stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired as error:
        failures: list[BaseException] = [error]
        _capture_failure(failures, lambda: _terminate_and_reap(process))
        if len(failures) > 1:
            _raise_failures("native supervisor timeout and cleanup both failed", failures)
        raise RuntimeError("native supervisor did not exit within 45 seconds") from error
    except BaseException as error:
        failures = [error]
        _capture_failure(failures, lambda: _terminate_and_reap(process))
        if len(failures) > 1:
            _raise_failures("native supervisor wait and cleanup both failed", failures)
        raise
    if process.returncode != 0:
        if stderr:
            print(stderr, file=sys.stderr, end="")
        raise RuntimeError(f"native supervisor exited with status {process.returncode}")


def _spawn_supervisor(binary: Path, parent: int, control: int) -> subprocess.Popen[str]:
    parent_backup = _backup_descriptor(3)
    try:
        control_backup = _backup_descriptor(4)
    except BaseException as primary_error:
        failures = [primary_error]
        if parent_backup is not None:
            _capture_failure(failures, lambda: os.close(parent_backup[0]))
        _raise_failures("cannot preserve fixed supervisor descriptors", failures)

    process: subprocess.Popen[str] | None = None
    primary_error: BaseException | None = None
    try:
        os.dup2(parent, 3, inheritable=True)
        os.dup2(control, 4, inheritable=True)
        process = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
            pass_fds=(3, 4),
        )
    except BaseException as error:
        primary_error = error

    failures = [] if primary_error is None else [primary_error]
    _capture_failure(failures, lambda: _restore_descriptor(4, control_backup))
    _capture_failure(failures, lambda: _restore_descriptor(3, parent_backup))
    if failures:
        if process is not None:
            _capture_failure(failures, lambda: _terminate_and_reap(process))
        _raise_failures("cannot launch native supervisor on fixed descriptors", failures)
    assert process is not None
    return process


def _install_coordinator_control(descriptor: int) -> DescriptorBackup:
    backup = _backup_descriptor(4)
    try:
        os.dup2(descriptor, 4, inheritable=True)
    except BaseException as primary_error:
        failures = [primary_error]
        if backup is not None:
            _capture_failure(failures, lambda: os.close(backup[0]))
        _raise_failures("cannot install coordinator control descriptor", failures)
    return backup


def _run_end_to_end_supervisor(parent_descriptor: int) -> int:
    from mosaic_archive.competitive_binding_runner import (
        create_binding_cgroup,
        qualify_supervised_binding_host,
    )
    from mosaic_archive.competitive_binding_supervisor import (
        inherit_exclusive_delegated_root,
    )

    binary = Path("target/release/mosaic-binding-supervisor").resolve()
    if not binary.is_file():
        raise RuntimeError(f"native supervisor binary is missing: {binary}")

    coordinator: socket.socket | None = None
    supervisor: socket.socket | None = None
    coordinator_source = -1
    supervisor_source = -1
    parent_source = -1
    process: subprocess.Popen[str] | None = None
    backup: DescriptorBackup = None
    capability = None
    lease = None
    primary_error: BaseException | None = None
    try:
        coordinator, supervisor = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        coordinator_source = os.dup(coordinator.fileno())
        supervisor_source = os.dup(supervisor.fileno())
        parent_source = os.dup(parent_descriptor)
        owned_coordinator = coordinator
        coordinator = None
        owned_coordinator.close()
        owned_supervisor = supervisor
        supervisor = None
        owned_supervisor.close()

        process = _spawn_supervisor(binary, parent_source, supervisor_source)
        owned_descriptor = supervisor_source
        supervisor_source = -1
        os.close(owned_descriptor)
        backup = _install_coordinator_control(coordinator_source)
        owned_descriptor = coordinator_source
        coordinator_source = -1
        os.close(owned_descriptor)

        capability = inherit_exclusive_delegated_root()
        qualification = qualify_supervised_binding_host(capability, 1)
        lease = create_binding_cgroup(
            qualification,
            capability=capability,
            leaf_name=f"mosaic-binding-ci-{os.getpid()}",
        )
        owned_lease = lease
        lease = None
        owned_lease.cleanup()
        owned_capability = capability
        capability = None
        owned_capability.close()
        owned_backup = backup
        backup = None
        _restore_descriptor(4, owned_backup)
        owned_process = process
        process = None
        _wait_for_supervisor(owned_process)
    except BaseException as error:
        primary_error = error

    failures = [] if primary_error is None else [primary_error]
    if lease is not None:
        owned_lease = lease
        lease = None
        _capture_failure(failures, owned_lease.cleanup)
    if capability is not None:
        owned_capability = capability
        capability = None
        _capture_failure(failures, owned_capability.close)
    if backup is not None:
        owned_backup = backup
        backup = None
        _capture_failure(
            failures,
            lambda backup=owned_backup: _restore_descriptor(4, backup),
        )
    if coordinator_source >= 0:
        owned_descriptor = coordinator_source
        coordinator_source = -1
        _capture_failure(
            failures,
            lambda descriptor=owned_descriptor: os.close(descriptor),
        )
    if supervisor_source >= 0:
        owned_descriptor = supervisor_source
        supervisor_source = -1
        _capture_failure(
            failures,
            lambda descriptor=owned_descriptor: os.close(descriptor),
        )
    if parent_source >= 0:
        owned_descriptor = parent_source
        parent_source = -1
        _capture_failure(
            failures,
            lambda descriptor=owned_descriptor: os.close(descriptor),
        )
    if coordinator is not None:
        owned_coordinator = coordinator
        coordinator = None
        _capture_failure(failures, owned_coordinator.close)
    if supervisor is not None:
        owned_supervisor = supervisor
        supervisor = None
        _capture_failure(failures, owned_supervisor.close)
    if process is not None:
        owned_process = process
        process = None
        _capture_failure(
            failures,
            lambda process=owned_process: _wait_for_supervisor(process),
        )
    if failures:
        _raise_failures("native cgroup integration and cleanup failed", failures)
    return 0


def main() -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("native cgroup integration requires Linux")
    raw_parent = os.environ.get("MOSAIC_NATIVE_CGROUP_PARENT")
    if raw_parent is None:
        raise RuntimeError("MOSAIC_NATIVE_CGROUP_PARENT is required")
    parent = _validated_parent(raw_parent)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    status = 1
    primary_error: BaseException | None = None
    try:
        descriptor = os.open(parent, flags)
        direct_status = _run_direct_lifecycle_test(descriptor)
        status = direct_status if direct_status != 0 else _run_end_to_end_supervisor(descriptor)
    except BaseException as error:
        primary_error = error

    failures = [] if primary_error is None else [primary_error]
    if descriptor >= 0:
        owned_descriptor = descriptor
        descriptor = -1
        _capture_failure(
            failures,
            lambda descriptor=owned_descriptor: os.close(descriptor),
        )
    if failures:
        _raise_failures("native cgroup integration and parent cleanup failed", failures)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
