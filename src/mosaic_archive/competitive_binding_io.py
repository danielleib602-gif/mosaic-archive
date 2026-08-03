"""Private descriptor-relative I/O for the binding-runner cgroup backend.

This module only secures filesystem access to a delegated cgroup-v2 root and its
fresh leaves.  It does not qualify a host or grant binding evidence authority.
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Protocol, cast

_MAX_CONTROL_BYTES = 64 * 1024
_MAX_LEAF_NAME_BYTES = 255
_LEAF_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_CGROUP2_SUPER_MAGIC = 0x63677270
_STATFS_BUFFER_BYTES = 512


class _FailureCombiner(Protocol):
    def __call__(
        self,
        context: str,
        *,
        primary_error: BaseException,
        cleanup_error: BaseException,
    ) -> NoReturn: ...


class _LeafNamingPolicy(Protocol):
    @property
    def leaf_name_prefix(self) -> str: ...


class _BindingBackend(Protocol):
    def system(self) -> str: ...

    def machine(self) -> str: ...

    def allowed_cpu_affinity(self) -> tuple[int, ...]: ...

    def inspect_root(self, root: Path) -> object: ...

    def read_root(self, root: object, filename: str) -> str: ...

    def create_leaf(self, root: object, name: str) -> object: ...

    def read_leaf(self, leaf: object, filename: str) -> str: ...

    def write_leaf(self, leaf: object, filename: str, value: str) -> int: ...

    def remove_leaf(self, root: object, leaf: object) -> None: ...

    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


def _validate_leaf_name(name: str, policy: _LeafNamingPolicy) -> None:
    if type(name) is not str:
        raise TypeError("cgroup leaf name must be a string")
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("cgroup leaf name must be ASCII") from error
    if (
        not name.startswith(policy.leaf_name_prefix)
        or not encoded
        or len(encoded) > _MAX_LEAF_NAME_BYTES
        or _LEAF_NAME_RE.fullmatch(name) is None
        or name in {".", ".."}
    ):
        raise ValueError("cgroup leaf name is outside the fixed safe namespace")


@dataclass(frozen=True, slots=True)
class _FilesystemRootHandle:
    path: Path
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _FilesystemLeafHandle:
    root: _FilesystemRootHandle
    name: str
    device: int
    inode: int


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _raise_primary_and_cleanup(
    context: str,
    primary_error: BaseException,
    cleanup_error: BaseException,
) -> NoReturn:
    errors = [primary_error, cleanup_error]
    if all(isinstance(error, Exception) for error in errors):
        raise ExceptionGroup(context, cast(list[Exception], errors)) from cleanup_error
    raise BaseExceptionGroup(context, errors) from cleanup_error


def _close_after_failure(
    descriptor: int,
    primary_error: BaseException,
    *,
    context: str,
) -> NoReturn:
    """Close one still-owned fd once, preserving both errors when close fails."""
    try:
        os.close(descriptor)
    except BaseException as cleanup_error:
        _raise_primary_and_cleanup(context, primary_error, cleanup_error)
    raise primary_error.with_traceback(primary_error.__traceback__)


def _secure_open_absolute_directory(path: Path) -> int:
    if os.name != "posix":
        raise OSError("descriptor-relative cgroup access requires a POSIX host")
    if not path.is_absolute():
        raise OSError("cgroup root must be absolute")
    flags = _directory_open_flags()
    current: int | None = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."} or "/" in component or "\x00" in component:
                raise OSError("cgroup root contains an unsafe path component")
            assert current is not None
            next_fd = os.open(component, flags, dir_fd=current)
            try:
                os.close(current)
            except BaseException as rotation_error:
                # Linux close failure leaves descriptor state ambiguous. Transfer
                # no ownership back to the handler and never retry that number.
                current = None
                _close_after_failure(
                    next_fd,
                    rotation_error,
                    context="cgroup path rotation and new-descriptor cleanup both failed",
                )
            current = next_fd
        assert current is not None
        return current
    except BaseException as open_error:
        if current is None:
            raise
        _close_after_failure(
            current,
            open_error,
            context="cgroup path open and descriptor cleanup both failed",
        )


def _filesystem_magic(descriptor: int) -> int:
    """Read Linux ``statfs.f_type`` for an already-open directory descriptor."""
    try:
        library = ctypes.CDLL(None, use_errno=True)
        fstatfs = library.fstatfs
        fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
        fstatfs.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(_STATFS_BUFFER_BYTES)
        ctypes.set_errno(0)
        result = fstatfs(descriptor, ctypes.byref(buffer))
    except (AttributeError, OSError) as error:
        raise OSError("host does not expose descriptor-based filesystem identity") from error
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(ctypes.c_long.from_buffer(buffer).value)


def _validate_control_filename(filename: str) -> None:
    if (
        type(filename) is not str
        or not filename
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or filename in {".", ".."}
    ):
        raise OSError("unsafe cgroup control filename")


def _read_control_file(directory_fd: int, filename: str) -> str:
    _validate_control_filename(filename)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(filename, flags, dir_fd=directory_fd)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(4096, _MAX_CONTROL_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_CONTROL_BYTES:
                raise OSError("cgroup control file exceeds the bounded read limit")
        try:
            return b"".join(chunks).decode("ascii")
        except UnicodeDecodeError as error:
            raise OSError("cgroup control file is not ASCII") from error
    finally:
        os.close(descriptor)


def _write_control_file(directory_fd: int, filename: str, value: str) -> int:
    _validate_control_filename(filename)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise OSError("cgroup control value is not ASCII") from error
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(filename, flags, dir_fd=directory_fd)
    try:
        return os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


class _DescriptorRelativeFilesystemBackend:
    def __init__(self, *, raise_combined_failures: _FailureCombiner) -> None:
        self._raise_combined_failures = raise_combined_failures

    def system(self) -> str:
        return platform.system()

    def machine(self) -> str:
        return platform.machine()

    def allowed_cpu_affinity(self) -> tuple[int, ...]:
        if not hasattr(os, "sched_getaffinity"):
            raise OSError("host does not expose sched_getaffinity")
        return tuple(sorted(os.sched_getaffinity(0)))

    def inspect_root(self, root: Path) -> _FilesystemRootHandle:
        descriptor = _secure_open_absolute_directory(root)
        try:
            status = os.fstat(descriptor)
            if status.st_ino == 0:
                raise OSError("cgroup root does not expose a stable inode identity")
            if _filesystem_magic(descriptor) != _CGROUP2_SUPER_MAGIC:
                raise OSError("delegated root is not on a cgroup-v2 filesystem")
            return _FilesystemRootHandle(root, status.st_dev, status.st_ino)
        finally:
            os.close(descriptor)

    def _open_root(self, root: _FilesystemRootHandle) -> int:
        descriptor = _secure_open_absolute_directory(root.path)
        try:
            status = os.fstat(descriptor)
            filesystem_magic = _filesystem_magic(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        if filesystem_magic != _CGROUP2_SUPER_MAGIC:
            os.close(descriptor)
            raise OSError("delegated root is no longer on a cgroup-v2 filesystem")
        if (status.st_dev, status.st_ino) != (root.device, root.inode):
            os.close(descriptor)
            raise OSError("inspected cgroup root identity changed")
        return descriptor

    def read_root(self, root: object, filename: str) -> str:
        if not isinstance(root, _FilesystemRootHandle):
            raise OSError("invalid cgroup root handle")
        descriptor = self._open_root(root)
        try:
            return _read_control_file(descriptor, filename)
        finally:
            os.close(descriptor)

    def create_leaf(self, root: object, name: str) -> _FilesystemLeafHandle:
        if not isinstance(root, _FilesystemRootHandle):
            raise OSError("invalid cgroup root handle")
        root_fd = self._open_root(root)
        created = False
        result: _FilesystemLeafHandle | None = None
        try:
            os.mkdir(name, mode=0o700, dir_fd=root_fd)
            created = True
            leaf_fd = os.open(name, _directory_open_flags(), dir_fd=root_fd)
            try:
                status = os.fstat(leaf_fd)
                if status.st_ino == 0:
                    raise OSError("new cgroup leaf does not expose a stable inode identity")
                result = _FilesystemLeafHandle(
                    root=root,
                    name=name,
                    device=status.st_dev,
                    inode=status.st_ino,
                )
            finally:
                os.close(leaf_fd)
            try:
                os.close(root_fd)
            except BaseException:
                # A close failure makes setup unsuccessful. Do not retry this
                # descriptor number because its post-EINTR state is ambiguous.
                root_fd = -1
                raise
            root_fd = -1
            assert result is not None
            return result
        except BaseException as setup_error:
            if created:
                try:
                    cleanup_root_fd = self._open_root(root) if root_fd == -1 else root_fd
                    try:
                        os.rmdir(name, dir_fd=cleanup_root_fd)
                    finally:
                        if cleanup_root_fd != root_fd:
                            os.close(cleanup_root_fd)
                except BaseException as cleanup_error:
                    self._raise_combined_failures(
                        "cgroup leaf creation and cleanup both failed",
                        primary_error=setup_error,
                        cleanup_error=cleanup_error,
                    )
            raise
        finally:
            if root_fd != -1:
                os.close(root_fd)

    def _open_leaf(self, leaf: _FilesystemLeafHandle) -> int:
        root_fd = self._open_root(leaf.root)
        try:
            descriptor = os.open(leaf.name, _directory_open_flags(), dir_fd=root_fd)
        except BaseException as open_error:
            _close_after_failure(
                root_fd,
                open_error,
                context="cgroup leaf open and root-descriptor cleanup both failed",
            )
        try:
            os.close(root_fd)
        except BaseException as root_close_error:
            _close_after_failure(
                descriptor,
                root_close_error,
                context="cgroup root close and leaf-descriptor cleanup both failed",
            )
        try:
            status = os.fstat(descriptor)
        except BaseException as inspect_error:
            _close_after_failure(
                descriptor,
                inspect_error,
                context="cgroup leaf inspection and descriptor cleanup both failed",
            )
        if status.st_ino == 0:
            _close_after_failure(
                descriptor,
                OSError("cgroup leaf does not expose a stable inode identity"),
                context="invalid cgroup leaf and descriptor cleanup both failed",
            )
        if (status.st_dev, status.st_ino) != (leaf.device, leaf.inode):
            _close_after_failure(
                descriptor,
                OSError("cgroup leaf identity changed"),
                context="changed cgroup leaf and descriptor cleanup both failed",
            )
        return descriptor

    def read_leaf(self, leaf: object, filename: str) -> str:
        if not isinstance(leaf, _FilesystemLeafHandle):
            raise OSError("invalid cgroup leaf handle")
        descriptor = self._open_leaf(leaf)
        try:
            return _read_control_file(descriptor, filename)
        finally:
            os.close(descriptor)

    def write_leaf(self, leaf: object, filename: str, value: str) -> int:
        if not isinstance(leaf, _FilesystemLeafHandle):
            raise OSError("invalid cgroup leaf handle")
        descriptor = self._open_leaf(leaf)
        try:
            return _write_control_file(descriptor, filename, value)
        finally:
            os.close(descriptor)

    def remove_leaf(self, root: object, leaf: object) -> None:
        if not isinstance(root, _FilesystemRootHandle):
            raise OSError("invalid cgroup root handle")
        if not isinstance(leaf, _FilesystemLeafHandle) or leaf.root != root:
            raise OSError("invalid cgroup leaf handle")
        leaf_fd = self._open_leaf(leaf)
        os.close(leaf_fd)
        root_fd = self._open_root(root)
        try:
            os.rmdir(leaf.name, dir_fd=root_fd)
        finally:
            os.close(root_fd)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
