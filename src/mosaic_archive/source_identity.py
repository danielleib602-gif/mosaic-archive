"""Identity-bound source traversal and reads for archive encoders."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _birthtime_ns(metadata: os.stat_result) -> int | None:
    value = getattr(metadata, "st_birthtime_ns", None)
    return None if value is None else int(value)


@dataclass(frozen=True, slots=True, eq=False)
class SourceIdentity:
    """Stable identity and replacement-sensitive metadata for one source object."""

    _metadata: os.stat_result = field(repr=False, compare=False)

    @classmethod
    def capture(cls, metadata: os.stat_result, path: Path) -> SourceIdentity:
        if metadata.st_ino == 0:
            raise OSError(f"the filesystem does not expose a stable source identity: {path}")
        return cls(metadata)

    @property
    def st_mode(self) -> int:
        return self._metadata.st_mode

    @property
    def st_size(self) -> int:
        return self._metadata.st_size

    @property
    def st_mtime_ns(self) -> int:
        return self._metadata.st_mtime_ns

    def _matches_common(self, metadata: os.stat_result) -> bool:
        if (
            self._metadata.st_dev != metadata.st_dev
            or self._metadata.st_ino != metadata.st_ino
        ):
            return False
        if stat.S_IFMT(self.st_mode) != stat.S_IFMT(metadata.st_mode):
            return False
        if stat.S_IMODE(self.st_mode) != stat.S_IMODE(metadata.st_mode):
            return False
        expected_birthtime = _birthtime_ns(self._metadata)
        actual_birthtime = _birthtime_ns(metadata)
        if expected_birthtime is not None and expected_birthtime != actual_birthtime:
            return False
        if self.st_mtime_ns != metadata.st_mtime_ns:
            return False
        return not stat.S_ISREG(self.st_mode) or self.st_size == metadata.st_size

    def matches_path(self, metadata: os.stat_result) -> bool:
        """Compare a fresh pathname lookup with the captured source object."""
        return (
            self._matches_common(metadata)
            and self._metadata.st_ctime_ns == metadata.st_ctime_ns
        )

    def matches_handle(self, metadata: os.stat_result) -> bool:
        """Compare metadata from the exact file handle that will supply bytes."""
        if not self._matches_common(metadata):
            return False
        # Before Python 3.12, Windows exposes creation time as st_ctime while
        # descriptor and pathname conversions can disagree. File identity,
        # birth time (when available), size, and mtime still bind the handle.
        return os.name == "nt" or self._metadata.st_ctime_ns == metadata.st_ctime_ns


@dataclass(frozen=True, slots=True)
class SourceEntry:
    """A discovered source object addressed relative to an anchored root."""

    relative_path: str
    is_directory: bool
    identity: SourceIdentity
    _path: Path = field(repr=False, compare=False)
    _parent: SourceEntry | None = field(repr=False, compare=False)


class SourceSession:
    """Capture a source tree and bind every later read to captured identities."""

    def __init__(self, source: str | os.PathLike[str]) -> None:
        # Anchor relative paths without lexically collapsing ``..``. On POSIX,
        # a preceding symlink changes what the next ``..`` component means.
        self.source = Path(source).absolute()
        root_metadata = self._initial_metadata(self.source)
        self.root_is_file = stat.S_ISREG(root_metadata.st_mode)
        if not self.root_is_file and not stat.S_ISDIR(root_metadata.st_mode):
            raise ValueError(f"input is neither a regular file nor a directory: {self.source}")
        root = SourceEntry(
            "",
            not self.root_is_file,
            SourceIdentity.capture(root_metadata, self.source),
            self.source,
            None,
        )
        self._entries_by_path: dict[str, SourceEntry] = {"": root}
        self.entries: tuple[SourceEntry, ...]
        if self.root_is_file:
            self.entries = (root,)
        else:
            discovered: list[SourceEntry] = []
            self._discover_directory(root, discovered)
            self.entries = tuple(
                sorted(
                    discovered,
                    key=lambda entry: (
                        entry.relative_path.count("/"),
                        entry.relative_path.casefold(),
                        not entry.is_directory,
                        entry.relative_path,
                    ),
                )
            )

    def __enter__(self) -> SourceSession:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    @staticmethod
    def _initial_metadata(path: Path) -> os.stat_result:
        try:
            metadata = path.stat(follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            raise FileNotFoundError(f"input path does not exist: {path}") from None
        if _is_link_or_reparse(metadata):
            raise ValueError(f"symbolic links and reparse points are not supported: {path}")
        return metadata

    def _require_binding(self, entry: SourceEntry) -> os.stat_result:
        path = entry._path
        try:
            metadata = path.stat(follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError, OSError) as error:
            raise OSError(f"input source identity changed: {path}") from error
        if _is_link_or_reparse(metadata) or not entry.identity.matches_path(metadata):
            raise OSError(f"input source identity changed: {path}")
        return metadata

    def _require_ancestor_bindings(self, entry: SourceEntry) -> None:
        ancestor = entry._parent
        while ancestor is not None:
            self._require_binding(ancestor)
            ancestor = ancestor._parent

    def _discover_directory(
        self,
        directory: SourceEntry,
        discovered: list[SourceEntry],
    ) -> None:
        pending = [directory]
        while pending:
            current = pending.pop()
            path = current._path
            children: list[SourceEntry] = []
            try:
                with os.scandir(path) as iterator:
                    for child in iterator:
                        child_path = path / child.name
                        try:
                            # Windows DirEntry.stat() does not expose volume/file
                            # IDs, while Path.stat() and fstat() do.
                            metadata = child_path.stat(follow_symlinks=False)
                        except OSError as error:
                            raise OSError(
                                f"input changed while it was discovered: {child_path}"
                            ) from error
                        if _is_link_or_reparse(metadata):
                            raise ValueError(
                                "symbolic links and reparse points are not supported: "
                                f"{child_path}"
                            )
                        is_directory = stat.S_ISDIR(metadata.st_mode)
                        if not is_directory and not stat.S_ISREG(metadata.st_mode):
                            raise ValueError(f"special files are not supported: {child_path}")
                        relative = (
                            child.name
                            if current.relative_path == ""
                            else f"{current.relative_path}/{child.name}"
                        )
                        entry = SourceEntry(
                            relative,
                            is_directory,
                            SourceIdentity.capture(metadata, child_path),
                            child_path,
                            current,
                        )
                        self._entries_by_path[relative] = entry
                        children.append(entry)
            except OSError as error:
                raise OSError(f"input changed while it was discovered: {path}") from error
            self._require_binding(current)
            discovered.extend(children)
            pending.extend(entry for entry in children if entry.is_directory)

    def path_for(self, relative_path: str) -> Path:
        """Return the anchored path for a previously discovered entry."""
        try:
            return self._entries_by_path[relative_path]._path
        except KeyError:
            raise KeyError(f"source entry was not discovered: {relative_path}") from None

    def identity_for(self, relative_path: str) -> SourceIdentity:
        """Return the captured identity for a previously discovered entry."""
        try:
            return self._entries_by_path[relative_path].identity
        except KeyError:
            raise KeyError(f"source entry was not discovered: {relative_path}") from None

    @contextmanager
    def open_file(self, relative_path: str) -> Iterator[BinaryIO]:
        """Open one discovered file and validate its handle before yielding bytes."""
        try:
            entry = self._entries_by_path[relative_path]
        except KeyError:
            raise KeyError(f"source entry was not discovered: {relative_path}") from None
        path = entry._path
        if entry.is_directory:
            raise IsADirectoryError(f"source entry is a directory: {path}")
        self._require_ancestor_bindings(entry)
        flags = os.O_RDONLY
        for name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW"):
            flags |= int(getattr(os, name, 0))
        descriptor: int | None = None
        stream: BinaryIO | None = None
        try:
            try:
                if getattr(os, "O_NOFOLLOW", 0):
                    descriptor = os.open(path, flags)
                    stream = os.fdopen(descriptor, "rb", closefd=True)
                    descriptor = None
                else:
                    stream = path.open("rb")
            except OSError as error:
                raise OSError(f"input source identity changed: {path}") from error
            opened = os.fstat(stream.fileno())
            if _is_link_or_reparse(opened) or not entry.identity.matches_handle(opened):
                raise OSError(f"input source identity changed: {path}")
            try:
                yield stream
            except BaseException:
                raise
            else:
                opened_after = os.fstat(stream.fileno())
                if not entry.identity.matches_handle(opened_after):
                    raise OSError(f"input changed while it was read: {path}")
        finally:
            if stream is not None:
                stream.close()
            elif descriptor is not None:
                os.close(descriptor)

    def verify_bindings(self) -> None:
        """Reject source topology or object identities changed since discovery."""
        root = self._entries_by_path[""]
        self._require_binding(root)
        if self.root_is_file:
            return
        seen = {""}
        pending = [root]
        while pending:
            directory = pending.pop()
            path = directory._path
            directories: list[SourceEntry] = []
            try:
                with os.scandir(path) as iterator:
                    for child in iterator:
                        relative = (
                            child.name
                            if directory.relative_path == ""
                            else f"{directory.relative_path}/{child.name}"
                        )
                        expected = self._entries_by_path.get(relative)
                        if expected is None or relative in seen:
                            raise OSError(f"input source topology changed: {path}")
                        child_path = expected._path
                        metadata = child_path.stat(follow_symlinks=False)
                        if (
                            _is_link_or_reparse(metadata)
                            or expected.is_directory != stat.S_ISDIR(metadata.st_mode)
                            or not expected.identity.matches_path(metadata)
                        ):
                            raise OSError(f"input source identity changed: {child_path}")
                        seen.add(relative)
                        if expected.is_directory:
                            directories.append(expected)
            except OSError as error:
                raise OSError(f"input source topology changed: {path}") from error
            self._require_binding(directory)
            pending.extend(directories)
        if seen != self._entries_by_path.keys():
            raise OSError(f"input source topology changed: {self.source}")
