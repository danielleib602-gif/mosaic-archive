from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import mosaic_archive.archive as legacy_archive
import mosaic_archive.dedup_archive as dedup_archive
import mosaic_archive.solid_archive as solid_archive
import mosaic_archive.solid_archive_v2 as solid_archive_v2
import mosaic_archive.source_identity as source_identity
import mosaic_archive.stream_archive as stream_archive
from mosaic_archive.cdc import ChunkingConfig
from mosaic_archive.source_identity import SourceSession

_TEST_KEY = bytes(range(32))
_CHUNKING = ChunkingConfig(256, 512, 2048)


@dataclass(frozen=True, slots=True)
class _WriterCase:
    name: str
    module: ModuleType
    encode: Callable[[Path, Path], object]
    supports_folders: bool


def _writer_cases() -> tuple[_WriterCase, ...]:
    return (
        _WriterCase(
            "MSC1",
            legacy_archive,
            lambda source, destination: legacy_archive.encode_file(
                source,
                destination,
                "source identity",
                chunk_size=512,
                padding_size=256,
                kdf_log_n=14,
            ),
            False,
        ),
        _WriterCase(
            "MSC2",
            stream_archive,
            lambda source, destination: stream_archive.encode_stream_archive(
                source,
                destination,
                "source identity",
                chunk_size=512,
                padding_size=256,
                kdf_log_n=14,
            ),
            True,
        ),
        _WriterCase(
            "MSC6",
            dedup_archive,
            lambda source, destination: dedup_archive.encode_dedup_archive(
                source,
                destination,
                "source identity",
                config=_CHUNKING,
                padding_size=256,
                kdf_log_n=14,
            ),
            True,
        ),
        _WriterCase(
            "MSR1",
            solid_archive,
            lambda source, destination: solid_archive.encode_solid_archive(
                source,
                destination,
                "source identity",
                config=_CHUNKING,
                padding_size=256,
                kdf_log_n=14,
            ),
            True,
        ),
        _WriterCase(
            "MSR2",
            solid_archive_v2,
            lambda source, destination: solid_archive_v2.encode_solid_archive_v2(
                source,
                destination,
                "source identity",
                config=_CHUNKING,
                frame_payload_size=1024,
                padding_size=256,
                kdf_log_n=14,
            ),
            True,
        ),
    )


def _temporary_outputs(destination: Path) -> list[Path]:
    return list(destination.parent.glob(f".{destination.name}.*"))


def _replace_file_with_identical_inode(path: Path) -> None:
    metadata = path.stat(follow_symlinks=False)
    replacement = path.with_name(f".{path.name}.replacement")
    replacement.write_bytes(path.read_bytes())
    os.chmod(replacement, stat.S_IMODE(metadata.st_mode))
    os.utime(
        replacement,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
    )
    os.replace(replacement, path)


def _create_windows_junction(link: Path, target: Path) -> None:
    command = os.environ.get("COMSPEC", "cmd.exe")
    completed = subprocess.run(
        [command, "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr or completed.stdout or "mklink /J failed")


class EncoderSourceIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _source_tree(
        self,
        root: Path,
        *,
        folder: bool,
    ) -> tuple[Path, Path, Path | None]:
        payload = (b"bound source identity\n" * 257) + bytes(range(256))
        if not folder:
            source = root / "source.bin"
            source.write_bytes(payload)
            return source, source, None
        source = root / "source"
        file_path = source / "parent" / "payload.bin"
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(payload)
        empty = source / "empty"
        empty.mkdir()
        return source, file_path, empty

    def _assert_publication_rejects_mutation(
        self,
        case: _WriterCase,
        variant: str,
        mutator: Callable[[Path, Path, Path | None], None],
    ) -> None:
        case_root = self.root / f"{case.name.lower()}-{variant}"
        case_root.mkdir()
        source, file_path, empty = self._source_tree(
            case_root,
            folder=case.supports_folders,
        )
        destination = case_root / "archive.msc"
        original_destination = b"existing destination must survive"
        destination.write_bytes(original_destination)
        original_verify = SourceSession.verify_bindings
        mutated = False

        def mutate_then_verify(session: SourceSession) -> None:
            nonlocal mutated
            if not mutated:
                mutator(source, file_path, empty)
                mutated = True
            original_verify(session)

        with (
            patch.object(
                SourceSession,
                "verify_bindings",
                autospec=True,
                side_effect=mutate_then_verify,
            ),
            patch.object(case.module, "derive_key", return_value=_TEST_KEY),
            self.assertRaises(OSError),
        ):
            case.encode(source, destination)

        self.assertTrue(mutated)
        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(_temporary_outputs(destination), [])

    def test_every_writer_rejects_same_content_file_replacement_before_publish(
        self,
    ) -> None:
        for case in _writer_cases():
            with self.subTest(writer=case.name):
                self._assert_publication_rejects_mutation(
                    case,
                    "file",
                    lambda _source, file_path, _empty: _replace_file_with_identical_inode(
                        file_path
                    ),
                )

    def test_folder_writers_reject_parent_directory_replacement_before_publish(
        self,
    ) -> None:
        def replace_parent(_source: Path, file_path: Path, _empty: Path | None) -> None:
            parent = file_path.parent
            accepted_parent = parent.with_name("accepted-parent")
            parent.rename(accepted_parent)
            parent.mkdir()
            replacement = parent / file_path.name
            replacement.write_bytes((accepted_parent / file_path.name).read_bytes())
            original = (accepted_parent / file_path.name).stat()
            os.utime(
                replacement,
                ns=(original.st_atime_ns, original.st_mtime_ns),
            )

        for case in _writer_cases():
            if not case.supports_folders:
                continue
            with self.subTest(writer=case.name):
                self._assert_publication_rejects_mutation(case, "parent", replace_parent)

    def test_every_writer_rejects_source_root_replacement_before_publish(self) -> None:
        def replace_root(source: Path, file_path: Path, _empty: Path | None) -> None:
            if source.is_file():
                _replace_file_with_identical_inode(source)
                return
            payload = file_path.read_bytes()
            accepted_root = source.with_name("accepted-source")
            source.rename(accepted_root)
            replacement = source / "parent" / "payload.bin"
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(payload)
            (source / "empty").mkdir()

        for case in _writer_cases():
            with self.subTest(writer=case.name):
                self._assert_publication_rejects_mutation(case, "root", replace_root)

    def test_folder_writers_recheck_empty_directory_identity_before_publish(self) -> None:
        def replace_empty(_source: Path, _file_path: Path, empty: Path | None) -> None:
            assert empty is not None
            accepted = empty.with_name("accepted-empty")
            empty.rename(accepted)
            empty.mkdir()

        for case in _writer_cases():
            if not case.supports_folders:
                continue
            with self.subTest(writer=case.name):
                self._assert_publication_rejects_mutation(case, "empty", replace_empty)

    def test_every_writer_rejects_links_before_password_derivation(self) -> None:
        probe_target = self.root / "symlink-probe-target"
        probe_target.write_bytes(b"probe")
        probe = self.root / "symlink-probe"
        try:
            probe.symlink_to(probe_target)
            probe.unlink()
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symbolic links are unavailable: {error}")

        for case in _writer_cases():
            with self.subTest(writer=case.name):
                case_root = self.root / f"{case.name.lower()}-link"
                case_root.mkdir()
                destination = case_root / "archive.msc"
                marker = b"existing destination"
                destination.write_bytes(marker)
                outside = case_root / "outside.bin"
                outside.write_bytes(b"outside bytes")
                if case.supports_folders:
                    source = case_root / "source"
                    source.mkdir()
                    (source / "linked.bin").symlink_to(outside)
                else:
                    source = case_root / "source-link.bin"
                    source.symlink_to(outside)
                with (
                    patch.object(case.module, "derive_key") as derive_key,
                    self.assertRaises(ValueError),
                ):
                    case.encode(source, destination)
                derive_key.assert_not_called()
                self.assertEqual(destination.read_bytes(), marker)
                self.assertEqual(_temporary_outputs(destination), [])

    def test_source_session_rejects_file_replacement_before_open(self) -> None:
        source = self.root / "direct-source"
        source.mkdir()
        file_path = source / "payload.bin"
        file_path.write_bytes(b"same bytes and timestamps")
        session = SourceSession(source)
        self.assertEqual([entry.relative_path for entry in session.entries], ["payload.bin"])
        _replace_file_with_identical_inode(file_path)
        entered = False

        with self.assertRaises(OSError), session.open_file("payload.bin"):
            entered = True
        self.assertFalse(entered)

    def test_source_session_rejects_rebind_between_path_check_and_open(self) -> None:
        source = self.root / "open-race"
        source.mkdir()
        file_path = source / "payload.bin"
        file_path.write_bytes(b"same bytes and timestamps")
        session = SourceSession(source)
        self.assertEqual(len(session.entries), 1)
        real_open = os.open
        real_path_open = Path.open
        raced = False

        def replace_then_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal raced
            if not raced and Path(path) == file_path:
                _replace_file_with_identical_inode(file_path)
                raced = True
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        def replace_then_path_open(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> object:
            nonlocal raced
            if not raced and path == file_path:
                raced = True
                _replace_file_with_identical_inode(file_path)
            return real_path_open(path, *args, **kwargs)

        with (
            patch.object(source_identity.os, "open", side_effect=replace_then_open),
            patch.object(
                source_identity.Path,
                "open",
                autospec=True,
                side_effect=replace_then_path_open,
            ),
            self.assertRaises(OSError),
            session.open_file("payload.bin"),
        ):
            self.fail("a rebound file handle must not be yielded")
        self.assertTrue(raced)

    def test_source_session_rejects_parent_replacement_before_open(self) -> None:
        source = self.root / "parent-race"
        file_path = source / "parent" / "payload.bin"
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(b"parent identity matters")
        alternate = self.root / "alternate-parent"
        alternate.mkdir()
        os.link(file_path, alternate / file_path.name)
        session = SourceSession(source)
        accepted = file_path.parent.with_name("accepted-parent")
        file_path.parent.rename(accepted)
        alternate.rename(file_path.parent)

        with self.assertRaises(OSError), session.open_file("parent/payload.bin"):
            self.fail("a file below a rebound parent must not be yielded")

    def test_source_session_rejects_an_entry_added_after_discovery(self) -> None:
        source = self.root / "topology-addition"
        source.mkdir()
        (source / "accepted.bin").write_bytes(b"accepted")
        session = SourceSession(source)

        (source / "added.bin").write_bytes(b"must not be silently omitted")

        with self.assertRaises(OSError):
            session.verify_bindings()

    def test_source_session_rejects_a_transiently_incomplete_enumeration(self) -> None:
        source = self.root / "enumeration-race"
        source.mkdir()
        (source / "accepted.bin").write_bytes(b"must be discovered")
        incomplete = self.root / "incomplete-view"
        incomplete.mkdir()
        real_scandir = os.scandir
        redirected = False

        def transient_scandir(path: str | os.PathLike[str]) -> os.ScandirIterator[str]:
            nonlocal redirected
            if not redirected and Path(path) == source:
                redirected = True
                return real_scandir(incomplete)
            return real_scandir(path)

        with patch.object(
            source_identity.os,
            "scandir",
            side_effect=transient_scandir,
        ):
            session = SourceSession(source)

        self.assertTrue(redirected)
        self.assertEqual(session.entries, ())
        with self.assertRaisesRegex(OSError, "topology changed"):
            session.verify_bindings()

    def test_source_session_anchors_relative_input_against_cwd_changes(self) -> None:
        source = self.root / "anchored"
        source.mkdir()
        (source / "payload.bin").write_bytes(b"anchored bytes")
        other = self.root / "other"
        other.mkdir()
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            session = SourceSession(Path("anchored"))
            os.chdir(other)
            with session.open_file("payload.bin") as stream:
                self.assertEqual(stream.read(), b"anchored bytes")
            session.verify_bindings()
        finally:
            os.chdir(previous)

    def test_source_session_allows_a_symlinked_ancestor_above_the_root(self) -> None:
        real_parent = self.root / "real-parent"
        source = real_parent / "selected-root"
        source.mkdir(parents=True)
        (source / "payload.bin").write_bytes(b"selected root is not a link")
        linked_parent = self.root / "linked-parent"
        try:
            linked_parent.symlink_to(real_parent, target_is_directory=True)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"directory symbolic links are unavailable: {error}")

        session = SourceSession(linked_parent / "selected-root")
        with session.open_file("payload.bin") as stream:
            self.assertEqual(stream.read(), b"selected root is not a link")
        session.verify_bindings()

    @unittest.skipUnless(os.name == "posix", "symlink/.. resolution differs on Windows")
    def test_source_session_preserves_dotdot_after_a_symlinked_ancestor(self) -> None:
        real_container = self.root / "real-container"
        real_parent = real_container / "real-parent"
        selected = real_container / "selected-root"
        real_parent.mkdir(parents=True)
        selected.mkdir()
        (selected / "payload.bin").write_bytes(b"component-resolved source")
        lexical_selected = self.root / "selected-root"
        lexical_selected.mkdir()
        (lexical_selected / "payload.bin").write_bytes(b"lexically collapsed source")
        linked_parent = self.root / "linked-parent"
        try:
            linked_parent.symlink_to(real_parent, target_is_directory=True)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"directory symbolic links are unavailable: {error}")

        session = SourceSession(linked_parent / ".." / "selected-root")
        with session.open_file("payload.bin") as stream:
            self.assertEqual(stream.read(), b"component-resolved source")
        session.verify_bindings()

    def test_source_session_rejects_a_link_as_the_selected_root(self) -> None:
        target = self.root / "target.bin"
        target.write_bytes(b"target")
        linked_root = self.root / "linked-root.bin"
        try:
            linked_root.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symbolic links are unavailable: {error}")

        with self.assertRaises(ValueError):
            SourceSession(linked_root)

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-specific")
    def test_source_session_rejects_windows_junctions(self) -> None:
        target = self.root / "junction-target"
        target.mkdir()
        (target / "payload.bin").write_bytes(b"junction target")
        selected_root = self.root / "selected-junction"
        source = self.root / "junction-parent"
        source.mkdir()
        child = source / "junction-child"
        try:
            _create_windows_junction(selected_root, target)
            _create_windows_junction(child, target)
        except OSError as error:
            self.skipTest(f"directory junctions are unavailable: {error}")

        with self.subTest(location="selected root"), self.assertRaises(ValueError):
            SourceSession(selected_root)
        with self.subTest(location="descendant"), self.assertRaises(ValueError):
            SourceSession(source)
