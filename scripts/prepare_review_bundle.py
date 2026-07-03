"""Build and verify deterministic source bundles for independent review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, cast

BUNDLE_FORMAT = "mosaic-review-bundle-v1"
MANIFEST_NAME = "REVIEW-MANIFEST.json"
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_SUPPORTED_MODES = {"100644", "100755"}
_MAX_BUNDLE_MEMBERS = 100_000
_MAX_MANIFEST_SIZE = 16 * 1024 * 1024
_MAX_MEMBER_SIZE = 1024 * 1024 * 1024
_MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", *arguments],
            cwd=root,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(arguments)} failed: {detail}") from error


def _safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"unsafe bundle path: {value!r}")
    return path


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, _ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = mode << 16
    return info


def _revision_files(root: Path, revision: str) -> tuple[str, str, list[dict[str, Any]]]:
    commit = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    tree = _git(root, "rev-parse", "--verify", f"{commit}^{{tree}}").decode().strip()
    records = _git(root, "ls-tree", "-rz", "--full-tree", commit).split(b"\0")
    files: list[dict[str, Any]] = []
    for record in records:
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise ValueError("malformed git tree entry")
        mode, object_type, object_id = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        _safe_path(path)
        if object_type != "blob" or mode not in _SUPPORTED_MODES:
            raise ValueError(
                f"unsupported git tree entry {path!r}: type={object_type}, mode={mode}"
            )
        payload = _git(root, "cat-file", "blob", object_id)
        files.append(
            {
                "path": path,
                "mode": mode,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "_payload": payload,
            }
        )
    files.sort(key=lambda item: str(item["path"]))
    return commit, tree, files


def build_review_bundle(root: Path, output: Path, revision: str = "HEAD") -> dict[str, Any]:
    """Build a deterministic review ZIP from Git objects at ``revision``."""
    root = root.resolve()
    output = output.resolve()
    commit, tree, files = _revision_files(root, revision)
    pyproject = next(
        (item["_payload"] for item in files if item["path"] == "pyproject.toml"),
        None,
    )
    if pyproject is None:
        raise ValueError("revision does not contain pyproject.toml")
    try:
        package_version = str(
            tomllib.loads(pyproject.decode("utf-8"))["project"]["version"]
        )
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("cannot read project.version from pyproject.toml") from error

    public_files = [
        {key: value for key, value in item.items() if key != "_payload"} for item in files
    ]
    manifest: dict[str, Any] = {
        "bundle_format": BUNDLE_FORMAT,
        "package_version": package_version,
        "source_commit": commit,
        "source_tree": tree,
        "files": public_files,
    }
    manifest_payload = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    prefix = f"mosaic-archive-{commit[:12]}/"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
        with zipfile.ZipFile(temporary_name, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(_zip_info(prefix + MANIFEST_NAME), manifest_payload)
            for item in files:
                mode = int(str(item["mode"]), 8)
                archive.writestr(
                    _zip_info(prefix + str(item["path"]), mode),
                    item["_payload"],
                )
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    verify_review_bundle(output)
    return manifest


def verify_review_bundle(bundle: Path) -> dict[str, Any]:
    """Verify structure and every payload digest in a review bundle."""
    try:
        archive = zipfile.ZipFile(bundle)
    except (OSError, zipfile.BadZipFile) as error:
        raise ValueError(f"invalid review bundle: {error}") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > _MAX_BUNDLE_MEMBERS:
            raise ValueError("review bundle contains too many members")
        total_size = 0
        for info in infos:
            _safe_path(info.filename)
            if info.is_dir():
                raise ValueError("review bundle must not contain directory members")
            if info.compress_type != zipfile.ZIP_STORED:
                raise ValueError("review bundle members must be stored without compression")
            if info.date_time != _ZIP_TIMESTAMP:
                raise ValueError("review bundle member has a non-deterministic timestamp")
            if info.file_size < 0 or info.file_size > _MAX_MEMBER_SIZE:
                raise ValueError("review bundle member exceeds the size limit")
            total_size += info.file_size
            if total_size > _MAX_TOTAL_SIZE:
                raise ValueError("review bundle exceeds the total size limit")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("review bundle contains duplicate member names")
        manifest_names = [name for name in names if name.endswith("/" + MANIFEST_NAME)]
        if len(manifest_names) != 1:
            raise ValueError("review bundle must contain exactly one review manifest")
        manifest_name = manifest_names[0]
        if archive.getinfo(manifest_name).file_size > _MAX_MANIFEST_SIZE:
            raise ValueError("review bundle manifest exceeds the size limit")
        prefix = manifest_name.removesuffix(MANIFEST_NAME)
        if prefix.count("/") != 1 or not prefix.startswith("mosaic-archive-"):
            raise ValueError("review bundle has an invalid root directory")
        try:
            raw_manifest = json.loads(archive.read(manifest_name))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("review bundle manifest is invalid") from error
        if not isinstance(raw_manifest, dict):
            raise ValueError("review bundle manifest must be an object")
        manifest = cast(dict[str, Any], raw_manifest)
        if manifest.get("bundle_format") != BUNDLE_FORMAT:
            raise ValueError("unsupported review bundle format")
        source_commit = manifest.get("source_commit")
        source_tree = manifest.get("source_tree")
        if (
            not isinstance(source_commit, str)
            or len(source_commit) != 40
            or any(character not in "0123456789abcdef" for character in source_commit)
            or not isinstance(source_tree, str)
            or len(source_tree) != 40
            or any(character not in "0123456789abcdef" for character in source_tree)
        ):
            raise ValueError("review bundle has an invalid source identity")
        if prefix != f"mosaic-archive-{source_commit[:12]}/":
            raise ValueError("review bundle root does not match its source commit")
        files = manifest.get("files")
        if not isinstance(files, list):
            raise ValueError("review bundle manifest files must be a list")

        expected_names = {manifest_name}
        seen_paths: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict):
                raise ValueError("review bundle file entry must be an object")
            try:
                path = str(entry["path"])
                size = int(entry["size"])
                expected_digest = str(entry["sha256"])
                mode = str(entry["mode"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("review bundle file entry is invalid") from error
            _safe_path(path)
            if path in seen_paths:
                raise ValueError(f"duplicate manifest path: {path}")
            seen_paths.add(path)
            if mode not in _SUPPORTED_MODES:
                raise ValueError(f"unsupported manifest mode for {path}: {mode}")
            member_name = prefix + path
            expected_names.add(member_name)
            try:
                member_info = archive.getinfo(member_name)
            except KeyError as error:
                raise ValueError(f"missing bundle payload: {path}") from error
            if size < 0 or size > _MAX_MEMBER_SIZE or member_info.file_size != size:
                raise ValueError(f"size mismatch for bundle payload: {path}")
            payload = archive.read(member_name)
            if hashlib.sha256(payload).hexdigest() != expected_digest:
                raise ValueError(f"digest mismatch for bundle payload: {path}")
        if set(names) != expected_names:
            extras = sorted(set(names) - expected_names)
            missing = sorted(expected_names - set(names))
            raise ValueError(f"bundle member mismatch: extras={extras}, missing={missing}")
        return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("output", type=Path)
    build_parser.add_argument("--root", type=Path, default=Path("."))
    build_parser.add_argument("--revision", default="HEAD")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("bundle", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "build":
            manifest = build_review_bundle(
                arguments.root,
                arguments.output,
                arguments.revision,
            )
        else:
            manifest = verify_review_bundle(arguments.bundle)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(
        json.dumps(
            {
                "bundle_format": manifest["bundle_format"],
                "file_count": len(manifest["files"]),
                "package_version": manifest["package_version"],
                "source_commit": manifest["source_commit"],
                "source_tree": manifest["source_tree"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
