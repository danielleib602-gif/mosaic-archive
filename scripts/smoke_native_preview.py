from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORD_VARIABLE = "MOSAIC_NATIVE_PREVIEW_SMOKE_PASSWORD"
PASSWORD = "native-preview-smoke-password"
EXECUTABLE_TIMEOUT_SECONDS = 120


def _payload() -> bytes:
    block = bytes(range(256)) * 32 + b"mosaic-native-preview\n" * 257
    return block * 17


def _executable_environment(password: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment[PASSWORD_VARIABLE] = password
    return environment


def _run_executable(
    executable: Path,
    directory: Path,
    *arguments: str,
    password: str = PASSWORD,
) -> str:
    process = subprocess.run(
        [str(executable), *arguments, "--password-env", PASSWORD_VARIABLE],
        check=False,
        capture_output=True,
        cwd=directory,
        encoding="utf-8",
        env=_executable_environment(password),
        timeout=EXECUTABLE_TIMEOUT_SECONDS,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"native preview smoke command failed ({process.returncode}): {process.stderr}"
        )
    return process.stdout


def _smoke_import_api(directory: Path) -> None:
    from mosaic_archive import _native
    from mosaic_archive.exceptions import AuthenticationError
    from mosaic_archive.native_preview import (
        decode_native_preview_file,
        encode_native_preview_file,
        inspect_native_preview_file,
    )

    if _native.BINDING_API_VERSION != 1:
        raise RuntimeError("unexpected native binding API version")

    source = directory / "source-π.bin"
    archive = directory / "archive-π.m7a"
    restored = directory / "restored-π.bin"
    protected = directory / "protected-π.bin"
    source.write_bytes(_payload())

    encoded = encode_native_preview_file(source, archive, PASSWORD, threads=2, kdf_log_n=14)
    inspected = inspect_native_preview_file(archive, PASSWORD, max_kdf_log_n=17)
    decoded = decode_native_preview_file(archive, restored, PASSWORD, max_kdf_log_n=17)
    if encoded.format_name != "M7A0" or not encoded.authenticated or encoded.stable:
        raise RuntimeError("native encode returned invalid preview identity")
    if encoded.hash_verified:
        raise RuntimeError("native encode incorrectly claimed a verified restored hash")
    if not inspected.hash_verified or not decoded.hash_verified:
        raise RuntimeError("native inspect/decode did not report verified hashes")
    if inspected != decoded or inspected.original_size != len(_payload()):
        raise RuntimeError("native inspect/decode statistics disagree")
    if hashlib.sha256(restored.read_bytes()).digest() != hashlib.sha256(_payload()).digest():
        raise RuntimeError("native preview round trip changed the payload")

    protected.write_bytes(b"preserve-existing-destination")
    try:
        decode_native_preview_file(archive, protected, "wrong-password", max_kdf_log_n=17)
    except AuthenticationError:
        pass
    else:
        raise RuntimeError("wrong password unexpectedly decoded native preview archive")
    if protected.read_bytes() != b"preserve-existing-destination":
        raise RuntimeError("failed decode modified an existing destination")


def _smoke_executable(directory: Path, executable: Path) -> None:
    if os.name == "nt" and executable.suffix.lower() != ".exe":
        executable = executable.with_suffix(".exe")
    source = directory / "cli-source-π.bin"
    archive = directory / "cli-archive-π.m7a"
    restored = directory / "cli-restored-π.bin"
    protected = directory / "cli-protected-π.bin"
    source.write_bytes(_payload())

    _run_executable(
        executable,
        directory,
        "encode-native-preview",
        str(source),
        str(archive),
        "--threads",
        "2",
        "--kdf-log-n",
        "14",
    )
    inspected = json.loads(
        _run_executable(
            executable,
            directory,
            "inspect-native-preview",
            str(archive),
            "--max-kdf-log-n",
            "17",
            "--json",
        )
    )
    if inspected["format_name"] != "M7A0" or not inspected["authenticated"]:
        raise RuntimeError("native executable inspect reported invalid preview identity")
    _run_executable(
        executable,
        directory,
        "decode-native-preview",
        str(archive),
        str(restored),
        "--max-kdf-log-n",
        "17",
    )
    if restored.read_bytes() != _payload():
        raise RuntimeError("native executable round trip changed the payload")

    protected.write_bytes(b"preserve-existing-destination")
    failure = subprocess.run(
        [
            str(executable),
            "decode-native-preview",
            str(archive),
            str(protected),
            "--password-env",
            PASSWORD_VARIABLE,
        ],
        check=False,
        capture_output=True,
        cwd=directory,
        encoding="utf-8",
        env=_executable_environment("wrong-password"),
        timeout=EXECUTABLE_TIMEOUT_SECONDS,
    )
    if failure.returncode == 0 or "wrong password or archive was modified" not in failure.stderr:
        raise RuntimeError("native executable did not fail generically for a wrong password")
    if protected.read_bytes() != b"preserve-existing-destination":
        raise RuntimeError("native executable failure modified an existing destination")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path)
    arguments = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="mosaic-native-preview-smoke-") as raw_directory:
        directory = Path(raw_directory)
        _smoke_import_api(directory)
        if arguments.executable is not None:
            _smoke_executable(directory, arguments.executable.resolve())
    print("native M7A0 Python preview smoke passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
