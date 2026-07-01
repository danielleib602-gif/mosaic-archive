"""Command-line interface for Mosaic Archive."""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from mosaic_archive.archive_api import decode_path, encode_path, inspect_path
from mosaic_archive.benchmark import benchmark_path
from mosaic_archive.compatibility import current_policy
from mosaic_archive.exceptions import MosaicError
from mosaic_archive.stream_archive import ProgressEvent


def _add_password_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--password",
        help="archive password (visible to local process inspection; prompting is safer)",
    )
    group.add_argument(
        "--password-env",
        metavar="NAME",
        help="read the archive password from environment variable NAME",
    )


def _add_common_encode_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=65_536,
        help="target average content-defined chunk size (power of two)",
    )
    parser.add_argument("--cdc-min-size", type=int)
    parser.add_argument("--cdc-max-size", type=int)
    parser.add_argument(
        "--profile",
        choices=("fast", "balanced", "research"),
        default="balanced",
        help="codec search profile (default: balanced)",
    )
    parser.add_argument(
        "--padding-size",
        type=int,
        default=1024,
        help="per-frame length-hiding bucket (default: 1024; use 4096+ for more privacy)",
    )
    parser.add_argument(
        "--kdf-log-n",
        type=int,
        default=15,
        help="scrypt N as log2(N), from 14 to 18 (default: 15)",
    )


def _add_progress_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="show or suppress progress (default: show on an interactive terminal)",
    )


class _ProgressPrinter:
    def __init__(self) -> None:
        self._finished = False

    def __call__(self, event: ProgressEvent) -> None:
        if event.total_bytes:
            percentage = min(100.0, (event.completed_bytes / event.total_bytes) * 100)
            detail = f"{percentage:6.2f}%"
        else:
            detail = f"{event.completed_files}/{event.total_files} files"
        print(
            f"\r{event.stage.title()}: {detail}",
            end="",
            file=sys.stderr,
            flush=True,
        )
        finished = (
            event.completed_bytes >= event.total_bytes
            and event.completed_files >= event.total_files
        )
        if finished and not self._finished:
            print(file=sys.stderr)
            self._finished = True


def _password_from_args(arguments: argparse.Namespace) -> str:
    if arguments.password is not None:
        password = arguments.password
    elif arguments.password_env is not None:
        try:
            password = os.environ[arguments.password_env]
        except KeyError as error:
            raise ValueError(
                f"password environment variable is not set: {arguments.password_env}"
            ) from error
    else:
        password = getpass.getpass("Password: ")
    if not password:
        raise ValueError("password must not be empty")
    return cast(str, password)


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _human_size(size: int) -> str:
    value = float(size)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _print_result(operation: str, result: Any, as_json: bool) -> None:
    data = {"operation": operation, **_jsonable(result)}
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return
    print(f"Mosaic Archive - {operation}")
    for key, value in data.items():
        if key == "operation":
            continue
        label = key.replace("_", " ").title()
        if key.endswith("_size") or key.endswith("_bytes") or key == "padding_overhead":
            print(f"{label}: {_human_size(int(value))}")
        elif isinstance(value, float):
            print(f"{label}: {value:.6f}")
        elif isinstance(value, dict):
            print(f"{label}: {json.dumps(value, sort_keys=True)}")
        else:
            print(f"{label}: {value}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="msc",
        description="Adaptive, padded, authenticated file/folder archives (experimental alpha).",
    )
    parser.add_argument("--version", action="version", version="msc 0.11.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encode_parser = subparsers.add_parser("encode", help="create an encrypted .msc archive")
    encode_parser.add_argument("input", type=Path)
    encode_parser.add_argument("output", type=Path)
    _add_password_options(encode_parser)
    _add_common_encode_options(encode_parser)
    _add_progress_option(encode_parser)
    encode_parser.add_argument("--json", action="store_true")

    decode_parser = subparsers.add_parser("decode", help="authenticate and restore an archive")
    decode_parser.add_argument("archive", type=Path)
    decode_parser.add_argument("output", type=Path)
    _add_password_options(decode_parser)
    _add_progress_option(decode_parser)
    decode_parser.add_argument("--json", action="store_true")

    inspect_parser = subparsers.add_parser("inspect", help="verify and explain an archive")
    inspect_parser.add_argument("archive", type=Path)
    _add_password_options(inspect_parser)
    inspect_parser.add_argument("--json", action="store_true")

    benchmark_parser = subparsers.add_parser(
        "benchmark", help="measure an encode/decode round trip"
    )
    benchmark_parser.add_argument("input", type=Path)
    _add_password_options(benchmark_parser)
    _add_common_encode_options(benchmark_parser)
    benchmark_parser.add_argument(
        "--compare",
        action="store_true",
        help="also benchmark ZIP, gzip, zstd, and 7-Zip when supported/installed",
    )
    benchmark_parser.add_argument("--json", action="store_true")

    compatibility_parser = subparsers.add_parser(
        "compatibility",
        help="show format, upgrade, and deprecation guarantees",
    )
    compatibility_parser.add_argument("--json", action="store_true")
    return parser


def _run(arguments: argparse.Namespace) -> None:
    if arguments.command == "compatibility":
        _print_result(arguments.command, current_policy(), arguments.json)
        return
    password = _password_from_args(arguments)
    progress = None
    if arguments.command in {"encode", "decode"}:
        show_progress = arguments.progress
        if show_progress is None:
            show_progress = sys.stderr.isatty() and not arguments.json
        if show_progress:
            progress = _ProgressPrinter()
    result: Any
    if arguments.command == "encode":
        result = encode_path(
            arguments.input,
            arguments.output,
            password,
            chunk_size=arguments.chunk_size,
            padding_size=arguments.padding_size,
            kdf_log_n=arguments.kdf_log_n,
            cdc_min_size=arguments.cdc_min_size,
            cdc_max_size=arguments.cdc_max_size,
            profile=arguments.profile,
            progress=progress,
        )
    elif arguments.command == "decode":
        result = decode_path(
            arguments.archive, arguments.output, password, progress=progress
        )
    elif arguments.command == "inspect":
        result = inspect_path(arguments.archive, password)
    elif arguments.command == "benchmark":
        result = benchmark_path(
            arguments.input,
            password,
            chunk_size=arguments.chunk_size,
            padding_size=arguments.padding_size,
            kdf_log_n=arguments.kdf_log_n,
            cdc_min_size=arguments.cdc_min_size,
            cdc_max_size=arguments.cdc_max_size,
            profile=arguments.profile,
            compare=arguments.compare,
        )
    else:
        raise AssertionError(f"unhandled command: {arguments.command}")
    _print_result(arguments.command, result, arguments.json)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        _run(arguments)
    except (MosaicError, OSError, ValueError) as error:
        print(f"msc: error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
