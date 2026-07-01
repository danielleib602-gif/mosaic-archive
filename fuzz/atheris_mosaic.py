"""Atheris entrypoint for Mosaic's public parsers and mode decoders."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from mosaic_archive.coverage_fuzzing import fuzz_one_input


def test_one_input(data: bytes) -> None:
    fuzz_one_input(data)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
