"""Coverage-guided fuzz adapter and valid seed-corpus generation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.reliability import _FuzzTarget, _mode_targets, _parser_targets


def _targets() -> tuple[_FuzzTarget, ...]:
    return _parser_targets() + _mode_targets()


def fuzz_one_input(data: bytes) -> None:
    """Dispatch one byte string to a parser or decoder selected by its prefix."""
    if not data:
        return
    targets = _targets()
    target = targets[data[0] % len(targets)]
    try:
        target.invoke(data[1:])
    except ArchiveFormatError:
        return


def generate_seed_corpus(destination: Path) -> tuple[Path, ...]:
    """Write one valid, selector-prefixed seed for every fuzz target."""
    destination.mkdir(parents=True, exist_ok=True)
    seeds: list[Path] = []
    for selector, target in enumerate(_targets()):
        seed = destination / f"{selector:02d}-{target.name}"
        seed.write_bytes(bytes((selector,)) + target.valid_input)
        seeds.append(seed)
    return tuple(seeds)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)
    seeds = generate_seed_corpus(arguments.destination)
    print(f"wrote {len(seeds)} coverage-fuzz seeds to {arguments.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
