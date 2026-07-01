"""Machine-readable Mosaic format and package compatibility contract."""

from __future__ import annotations

from dataclasses import dataclass

from mosaic_archive import __version__


@dataclass(frozen=True, slots=True)
class CompatibilityPolicy:
    package_version: str
    writer_format_version: int
    readable_format_versions: tuple[int, ...]
    format_status: str
    backward_compatibility_rule: str
    incompatible_change_rule: str
    deprecation_notice_minor_releases: int
    removal_requires_major_version: bool


def current_policy() -> CompatibilityPolicy:
    """Return the compatibility promises enforced by fixtures and release policy."""
    return CompatibilityPolicy(
        package_version=__version__,
        writer_format_version=6,
        readable_format_versions=(1, 2, 3, 4, 5, 6),
        format_status="frozen-for-1.0",
        backward_compatibility_rule="decode-all-committed-formats",
        incompatible_change_rule="new-format-version",
        deprecation_notice_minor_releases=2,
        removal_requires_major_version=True,
    )
