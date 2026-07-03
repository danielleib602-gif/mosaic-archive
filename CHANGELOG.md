# Changelog

All notable project changes are recorded here. Mosaic Archive is pre-1.0, so
experimental encoder behavior may change while documented decoder compatibility
is preserved.

## [0.33.0] - 2026-07-03

### Added

- Caller-overridable restored-size, frame/block-count, and legacy MSC1
  archive-size limits across decode, inspect, Python APIs, and the CLI.
- Machine-readable `msc readiness --json` evaluation of all nine MSC 1.0 gates.
- Current internal security review with findings, fixes, and residual risks.

### Security

- Restored-size and frame limits are enforced before destination creation.
- Whole-buffer MSC1 ciphertext allocation is capped before reading.
- MSR2 metadata decoding no longer ends with an unbounded decompressor flush.
- MSC1 inspection hashes into a null writer instead of retaining output bytes.

## [0.32.0] - 2026-07-02

### Added

- Deterministic one-lookup Gear content-defined chunk boundary detection.
- Repeated hosted-Linux benchmark evidence using five contemporaneous runs per
  revision.
- Publication status, contribution, and vulnerability-reporting documentation.

### Changed

- Hosted MSR2 median encode time improved by 29.220627% versus v0.31.
- Maximum public-corpus frame payload improved by 8 bytes while the final
  275,859-byte archive remained unchanged.

## [0.31.0] - 2026-07-02

- Replaced per-byte chunk-buffer appends with one block-sized extend.
- Improved repeated hosted-Linux median encode time by 4.944574% with identical
  archive bytes.

## [0.30.0] - 2026-07-02

- Compacted authenticated MSR2 metadata by 256 archive bytes.
- Retained legacy fixed-width MSR2 metadata decoding.
- Made generated corpus timestamps deterministic.

## [0.23.0] through [0.29.0] - 2026-07-01 to 2026-07-02

- Added an encrypted 7-Zip comparison and reduced hosted MSR2 encode time from
  1.889 seconds to 0.592 seconds through single-pass lane compression, cheap
  routing features, fused chunk traversal, specialized entropy analysis, and
  Buzhash hot-loop reductions.

## [0.13.0] through [0.22.0] - 2026-07-01

- Added cross-platform binary builds and provenance, solid-lane research,
  bounded authenticated MSR2 frames, parser hardening, compact metadata/lane
  streams, CLI access to MSR2, and format-aware benchmarking.

## [0.1.0] through [0.12.0] - 2026-06-29 to 2026-07-01

- Established authenticated encrypted archives, directory support, adaptive
  modes, content-defined deduplication, compatibility fixtures, fuzz/soak
  automation, the frozen MSC6 compatibility policy, and reproducible mature-tool
  comparisons.
