# Changelog

All notable project changes are recorded here. Mosaic Archive is pre-1.0, so
experimental encoder behavior may change while documented decoder compatibility
is preserved.

## [Unreleased]

### Security

- Stable `v1.*` and later release tags now fail before binary construction
  unless all nine automatic and external 1.0 readiness gates are complete.
- The readiness CLI exposes a fail-closed `--require-ready` policy for release
  automation while preserving the seven-gate pre-1.0 policy.

### Documentation

- Exact hosted v0.39 benchmark JSON and Markdown, workflow provenance, source
  tree binding, and artifact hashes are committed for independent review.

### Changed

- Pinned `astral-sh/setup-uv` 8.3.0 and `actions/attest` 4.1.1 across the CI,
  benchmark, fuzzing, reliability, and release workflows, with policy tests
  bound to the reviewed upstream tag SHAs.
- Pinned the security-hardened `actions/checkout` 7.0.0 in every workflow and
  completed the remaining `actions/upload-artifact` 7.0.1 migration.

## [0.39.0] - 2026-07-05

### Added

- An 11-run alternating-process scorecard for lane-specific bounded LZMA match
  search across both deterministic public corpora.
- A regression that requires each solid lane to use its own encoder search
  parameters while preserving the shared decoder filter chain.

### Changed

- The standard solid lane bounds match search at nice length 48 and depth 12;
  the delta lane drops to the faster LZMA2 preset 5. Both retain the
  preset-6 LZMA2 decoder property byte, so v0.38 decoders restore every archive.
- Repeated benchmark evidence records randomized encrypted-7-Zip archive sizes
  as samples plus median/minimum/maximum while retaining strict size stability
  checks for Mosaic and deterministic comparison formats.
- Expanded corpus v2 shrinks from 293,523 to 291,731 bytes (1,792 bytes) while
  median Windows encode time improves by 6.727759% on corpus v1 and 2.986441%
  on corpus v2, with unchanged chunk counts and maximum frame payloads.

## [0.38.0] - 2026-07-04

### Added

- An 11-run alternating-process scorecard for bounded Gear scans on both
  deterministic public corpora.
- A regression that requires every Gear scan slice to stop at the mandatory
  maximum chunk boundary.

### Changed

- Gear chunking settles byte counts once per bounded segment instead of
  updating and checking the maximum size for every eligible byte.
- Median Windows encode time improves by 3.748490% on expanded corpus v2 and
  remains effectively flat (+0.206949%) on corpus v1, with unchanged chunk
  counts, frame payloads, and archive bytes.

## [0.37.0] - 2026-07-04

### Added

- An 11-run contemporaneous scorecard covering both deterministic public
  corpora and checking archive size plus maximum frame payload.
- Regression coverage proving that unobservable subminimum Gear prefixes do
  not enter the Python byte loop.

### Changed

- Gear chunking jumps directly to the first position where a boundary can be
  observed, while retaining byte-identical boundaries and archives.
- Median Windows encode time improves by 3.557517% on corpus v1 and 7.923612%
  on corpus v2, with unchanged 275,859-byte and 293,523-byte archives.

## [0.36.0] - 2026-07-04

### Added

- Backward-readable MC22 solid metadata with an authenticated raw lane codec.
- A bounded distant-reuse probe that distinguishes truly incompressible lanes
  from high-entropy lanes with relationships outside short codec windows.
- An 11-run contemporaneous scorecard for random and precompressed workloads.

### Changed

- High-entropy lanes without sampled distant reuse bypass futile LZMA
  compression while retaining the same authenticated framing and padding.
- Median random encode time improves by 26.514452% and precompressed time by
  24.328667%, with identical 131,679-byte archives.

## [0.35.0] - 2026-07-03

### Added

- Benchmark schema v2 with odd-count repeated runs, median/minimum/maximum/MAD
  timing summaries, and the raw timing samples.
- Deterministic corpus v2 with 78 files across 13 categories, adding source,
  sparse, tabular, Unicode, image-like, and tiny-file workloads.
- Per-category Mosaic and mature-tool archive sizes plus explicit byte deltas.
- A versioned local v0.35 evidence report covering five full-corpus runs and
  one verified run per category.

### Changed

- The standard benchmark now measures encrypted, padded MSR2 and includes the
  encrypted 7-Zip adapter when available.
- Publication aborts if any deterministic result changes across repetitions or
  any round trip fails.
- Hosted benchmark artifacts now identify the current package release instead
  of retaining the historical v0.12 label.

## [0.34.0] - 2026-07-03

### Added

- Deterministic, self-verifying source bundles built directly from committed
  Git objects for independent security review.
- A dedicated review-bundle workflow and a written independent-review scope,
  reproduction procedure, and report contract.
- Review source bundles in tagged-release checksums and signed provenance.

### Changed

- External 1.0 gates now require structured HTTPS, reviewer/verifier, date, and
  exact-commit evidence. A bare boolean no longer marks a gate complete.
- The first attested release must use the exact commit covered by the
  independent security review.

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
