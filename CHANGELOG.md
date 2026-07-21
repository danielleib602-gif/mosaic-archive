# Changelog

All notable project changes are recorded here. Mosaic Archive is pre-1.0, so
experimental encoder behavior may change while documented decoder compatibility
is preserved.

## [Unreleased]

### Security

- Every active MSC1, MSC2, MSC6, MSR1, and MSR2 encoder now binds traversal
  and reads to captured root, directory, and file identities. Ancestors and the
  exact opened file handle are checked for every read, and a complete topology
  and identity rescan runs immediately before atomic publication. Source
  replacement, additions, removals, and link/reparse-point substitution
  observable at a binding check are rejected with temporary-output cleanup.
- Stable `v1.*` and later release tags now fail before binary construction
  unless all nine automatic and external 1.0 readiness gates are complete.
- The readiness CLI exposes a fail-closed `--require-ready` policy for release
  automation while preserving the seven-gate pre-1.0 policy.
- Stable evidence is sealed into a schema-v3 annotated tag and must bind the
  reviewed commit, attested candidate, tag target, workflow SHA, and checkout
  before native builds start; fake, lightweight, malformed, oversized, moved,
  or version-mismatched tags are rejected.
- Stable preflight verifies the immutable candidate release's exact assets,
  checksums, workflow/source-pinned attestations, candidate tag target, and
  review-bundle digest, then repeats source and bundle checks before publishing.
- The release workflow can publish an attested prerelease candidate only from
  the exact current protected-main commit, closing the post-review evidence
  circularity without permitting source changes.
- Candidate publication rechecks protected `main` immediately before release,
  binary smoke tests derive their expected version from project metadata, and
  the checksum manifest now receives and must pass its own workflow-pinned
  attestation.
- PyInstaller and its transitive release-build dependencies are lockfile-pinned.
  Stable releases repeat candidate verification and promote the exact reviewed
  candidate payload bytes; fresh platform rebuilds remain smoke checks only.
- Final publication rechecks the remote annotated-tag object, protected `main`,
  and candidate release identity, preserves the candidate checksum manifest,
  and rejects any published release whose immutable API asset digests differ
  from the locally attested manifest.
- Repository rulesets restrict stable tag creation to the release authority and
  prevent stable or candidate tag mutation and deletion after publication.
- Structured MSC2 corruption regressions now re-authenticate traversal,
  digest-mismatch, and entry-index/size metadata mutations. Separate structural
  cases cover trailing bytes, frame order, padding alignment, frame-size
  budgets, and atomic temporary-output cleanup.
- MSC2 and MSC6 decoding now invokes caller progress callbacks inside the
  atomic-output cleanup scope, so an exception from the first callback cannot
  leak a temporary file or folder tree.
- MSC2 and MSC6 caller frame-count budgets now reject from the public header,
  before expensive key derivation or manifest decryption.
- Structured MSC6 regressions now re-authenticate traversal, file/chunk digest,
  truncation, and occurrence/size metadata mutations. Separate MSC6 cases cover
  trailing bytes, frame order, padding alignment, and caller resource limits.
- Every MSC1-through-MSC6 decoder plus experimental MSR1 and MSR2 now rejects
  direct, symlinked, hard-linked, and late-rebound output aliases. Checks bind
  to the identity and size of the file actually opened, fail before password
  derivation, and run again immediately before atomic publication.
- MSR2 encoding now rejects non-integer or out-of-range frame/padding options
  before scanning input, deriving a key, or creating temporary output.
- Authenticated MSR2 metadata regressions cover traversal, file/chunk digest
  failures, and late folder cleanup. A separate trailing-byte case verifies
  existing-file preservation before restoration begins.

### Documentation

- Added a locked-corpus scorecard for identity-bound one-pass encoding,
  including all 33 timing samples per revision, physical source-open counts,
  archive sizes, frame bounds, and authenticated tree round trips.
- Added a locked-corpus scorecard for bounded delta routing, including the raw
  11-run timing samples, route-sequence hashes, archive sizes, frame bounds,
  observation counts, and authenticated round-trip results.
- Exact hosted v0.39 benchmark JSON and Markdown, workflow provenance, source
  tree binding, and artifact hashes are committed for independent review.
- The independent-review and release guides document the candidate-seal flow
  and treat the committed external-gate JSON as an incomplete tag template.

### Changed

- Dedup and solid manifest construction now computes file digests, chunks,
  owners, and unique-chunk callbacks in one content pass. MSR1 and MSR2 open
  each source file once and MSC6 twice instead of three times. Thirty-three
  alternating independent Windows processes per revision show corpus v1
  effectively flat at 0.295302% slower, while corpus v2 improves by 6.972763%.
  Archive bytes, unique-chunk counts, maximum frame payloads, and authenticated
  round trips are preserved.
- Solid-lane delta routing remains exact through 8,192 observations and uses 15
  deterministic, region-stratified windows for larger chunks, capping the
  sampled Python work at 4,095 observations. Entropy, decision-band, and
  per-window advantage-spread guards fall back to exact analysis when the
  sample is not decisive. Eleven alternating independent Windows processes per
  revision improved locked-corpus median encode time by 10.304818% on corpus v1
  and 10.873414% on corpus v2 while preserving route sequences, archive bytes,
  chunk counts, frame bounds, and authenticated round trips.
- Coverage CI now measures branches across every package module instead of
  omitting the CLI, module entrypoint, benchmark runner, and comparison tools.
  Reports retain two decimal places, and focused in-process tests exercise
  those user-facing orchestration paths.
- Pinned `astral-sh/setup-uv` 8.3.0 and `actions/attest` 4.1.1 across the CI,
  benchmark, fuzzing, reliability, and release workflows, with policy tests
  bound to the reviewed upstream tag SHAs.
- Pinned the security-hardened `actions/checkout` 7.0.0 in every workflow and
  completed the remaining `actions/upload-artifact` 7.0.1 migration.
- Raised the strict type-checking baseline to mypy 2.x and locked CI to the
  verified mypy 2.3.0 toolchain.

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
