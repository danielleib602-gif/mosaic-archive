# Project status

- Package version: 0.39.0
- Publication status: v0.39.0 source and native binaries published with
  checksums, GitHub build attestations, and an exact-source review bundle
- Stable-format status: MSC6 is frozen and remains supported; additive MSC7 is
  the conditional default-format target for 1.0
- Repository status at this snapshot: public; `v0.39.0` is published

## What is ready now

- The default `msc encode` path writes authenticated MSC6 archives and the
  decoder retains permanent fixtures for MSC1 through MSC6.
- Every MSC1-through-MSC6 decoder plus experimental MSR1 and MSR2 rejects
  direct, symbolic-link, hard-link, and late-rebound output aliases using the
  identity and size of the archive file actually opened. Initial aliases fail
  before password derivation and publication repeats the identity check.
- Every active MSC1, MSC2, MSC6, MSR1, and MSR2 encoder binds discovered root,
  directory, and file identities through ancestor and exact-handle validation,
  then repeats a complete topology and identity scan before atomic publication.
  Source replacement, additions, removals, and link/reparse-point substitution
  observable at a binding check fail without publishing partial output.
- The opt-in `--format solid` path writes the experimental MSR2 container with
  bounded authenticated frames, compact encrypted metadata, solid compression
  lanes, Gear content-defined chunking, and cross-file deduplication.
- The native laboratory now has an explicit authenticated single-stream
  vertical slice. `M7A0` wraps the exact `M7R0` core stream in bounded scrypt
  and ChaCha20-Poly1305 records and a mandatory transcript footer. A shared
  Rust regular-file API provides alias-safe sibling temporary output and
  atomic publication. The laboratory CLI and a private CPython 3.11+ ABI3
  extension both use that boundary; the typed Python facade and its three
  explicit preview commands stay outside stable archive dispatch. This is a
  non-stable preview, not an MSC7 fixture.
- The current CI configuration gives the Rust workspace pinned-toolchain
  format, strict Clippy, tests, and release-build checks, plus a dedicated
  Linux/Windows/macOS ABI3 wheel matrix. Each wheel is installed into a clean
  environment and must complete an authenticated round trip and preserve an
  existing destination on failure. Release PyInstaller builds bundle the
  extension and run the same smoke. These are configured hosted gates until the
  current tree passes them.
- Linux, Windows, and macOS binary builds are smoke-tested in CI. The
  `v0.39.0` release includes checksum-verified native binaries, keyless
  GitHub/Sigstore build provenance, and an exact-source review bundle.
- The release workflow fails closed for `v1.*` and later stable tags until all
  ten readiness gates are complete. Schema-v3 tag evidence can bind the
  reviewed and attested candidate to the tag target and workflow checkout, but
  it cannot complete the competitive gate; that requires the future schema-v4
  scorecard binding. The current release workflow
  verifies the immutable candidate release, all checksums and attestations, and
  the deterministic review-bundle digest before building or publishing stable
  assets. Native build dependencies are lockfile-pinned, and stable publication
  promotes the exact verified candidate bytes rather than a later rebuild. A
  post-publication check requires immutable release metadata and exact API asset
  digests before the workflow can succeed.
- Immutable releases and repository tag rulesets now make stable tags
  release-authority-only and prevent published candidate tags from being moved
  or deleted. Human reviewer identity remains an explicit out-of-band trust
  boundary until evidence is signed by a pinned independent identity.
- The deterministic public corpus, compatibility fixtures, parser/decoder fuzz
  harnesses, 256/1,025/2,049 MiB sustained-soak tiers, and cross-platform test
  matrix are committed.
- Competitive Contract v1 now has a strict unverified development-scorecard
  boundary, exact Linux cgroup-v2 mount/root qualification, and a Rust native
  supervisor that creates an unpredictable fixed-controller session and hands
  its descriptor to Python as an authenticated, live, process-bound capability.
  That capability can configure fresh leaves; path-only qualification, stale
  peers, forked leases, and production post-spawn attachment fail closed. The
  offline descriptor-bound corpus-copy foundation still treats approval-shaped
  inputs as unverified claims. Display paths carry no authority, secure reopen
  yields bounded immutable snapshots, and publication is not reported durable
  until directory sync plus final-name revalidation succeeds. These foundations
  are intentionally non-binding: native `clone3` PID-namespace/pre-exec launch,
  complete executable identity, externally approved immutable corpus locking,
  the real MSC7 candidate, signed raw measurements, and schema-v4 tag binding
  remain.
- The package is MIT-licensed and contains public contribution, security,
  release, compatibility, format, benchmark, and threat-model documentation.

## Measured capability

The schema-v2 local Windows report in `benchmarks/v0.35.0/report.json` covers
five full-corpus runs plus one verified run for each of 13 categories. The
expanded corpus has 78 declared files and presents 1,719,961 bytes to the
archive after including its manifest. Encrypted, authenticated, 256-byte-padded
MSR2 produces 293,523 bytes. Median encode time is 0.441192 seconds with a
0.011131-second median absolute deviation; median decode time is 0.084800
seconds.

Mosaic is 540,213 bytes smaller than ZIP overall. It is smaller on deduplicated,
image-like, numeric, source, sparse, structured, tabular, text, tiny-file, and
Unicode categories. It is 269 bytes larger on precompressed data, 345 bytes
larger on random data, and its 325-byte empty archive is 107 bytes larger.
Local 7-Zip and zstd executables were unavailable, so the committed report
marks those comparisons unavailable rather than substituting estimates.

The v0.36 scorecard in
`.ecc/benchmarks/msc-v0.36-raw-entropy-lane.json` compares 11 contemporaneous
Windows runs per revision. Authenticated raw passthrough improves median random
encode time from 0.080268 to 0.058986 seconds (26.514452%) and precompressed
time from 0.079420 to 0.060098 seconds (24.328667%). Both archives remain
131,679 bytes. The bounded distant-reuse probe keeps LZMA enabled for the
historical corpus, preserving its 275,859-byte archive.

The v0.37 scorecard in
`.ecc/benchmarks/msc-v0.37-segmented-gear.json` compares 11 contemporaneous
Windows runs per revision. Skipping Gear positions where a boundary cannot yet
occur improves median encode time from 0.275920 to 0.266104 seconds on corpus
v1 (3.557517%) and from 0.567044 to 0.522114 seconds on corpus v2 (7.923612%).
Chunk boundaries, maximum frame payloads, and the 275,859-byte and 293,523-byte
archives remain unchanged.

The v0.38 scorecard in
`.ecc/benchmarks/msc-v0.38-bounded-gear-scan.json` compares 11 alternating
independent Windows processes per revision. Capping each Gear scan at the
mandatory maximum boundary improves expanded corpus-v2 median encode time from
0.473999 to 0.456231 seconds (3.748490%). Corpus v1 is effectively flat at
+0.206949%. Chunk counts, maximum frame payloads, and both archive sizes remain
unchanged.

The v0.39 scorecard in
`.ecc/benchmarks/msc-v0.39-lane-match-search.json` compares 11 alternating
independent Windows processes per revision. Separating LZMA encoder search
parameters from the decoder filter chain shrinks expanded corpus-v2 from 293,523
to 291,731 bytes (1,792 bytes) and improves median encode time by 6.727759% on
corpus v1 and 2.986441% on corpus v2. Both lanes keep the preset-6 LZMA2 decoder
property byte, so the unchanged v0.38 decoder restores every candidate archive;
chunk counts and maximum frame payloads are unchanged.

The hosted Ubuntu v0.39 workflow then reproduced the 291,731-byte MSR2 result
across five independent runs. The same verified corpus produced 336,784 bytes
with encrypted 7-Zip, 336,723 bytes with compression-only 7-Zip, and 496,246
bytes with zstd. Mosaic remains slower; these results are corpus-specific and
do not establish universal superiority.

The unreleased v0.40 scorecard in
`.ecc/benchmarks/msc-v0.40-bounded-delta-routing.json` compares 11 alternating
independent Windows processes per revision. Large-chunk delta routing now uses
15 deterministic, region-stratified windows capped at 4,095 Python delta
observations, with exact analysis retained through 8,192 observations and
conservative exact fallbacks for ambiguous or heterogeneous samples. Median
encode time improves by 10.304818% on corpus v1 and 10.873414% on corpus v2.
The locked corpora retain identical route-sequence hashes, lane distributions,
archive bytes, chunk counts, maximum frame payloads, and authenticated round
trips. This is scoped evidence, not a universal route-equivalence claim.

The identity-bound one-pass scorecard in
`.ecc/benchmarks/msc-v0.40-source-identity-one-pass.json` compares 33
alternating independent Windows processes per revision. Manifest hashing and
chunk discovery now share one content pass, reducing physical source opens to
two per file for MSC6 and one per file for MSR1/MSR2. Median encode time is
effectively flat from 0.214052 to 0.214684 seconds on corpus v1 (0.295302%
slower) and improves from 0.342857 to 0.318950 seconds on corpus v2
(6.972763%). The 275,859-byte and 291,731-byte archives, unique-chunk counts,
maximum frame payloads, and authenticated tree round trips remain unchanged.

The fast-profile routing scorecard in
`.ecc/benchmarks/msc-v0.40-fast-profile-analysis.json` compares 11 alternating
fresh Windows processes per revision. Removing the unused router analysis
improves median MSC6-fast encode time from 0.464328 to 0.339373 seconds on
corpus v1 (26.910926%) and from 0.760783 to 0.547597 seconds on corpus v2
(28.022006%). The 493,005-byte and 632,681-byte archives, mode distributions,
feature statistics, chunk counts, and authenticated round trips are identical.

The unreleased v0.41 scorecard in
`.ecc/benchmarks/msc-v0.41-low-bit-zstd-native-core.json` binds the performance
sprint to exact commits and 11 fresh Windows processes per revision. Exact
low-bit Gear state and high-entropy zstd with framed-storage RAW fallback shrink
expanded corpus v2 from 291,731 to 290,451 bytes (1,280 bytes, 0.438760%). Median
encode time improves from 0.345192 to 0.263301 seconds (23.723347%), median
decode improves from 0.099696 to 0.091824 seconds (7.895225%), and all 13 public
category archive sizes remain unchanged. Five fresh-process peak-working-set
samples per revision are effectively flat at +0.129889%.

The same artifact records the first real native compression-core vertical
slice. The explicitly non-stable `M7R0` envelope performs Gear CDC, bounded
deduplication, adaptive LZMA2/delta4+zstd/zstd/RAW routing, and deterministic
ordered parallel emission. A 64 MiB diagnostic round-trips to 5,145,673 bytes;
three current runs have median encode throughput of 42.049 MiB/s with one
worker and 145.347 MiB/s with eight, while decode reaches 184.374 MiB/s. This
is in-memory laboratory evidence, not authenticated MSC7, end-to-end disk
throughput, or a Competitive Contract result.

This native slice adds the separate non-stable `M7A0` outer envelope. It
derives a 32-byte key with scrypt (writer `log2(N)` 14–18, default 17, `r=8`,
`p=1`); decode caps the accepted exponent at 17 by default and accepts an
explicit caller policy from 14 through 18. It authenticates at most 2,097,144 inner
bytes per ChaCha20-Poly1305 record, pads short plaintext records to 1 KiB, and
requires a final authenticated transcript, inner-stream digest, exact totals,
and physical EOF. This sprint has no new committed performance measurement:
`M7A0` is functional security engineering, not a stable MSC7 archive or binding
competitive result.

On a local deterministic 67,108,864-byte incompressible diagnostic, the inner
`M7R0` stream is 67,123,984 bytes and the aligned `M7A0` archive is 67,127,424
bytes. Full 2,097,144-byte inner payloads eliminate redundant full-record
padding and save 31,744 bytes versus the earlier 67,159,168-byte outer result.
The remaining 18,560-byte overhead over the source is 0.027656%, below the
diagnostic `ceil(input/2000)` threshold. This is local non-binding size
evidence; no M7A0 timing or competitive result is claimed.

The authenticated core is now reachable from installed Python builds without
duplicating the file-safety logic. `mosaic-msc7-python` is a private CPython
3.11+ ABI3 extension; `mosaic_archive.native_preview` adds frozen typed stats,
strict backend identity/schema validation, generic authentication errors,
Unicode paths, complete resource-limit forwarding, and fail-closed backend
loading. Native work releases the GIL. The separate Python preview CLI accepts
a hidden prompt or named environment variable and rejects literal password
arguments. MSC6 remains the normal/default writer, and ordinary decode/inspect
do not auto-detect `M7A0`.

The v0.32 scorecard in
`.ecc/benchmarks/msc-v0.32-gear-cdc.json` compares five contemporaneous hosted
Ubuntu runs per revision. Median MSR2 encode time improved from 0.617936 seconds
in v0.31 to 0.437371 seconds in v0.32, a 29.220627% gain. The authenticated,
256-byte-padded archive remains 275,859 bytes and its maximum frame payload
improves from 263,518 to 263,510 bytes.

The final v0.32 hosted comparison run produced:

| Method | Archive bytes | Scope |
|---|---:|---|
| Mosaic MSR2 | 275,859 | encrypted, authenticated, 256-byte padded |
| encrypted 7-Zip | 292,864 | AES-256 data and header encryption |
| zstd | 365,949 | compression only |
| ZIP | 718,214 | compression only |
| gzip | 720,233 | compression only |

These results apply only to the committed duplicate-rich generated corpus.
They do not establish general superiority over mature compressors. The current
Mosaic encoder is also slower than those tools on that corpus.

## MSC 1.0 distance

`msc readiness --json` evaluates ten committed stable-release gates. Seven are
complete (70%). The three remaining formal gates are Competitive Contract v1
single-profile dominance, an independent security review, and the first
independently verified attested binary release. The v0.33 maintainer review is
documented in
`docs/SECURITY_REVIEW_v0.33.md`; it does not claim independence.
The percentage reports completed checklist gates, not a statistical estimate
of security, quality, or total engineering completion. Adding the explicit
competitive criterion changes the denominator from nine to ten rather than
pretending existing work regressed. Extended soak scope and other residual
work remain visible separately. Encoder source-identity hardening is implemented
across every active writer; portable filesystem operations still retain the
explicitly documented hostile-local-process boundary.
The v0.34 handoff adds a deterministic exact-commit review bundle and rejects
unstructured external evidence or a release commit that differs from the
reviewed commit. The stable release preflight now also rejects filled templates,
fake commits, lightweight tags, tag/version mismatches, and any difference
among the reviewed source, candidate attestation, annotated tag, workflow SHA,
and checkout. A manual workflow can publish the final protected-main commit as
an attested prerelease candidate before external review begins.

## Known release boundaries

- This is pre-1.0 experimental software and has not received an independent
  security audit. Do not present it as a replacement for a reviewed archival or
  cryptographic product.
- MSR2 is opt-in. MSC6 remains the default writer and a frozen compatibility
  commitment. `M7R0` exercises the proposed compression pipeline and `M7A0`
  proves an authenticated single-stream composition, but neither is an MSC7
  archive or compatibility fixture. MSC7 cannot become the default until its
  file/tree format, Python surface, fixtures, security work, and competitive
  gate pass.
- The GitHub workflow publishes native executables, checksums, and provenance.
  PyPI publication is not configured.
- On 2026-07-03, GitHub refused to start private-repository jobs because of an
  account billing/spending-limit gate. The repository is now public. On
  2026-07-06, PR #43 and merge commit `73f2d9b` completed real Linux, Windows,
  macOS, quality/security, benchmark, review-bundle, and binary-build steps.
  The former account gate is resolved.
- Windows binaries are not Authenticode-signed and macOS binaries are not
  Developer-ID-signed or notarized, so operating systems may warn.
- Padding hides exact length only within the selected bucket and cannot hide
  rough archive size.
- The full functional limits remain listed in the README.
- Raw Git history contains a Gmail author-domain entry. It is not a repository
  secret, but the address in commit metadata becomes public if repository
  visibility changes. Rewriting shared history would invalidate existing commit
  IDs and tags, so that privacy decision belongs to the maintainer.

## Verification snapshot

The current tree collects 603 Python unit/integration tests. Local Windows runs
pass 533 and skip 70 Linux-capability-specific cases. The last protected-main
Linux snapshot passed 557 and skipped 3; hosted PR CI remains the authority for
the next Linux count. CI measures statement and branch
coverage across every package module on Linux, where the cgroup-v2 and sealed-
memfd paths execute. The last protected-main result is 84.79% against a required
80%, with no package module omitted. A Windows-only coverage run is
intentionally not the release gate because those Linux-kernel paths cannot
execute there. The portable Rust workspace now executes 46 compression-core,
authenticated-envelope, file-API, and laboratory-CLI tests plus 7 binding-
supervisor tests; all 53 pass locally on Windows. The installed-extension suite
separately exercises the PyO3 ABI. Linux retains its
additional opt-in real-cgroup paths. The configured macOS native-core job and hosted Linux CI
remain authoritative for those platforms.
Ruff, strict mypy, Bandit, dependency audit, bytecode
compilation, source/wheel builds, and package-metadata validation pass. The
deterministic review bundle rejects payload tampering, compressed members,
unsafe paths, invalid source identities, and resource-limit violations before
publication.

The deterministic reliability campaign executes 10,000 mutations across 14
targets. A local 1,025 MiB high-entropy MSC6 soak crossed 1 GiB and restored
exactly. The protected-main 2,049 MiB hosted tier crossed signed 32-bit offsets,
produced a 2,152,567,212-byte archive from 2,148,532,224 source bytes, and
restored exactly; durable evidence for both runs is committed under
`.ecc/benchmarks/`. The v0.39 PR and `main`
checks passed across Python 3.11 and 3.13 on
Linux and Windows, Python 3.13 on macOS, all three native-binary smoke builds,
the quality/security job, deterministic review-bundle generation, and the
hosted mature-compressor benchmark.

Tracked files and Git history were checked for common private-key, AWS-key, and
GitHub-token signatures. No matching secret or dangerous credential file was
found. This is a bounded automated scan, not a guarantee that arbitrary prose
contains no sensitive information.

## Current development focus

The v0.39.0 release is published and its checksums, Windows binary, exact-source
bundle, and GitHub attestation have been verified as documented in
`docs/RELEASE_VERIFICATION_v0.39.md`. The next priorities are:

1. finish the authoritative runner with a native pre-exec PID namespace,
   race-free `clone3(CLONE_INTO_CGROUP)` placement, isolated workload identity,
   complete descendant executable identities, bounded outputs, and signed
   raw-run records; the exclusive delegated-root/session capability slice is
   complete. The native supervisor and Python runner have now been split into
   focused protocol, cgroup, qualification, lifecycle, and test modules. An
   internal non-binding ABI probe now proves the exact `clone3` flag layout,
   namespace PID 1, initial leaf placement, and pidfd-only bounded reaping. The
   next executable slice is the fixed-payload namespace-reaper self-test
   specified in `docs/NATIVE_LAUNCHER_DESIGN.md`;
2. acquire and externally approve all six immutable public corpus bundles,
   finish aggregate member manifests/recipes, and commit the real lock;
3. extend the authenticated path-only `M7A0` vertical slice into the additive
   MSC7 file/tree format, including an encrypted canonical manifest,
   identity-bound traversal, safe extraction, atomic directory publication,
   frozen qualified codec identifiers, and permanent fixtures;
4. run all 48 contract cases, publish all 2,640 content-addressed raw records,
   and add schema-v4 tag binding only after the candidate actually passes;
5. freeze and publish a new exact-commit attested candidate after the current
   unreleased hardening is merged, then rebind
   [issue #50](https://github.com/danielleib602-gif/mosaic-archive/issues/50)
   and the review handoff to that candidate rather than the older v0.39 commit;
6. complete the independent security review and resolve or document its
   findings;
7. decide whether a separate compression-only profile is worth the security
   and product complexity; the remaining incompressible-byte delta is the
   expected cost of encryption, authentication, and privacy padding;
8. keep MSR2 as research evidence rather than promoting its wire format;
9. add PyPI trusted publishing only if a Python-package release channel is
   desired.

The detailed milestone history and rollback rules remain in
`plans/mosaic-archive-roadmap.md`.

## Maintainer publication record

The public-repository and commit-email privacy choices were accepted for this
release. Required workflows passed, `v0.39.0` was created from
`f99495cfc5be73617da8f929f89c3c044abbce89`, all three binaries and the review
bundle were published, and downloaded assets were verified. Announcement and
documentation must retain the experimental-alpha and no-independent-audit
language.
