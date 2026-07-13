# Project status

- Package version: 0.39.0
- Publication status: v0.39.0 source and native binaries published with
  checksums, GitHub build attestations, and an exact-source review bundle
- Stable-format status: MSC6 is frozen for the planned 1.0 line
- Repository status at this snapshot: public; `v0.39.0` is published

## What is ready now

- The default `msc encode` path writes authenticated MSC6 archives and the
  decoder retains permanent fixtures for MSC1 through MSC6.
- The opt-in `--format solid` path writes the experimental MSR2 container with
  bounded authenticated frames, compact encrypted metadata, solid compression
  lanes, Gear content-defined chunking, and cross-file deduplication.
- Linux, Windows, and macOS binary builds are smoke-tested in CI. The
  `v0.39.0` release includes checksum-verified native binaries, keyless
  GitHub/Sigstore build provenance, and an exact-source review bundle.
- The release workflow fails closed for `v1.*` and later stable tags until all
  nine readiness gates are complete and schema-v3 tag evidence binds the
  reviewed and attested candidate to the tag target and workflow checkout. It
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
  harnesses, scheduled 256 MiB soak test, and cross-platform test matrix are
  committed.
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

`msc readiness --json` evaluates the nine committed stable-release gates.
Seven are complete (77.777778%). The two remaining formal gates are an
independent security review and the first independently verified attested
binary release. The v0.33 maintainer review is documented in
`docs/SECURITY_REVIEW_v0.33.md`; it does not claim independence.
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
- MSR2 is opt-in. MSC6 remains the default writer and the frozen 1.0-line
  compatibility commitment.
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

The current checkout passes 247 unit/integration tests on Python 3.13.
Full-package coverage is 4,051 of 4,505 statements and 1,136 of 1,464 branches
(5,187 of 5,969 combined opportunities, 86.90%); no package module is omitted
from the gate. Ruff, strict mypy, Bandit, dependency audit, bytecode
compilation, source/wheel builds, and package-metadata validation pass. The
deterministic review bundle rejects payload tampering, compressed members,
unsafe paths, invalid source identities, and resource-limit violations before
publication.

The deterministic reliability campaign executes 10,000 mutations across 14
targets, and the local 256 MiB MSC6 soak round trip restores the exact source
SHA-256. The v0.39 PR and `main` checks passed across Python 3.11 and 3.13 on
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

1. recruit an independent reviewer through
   [issue #50](https://github.com/danielleib602-gif/mosaic-archive/issues/50)
   using the exact v0.39 source bundle, published review brief, and durable
   machine-readable benchmark evidence;
2. complete the independent security review and resolve or document its
   findings;
3. decide whether a separate compression-only profile is worth the security
   and product complexity; the remaining incompressible-byte delta is the
   expected cost of encryption, authentication, and privacy padding;
4. decide whether and how MSR2 should graduate from opt-in research format;
5. add PyPI trusted publishing only if a Python-package release channel is
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
