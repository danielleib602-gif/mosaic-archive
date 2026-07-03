# Project status

- Package version: 0.33.0
- Publication status: READY for source publication; tagged binary release
  BLOCKED by the GitHub Actions account gate described below
- Stable-format status: MSC6 is frozen for the planned 1.0 line
- Repository status at this snapshot: private; no `v0.33.0` tag has been created

## What is ready now

- The default `msc encode` path writes authenticated MSC6 archives and the
  decoder retains permanent fixtures for MSC1 through MSC6.
- The opt-in `--format solid` path writes the experimental MSR2 container with
  bounded authenticated frames, compact encrypted metadata, solid compression
  lanes, Gear content-defined chunking, and cross-file deduplication.
- Linux, Windows, and macOS binary builds are smoke-tested in CI. A matching
  `v0.33.0` tag triggers checksum generation, keyless GitHub/Sigstore build
  provenance, and immutable GitHub release assets.
- The deterministic public corpus, compatibility fixtures, parser/decoder fuzz
  harnesses, scheduled 256 MiB soak test, and cross-platform test matrix are
  committed.
- The package is MIT-licensed and contains public contribution, security,
  release, compatibility, format, benchmark, and threat-model documentation.

## Measured capability

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

## Known release boundaries

- This is pre-1.0 experimental software and has not received an independent
  security audit. Do not present it as a replacement for a reviewed archival or
  cryptographic product.
- MSR2 is opt-in. MSC6 remains the default writer and the frozen 1.0-line
  compatibility commitment.
- The GitHub workflow publishes native executables, checksums, and provenance.
  PyPI publication is not configured.
- On 2026-07-03, GitHub refused to start PR, binary, reliability, and
  coverage-fuzz jobs because recent account payments failed or the Actions
  spending limit must be increased. No workflow steps executed. There are two
  valid paths: make the repository public or resolve billing while it remains
  private. GitHub documents that standard GitHub-hosted runners are free for
  public repositories. Then rerun the required workflows on `main` before
  creating `v0.33.0`; otherwise the tag cannot produce the promised binary
  assets.
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

The publication checkout passes 155 unit/integration tests on Python 3.13.
Exact source coverage is 3,205 of 3,634 executable lines (88.194827%). Ruff,
strict mypy, Bandit, dependency audit, bytecode compilation, source/wheel
builds, and package-metadata validation pass. A clean isolated installation of
the built wheel reports `msc 0.33.0` and completes a verified encrypted MSR2
round trip.

The deterministic reliability campaign executes 10,000 mutations across 14
targets, and the local 256 MiB MSC6 soak round trip restores the exact source
SHA-256. The last v0.32 code CI and cross-platform binary matrix passed before
the account gate appeared. The final documentation PR jobs did not fail code;
GitHub created them with zero steps and a billing/spending-limit annotation.

Tracked files and Git history were checked for common private-key, AWS-key, and
GitHub-token signatures. No matching secret or dangerous credential file was
found. This is a bounded automated scan, not a guarantee that arbitrary prose
contains no sensitive information.

## Current development focus

The immediate current work is to rerun the required workflows on `main`. That
requires making the repository public or resolving the private-repository
GitHub Actions account gate. After the v0.33 alpha is published, the next
priorities are:

1. complete an independent security review and resolve or document its findings;
2. promote repeated benchmark medians into the standard CI report schema;
3. expand corpus diversity before making broader compression claims;
4. decide whether and how MSR2 should graduate from opt-in research format;
5. add PyPI trusted publishing only if a Python-package release channel is
   desired.

The detailed milestone history and rollback rules remain in
`plans/mosaic-archive-roadmap.md`.

## Maintainer publication checklist

1. Review the commit-email privacy note above.
2. Make the repository public, or resolve the billing/spending-limit gate while
   keeping it private.
3. Rerun the required workflows on `main`.
4. Confirm every `main` and release-binary check is green.
5. Create and push the annotated tag `v0.33.0`.
6. Let the release workflow build, attest, and publish all three binaries.
7. Download one asset and verify both `SHA256SUMS` and its GitHub attestation.
8. Keep the experimental-alpha and no-independent-audit language in the
   announcement.
