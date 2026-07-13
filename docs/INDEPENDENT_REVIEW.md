# Independent review brief

This document defines the handoff for the independent security review required
before Mosaic Archive 1.0. A maintainer self-review does not satisfy this gate.
The reviewer must be able to identify the exact source commit, reproduce the
submitted source bundle, publish a report, and remain free to report unresolved
findings.

Public reviewer coordination and scope declarations belong in
[issue #50](https://github.com/danielleib602-gif/mosaic-archive/issues/50).

## Current baseline identity

The released `v0.39.0` source is the current reproducible review baseline:

- source commit: `f99495cfc5be73617da8f929f89c3c044abbce89`;
- source tree: `e8c56dbecc0398deafcbcdf6c2193f503a084b8d`;
- review bundle SHA-256:
  `2307cb50355e1b942718364780c8cb1af2dd9228d9550d864213f9d79ac7c130`;
- release: https://github.com/danielleib602-gif/mosaic-archive/releases/tag/v0.39.0;
- release verification:
  [RELEASE_VERIFICATION_v0.39.md](RELEASE_VERIFICATION_v0.39.md);
- hosted benchmark: [v0.39.0 results](../benchmarks/v0.39.0/report.md);
- benchmark provenance:
  [workflow, source-tree binding, and hashes](../benchmarks/v0.39.0/PROVENANCE.md).

Reviewers should download the release bundle named
`mosaic-review-f99495cfc5be73617da8f929f89c3c044abbce89.zip`, verify it against
both `SHA256SUMS` and the digest above, then use its embedded
`REVIEW-MANIFEST.json` as the authoritative file list.

Build a bundle from committed Git objects:

```console
python scripts/prepare_review_bundle.py build review.zip --revision HEAD
python scripts/prepare_review_bundle.py verify review.zip
sha256sum review.zip
```

The ZIP uses fixed metadata and stores files without implementation-dependent
compression. Repeating the build for the same commit must produce identical
bytes. `REVIEW-MANIFEST.json` records the full source commit, Git tree, package
version, mode, size, and SHA-256 digest of every tracked payload. Dirty or
untracked working-tree content is never included.

The `Independent review bundle` workflow performs the same build for
`GITHUB_SHA` and uploads the result. Tagged releases include this bundle in
`SHA256SUMS` and GitHub's signed build provenance alongside the native
executables.

The v0.39 baseline is useful for reviewer onboarding, but it cannot close the
stable 1.0 gates: its package version and source predate the final 1.0 commit.
The exact final candidate must already declare version 1.0.0 and contain every
source, dependency, workflow, and release-metadata change intended for stable
publication. Native build tooling and its transitive dependencies must already
be frozen in `uv.lock`.

## Final 1.0 candidate identity

When protected `main` is frozen for 1.0, manually dispatch the cross-platform
release workflow at that exact commit with `publish_candidate` enabled. It
publishes a durable `candidate-v1.0.0-COMMIT12` prerelease containing native
binaries, checksums, provenance, and the deterministic source bundle. The
workflow refuses to publish a candidate from an arbitrary branch or stale main
commit. Stable preflight later requires that candidate release to be immutable,
checks every asset digest, pins attestation identity to this release workflow
and protected-main source commit, and compares the downloaded review bundle to
the digest recorded by the reviewer. Stable publication promotes these exact
verified candidate payload bytes instead of substituting a later rebuild.

The reviewer and independent binary verifier must both name the same full
40-character candidate commit. Any later change to code, dependency locks,
package version, or workflows invalidates that candidate and requires a new
bundle, candidate release, review disposition, and verification.

## Human trust boundary

The automated gate cryptographically binds the candidate tag, source commit,
workflow provenance, artifact digests, and reviewed bundle bytes. It does not
authenticate the people named in `reviewer` or `verified_by`, establish their
independence, fetch or evaluate the linked report, or prove that they authored
it. Until reviewer-signed evidence is pinned to a separately verified identity,
these fields are maintainer assertions sealed into the release tag. Maintainers
and consumers must verify report authorship, independence, and disposition out
of band. A machine result of 9/9 proves evidence-to-source binding; it is not by
itself proof that an independent review occurred.

## Review scope

The review should cover:

- MSC1 through MSC6 and MSR2 parsing, authentication, decompression, inspection,
  and restoration paths;
- scrypt parameter handling, key derivation, nonce separation, AEAD associated
  data, authentication-failure behavior, and secret handling;
- restored-byte, frame/block-count, archive-size, metadata, path, allocation,
  and decompression limits;
- archive path normalization, collision handling, link/reparse-point rejection,
  temporary storage, and atomic destination publication;
- malformed, truncated, reordered, duplicated, and adversarially compressed
  input behavior;
- compatibility fixtures and the security consequences of retaining legacy
  decoders;
- release workflow permissions, dependency pinning, checksums, provenance, and
  the relationship between reviewed source and published binaries.

Standard cryptographic primitives themselves are not novel project code, but
their composition and every project-controlled parameter remain in scope.
Compression-ratio or speed claims are not security findings unless they create
an availability or resource-exhaustion risk.

## Reproduction commands

From the exact reviewed commit:

```console
uv sync --frozen --extra dev
uv run --frozen python -m unittest discover -s tests -v
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen --with bandit bandit -q -r src -lll
uv run --frozen --with pip-audit pip-audit
uv build
```

The reviewer may use additional static analysis, fuzzing, sanitizers, corpus
generation, or manual proof techniques. Any tool limitations belong in the
report.

## Required report contents

The published report must state:

1. reviewer identity or organization and independence relationship;
2. reviewed 40-character commit and review-bundle SHA-256;
3. dates, methods, tools, scope exclusions, and environmental limitations;
4. each finding's severity, affected formats/versions, reproduction, impact,
   and recommended remediation;
5. the disposition of every finding after fixes or documented acceptance;
6. a clear statement about whether unresolved findings block the reviewed
   candidate from its intended experimental 1.0 use.

After the report and candidate verification are public, copy
`docs/1.0-external-gates.json` outside the working tree and fill its schema-v3
tag, commit, review-bundle digest, candidate-tag, URL, identity, and date fields.
Use that JSON as the complete message of the annotated stable tag; do not commit
a post-review evidence edit to the candidate. The readiness evaluator rejects a
bare `complete: true`, a missing or malformed bundle digest, the wrong candidate
identity, a lightweight tag, malformed or oversized evidence, a tag/version
mismatch, and any difference among the reviewed commit, attested candidate
commit, tag target, workflow SHA, or checked-out source. The exact commands are
in [RELEASES.md](RELEASES.md).

