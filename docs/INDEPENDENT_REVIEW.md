# Independent review brief

This document defines the handoff for the independent security review required
before Mosaic Archive 1.0. A maintainer self-review does not satisfy this gate.
The reviewer must be able to identify the exact source commit, reproduce the
submitted source bundle, publish a report, and remain free to report unresolved
findings.

## Candidate identity

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

After the report is public, update `docs/1.0-external-gates.json` with its HTTPS
URL, reviewer, exact commit, and completion date. The readiness evaluator
rejects a bare `complete: true`, malformed evidence, and an attested release
whose source commit differs from the independently reviewed commit.

