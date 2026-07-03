# v0.33 internal security review

Date: 2026-07-03

Scope: MSC1-through-MSC6 and MSR2 decode paths, parser/resource limits,
authentication and output publication ordering, path handling, password input,
dependencies, release automation, fuzz/soak coverage, and public-release
metadata.

This is a maintainer self-review. It reduces the scope and uncertainty of the
independent review required for MSC 1.0, but does not satisfy that gate.

## Methods

- manual data-flow review from public headers through authenticated manifests,
  codec decoding, hash verification, and atomic publication;
- review of every caller-controlled size, count, path, KDF, padding, frame, and
  compressed-stream field;
- Bandit and dependency auditing;
- common secret, credential-file, tracked-PII, and Git-history signature scans;
- permanent MSC1-through-MSC6 compatibility fixtures;
- deterministic 10,000-case mutation testing across 14 parser/decoder targets;
- seeded Atheris coverage-guided fuzzing;
- local 256 MiB streaming round trip;
- isolated wheel installation and encrypted round-trip smoke testing.

## Findings fixed in v0.33

### SR-033-01: inconsistent decode resource budgets

Severity: medium availability risk.

MSR2 accepted caller-defined restored-size and frame-count ceilings, while
MSC1-through-MSC6 exposed only fixed parser limits. A valid but untrusted
archive shared with its password could therefore request substantial disk,
memory, or CPU work without an application-specific budget.

Fix: all public decode and inspect APIs now accept a shared maximum restored
size and frame/block count. The CLI exposes the same controls. Authenticated
manifests are checked before destination creation. Defaults are 1 TiB restored
bytes and 1,000,000 data frames/blocks; callers handling untrusted archives
should select lower limits.

### SR-033-02: legacy MSC1 whole-ciphertext allocation lacked a caller cap

Severity: medium availability risk.

MSC1 is a legacy whole-archive AEAD format. Its decoder verified that the public
ciphertext length matched the file, then read the complete ciphertext into
memory. The structural length check prevented truncation but did not provide an
application budget.

Fix: MSC1 now rejects archives larger than a caller-defined legacy archive
limit before reading ciphertext. The default is 1 GiB and can be deliberately
overridden. Restored size and block count use the shared decode policy.

### SR-033-03: bounded MSR2 metadata decode ended with an unbounded flush

Severity: medium availability risk.

Compressed MSR2 metadata used `decompress(..., expected_size + 1)` but then
called `flush()` without an output bound. Normal zlib streams produced no
meaningful extra output there, but the final unbounded operation weakened the
resource-limit argument for malformed authenticated metadata.

Fix: the decoder no longer flushes after bounded decompression. It requires the
stream to reach EOF with the exact authenticated size and no unconsumed or
unused bytes. A regression test uses a decoder whose `flush()` raises.

### SR-033-04: legacy inspect retained restored bytes unnecessarily

Severity: low availability risk.

MSC1 inspection decoded into `BytesIO`, retaining the restored content even
though only its SHA-256 and mode distribution were needed.

Fix: inspection now decodes into a null writer while retaining full hash and
codec verification.

## Results

No known authentication bypass, nonce-reuse path, traversal publication,
dedup-reference cycle, decoder output-bound bypass, or high-severity dependency
finding remains from this review.

The machine-readable command:

```console
msc readiness --json
```

reports seven of nine MSC 1.0 roadmap gates complete. Independent security
review and the first independently verified attested binary release remain.

## Residual risks and external gates

- Independent review of the current candidate is still required.
- Source traversal detects links and content/metadata changes but is not fully
  race-resistant against a hostile local process replacing files during encode.
- Authenticated archives can consume resources up to the selected caller
  limits. Defaults are interoperability ceilings, not safe multi-tenant quotas.
- Password-derived encryption remains vulnerable to offline guessing when
  users choose weak or reused passwords.
- Padding reduces exact-length leakage but does not eliminate compression-ratio
  or rough-size leakage.
- Python, `cryptography`, zlib, LZMA, PyInstaller, GitHub Actions, and installed
  comparison tools remain in the trusted computing base.
- Windows Authenticode and Apple Developer-ID/notarization are not configured.
- The first tagged release must be built, checksum-verified, and provenance-
  verified after GitHub Actions can run.
