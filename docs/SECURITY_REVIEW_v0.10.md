# v0.10 internal security review

Date: 2026-06-30

Scope: archive parsing, path handling, temporary output publication, external
comparison commands, password handling, dependency posture, deterministic
mutation testing, and the v0.10 coverage-guided fuzz harness.

This is a maintainer self-review, not the independent audit required for MSC
1.0.

## Methods

- manual review against the project threat model;
- Bandit 1.9.4 over `src`;
- `pip-audit` against the active environment;
- secret-pattern scan over tracked files;
- deterministic malformed-input tests and Atheris coverage-guided targets;
- cross-platform unit, type, lint, coverage, dependency, and build gates.

## Results

No medium- or high-severity Bandit findings and no tracked secret signatures
were found.

Bandit reported seven low-severity items:

- `comparisons.py` invokes discovered `zstd` and `7z` executables with
  argument lists, `shell=False`, a five-minute timeout, and no command-string
  interpolation. This is retained; users still trust locally installed
  comparison tools.
- `corpus.py` and `reliability.py` use `random.Random` only to reproduce public
  benchmark, mutation, and soak inputs. Cryptographic salts and nonces continue
  to use `os.urandom`.
- the reliability harness contains an intentionally public archive password.
  It protects no secret and exists only to exercise authenticated round trips.

## Residual risks and required follow-up

- The archive composition and implementation still require independent review.
- Source-tree traversal detects links and metadata changes but is not fully
  race-resistant against a hostile process mutating the source concurrently.
- Authenticated inputs can still consume CPU and disk up to documented parser
  limits; callers should apply external quotas for untrusted archives.
- Compression ratios leak coarse information despite padding and must not be
  exposed as an interactive attacker-controlled compression oracle.
- Native cryptographic and compression dependencies remain part of the trusted
  computing base and require timely security updates.

The MSC 1.0 independent-audit roadmap gate remains open.
