# Contributing

Mosaic Archive welcomes focused bug reports, benchmark evidence, tests,
documentation, and lossless codec experiments.

## Development setup

Install Python 3.11 or newer and `uv`, then run:

```console
uv sync --extra dev
uv run msc --version
```

Keep experimental format work additive. Existing MSC1-through-MSC6 decoder
fixtures and mode identifiers are compatibility commitments.

## Working agreement

- Start behavior changes with a failing test.
- Preserve exact round trips, parser bounds, authentication-before-publication,
  portable-path validation, and atomic destination replacement.
- Do not weaken decoding limits to improve benchmark numbers.
- Make benchmark claims against committed, reproducible inputs. Report size and
  speed regressions as plainly as improvements.
- Keep mature-tool comparisons explicit about encryption, authentication,
  metadata, and padding differences.
- Do not commit generated archives, build outputs, credentials, or private
  corpora.

## Verification

Before opening a pull request:

```console
uv run python -m unittest discover -s tests -v
uv run ruff check .
uv run mypy src
uv run --with coverage coverage run -m unittest discover -s tests
uv run --with coverage coverage report --fail-under=80
uv run --with bandit==1.9.4 bandit -q -r src -lll
uv run --with pip-audit pip-audit --local
uv build
```

Changes to chunking, solid routing, metadata, or framing must also regenerate
the deterministic corpus benchmark and prove restoration. Speed claims should
use repeated runs and a median; do not select a favorable single CI runner.

## Pull requests

Explain the invariant being preserved, the RED test, implementation tradeoffs,
and exact verification evidence. Format changes must update `docs/FORMAT.md`,
`docs/COMPATIBILITY.md`, fixtures, fuzz seeds, and rollback notes together.

Security vulnerabilities should follow [SECURITY.md](SECURITY.md), not a public
issue.
