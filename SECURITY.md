# Security policy

## Supported versions

Mosaic Archive is experimental pre-1.0 software. Security fixes are applied to
the current development release:

| Version | Supported |
|---|---|
| 0.38.x | Yes |
| Earlier versions | No |

Decoder compatibility for MSC1 through MSC6 is separate from package support:
current releases retain those decoders, but old packages do not receive fixes.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion,
benchmark artifact, or pull request.

Use GitHub's private vulnerability reporting surface for this repository:

`https://github.com/danielleib602-gif/mosaic-archive/security/advisories/new`

If that surface is unavailable, contact the repository owner through their
GitHub profile without including exploit details and request a private channel.
Include affected versions, impact, reproduction conditions, and any proposed
mitigation once a private channel is established.

Expect an acknowledgement within seven days. Fix timing depends on severity and
the compatibility impact. Coordinated disclosure should wait until a patched
release and advisory are ready.

## Scope and expectations

Especially useful reports cover authentication bypass, nonce reuse, unsafe path
restoration, parser resource exhaustion, decompression bombs, destination
publication before verification, compatibility-fixture regressions, and release
provenance failures.

The current threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
Mosaic Archive uses standard cryptographic primitives but has not received an
independent security audit. Do not use it as the sole copy of important data.
