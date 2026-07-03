# Release binaries and provenance

Mosaic Archive publishes native one-file command-line executables for Linux,
Windows, and macOS. Each version tag builds independently on the matching
GitHub-hosted operating system, runs `msc --version`, and publishes the resulting
executables with a `SHA256SUMS` file.

## Verify a download

First verify the checksum from the release:

```console
sha256sum --check SHA256SUMS
```

Then verify that GitHub's keyless Sigstore signature binds that exact binary to
this repository and release workflow:

```console
gh attestation verify ./msc-linux-x86_64 \
  --repo danielleib602-gif/mosaic-archive
```

Use the downloaded executable's actual filename on Windows or macOS. Verification
requires GitHub CLI 2.49 or newer and network access. GitHub's signed SLSA
provenance records the source repository, commit, workflow, and build environment.

## What “signed” means

Release binaries have cryptographically signed build provenance produced from a
short-lived Sigstore certificate obtained through GitHub Actions OIDC. There is
no long-lived signing key to store or leak.

This is supply-chain provenance, not an operating-system publisher identity.
The Windows executable does not yet carry an Authenticode certificate, and the
macOS executable does not yet carry an Apple Developer ID signature or
notarization. Those require paid publisher identities and protected credentials.
Windows SmartScreen or macOS Gatekeeper may therefore warn before first launch
even after the provenance verifies.

## Maintainer release procedure

1. Ensure the version in `pyproject.toml`, the CLI, and tests matches the intended
   `vX.Y.Z` tag.
2. Wait for all branch checks, including all three binary jobs, to pass.
3. Create and push the version tag.
4. The release workflow rebuilds, smoke-tests, hashes, attests, and publishes the
   assets. It refuses to publish assets for an unverified tag.
5. Download one released binary and run both checksum and attestation
   verification before announcing the release.

Before tagging, run `msc readiness --json`. A 1.0 tag additionally requires
both external gates in `docs/1.0-external-gates.json` to reference reviewable
evidence.
