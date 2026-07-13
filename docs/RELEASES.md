# Release binaries and provenance

Mosaic Archive publishes native one-file command-line executables for Linux,
Windows, and macOS. Each version tag builds independently on the matching
GitHub-hosted operating system, runs `msc --version`, and publishes the resulting
executables, a deterministic source-review bundle, and a `SHA256SUMS` file.

## Verify a download

Download `SHA256SUMS` and every asset listed in it, then verify the complete
inventory:

```console
sha256sum --check SHA256SUMS
```

Then verify that GitHub's keyless Sigstore signature binds that exact binary to
this repository and release workflow:

```console
gh attestation verify ./msc-linux-x86_64 \
  --repo danielleib602-gif/mosaic-archive \
  --signer-workflow danielleib602-gif/mosaic-archive/.github/workflows/release.yml \
  --source-digest FULL_40_CHARACTER_COMMIT \
  --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
```

Use the downloaded executable's actual filename on Windows or macOS. Verification
requires GitHub CLI 2.49 or newer and network access. GitHub's signed SLSA
provenance records the source repository, commit, workflow, and build environment.
Run the same command for `SHA256SUMS`, which has its own provenance. For a
candidate prerelease, use `refs/heads/main` as `--source-ref`; for a stable
release, use its full `refs/tags/vX.Y.Z` ref.

Verify the source-review bundle's internal manifest from a checkout of the
release commit:

```console
python scripts/prepare_review_bundle.py verify mosaic-review-COMMIT.zip
```

Rebuilding it with `build ... --revision COMMIT` must produce identical bytes.
The bundle's checksum and GitHub attestation bind reviewed source to the same
release record as the executables.

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

Before relying on this procedure, confirm immutable releases are enabled. The
public repository also has active tag rulesets: `candidate-v*` tags cannot be
updated, deleted, or force-moved after creation, while stable `v*` creation,
updates, deletion, and force-moves are restricted to the release authority.
These controls are repository settings and must be recreated explicitly in any
fork.

For a pre-1.0 release, ensure the package version matches the intended `v0.X.Y`
tag, wait for protected-main checks, create the tag, and let the release workflow
build and publish it. The workflow requires all seven repository-verifiable
gates.

A stable `v1.0.0` release uses a two-stage candidate seal so evidence gathered
after review cannot silently change the reviewed source:

1. Freeze the final package version, source, dependency lock, build workflow,
   and documentation on protected `main`. Call that exact commit `C`. Any later
   code, dependency, version, or workflow change creates a new candidate.
2. After confirming protected `main` still points to `C`, manually dispatch
   **Cross-platform release binaries** on the `main` ref with
   `publish_candidate` enabled. Publication is rejected unless `C` is still the
   current protected-main commit both before the build matrix and immediately
   before publication, and all seven automatic gates pass. The job publishes
   `candidate-v1.0.0-COMMIT12` as a prerelease with all three native binaries,
   a deterministic source bundle, checksums, and GitHub provenance. PyInstaller
   and all of its transitive build dependencies are resolved from `uv.lock`;
   any pre-existing candidate tag must already peel to `C`.
3. Have the independent reviewer inspect `C` and its source bundle. Separately
   verify the candidate checksums and attestations. Record durable HTTPS URLs,
   reviewer/verifier identities, dates, the review-bundle SHA-256, the exact
   candidate tag, and the same full 40-character `C` in a copy of
   `docs/1.0-external-gates.json` kept outside the working tree. Fetch the
   remotely created candidate tag and download the exact review bundle first:

   ```console
   git fetch --force --tags origin
   C=$(git rev-parse origin/main)
   test "$(git rev-parse HEAD)" = "$C"
   CANDIDATE_TAG="candidate-v1.0.0-${C:0:12}"
   gh release download "$CANDIDATE_TAG" \
     --pattern "mosaic-review-${C}.zip" --dir ..
   ```
4. Set that copy's `release_tag` to `v1.0.0`, its `release_commit` to `C`, and
   both gate commit fields to `C`. Create an annotated tag whose complete
   message is the schema-v3 JSON:

   ```console
   git fetch --force --tags origin
   C=$(git rev-parse origin/main)
   test "$(git rev-parse HEAD)" = "$C"
   git tag --annotate v1.0.0 "$C" --file ../v1.0.0-evidence.json
   uv run msc readiness --release-tag v1.0.0 --release-commit "$C" \
     --review-bundle "../mosaic-review-${C}.zip" --require-ready --json
   git push origin v1.0.0
   ```

5. The stable-tag preflight peels the annotated tag and fails unless the tag
   name matches the package version and the evidence commit, reviewed commit,
   attested candidate commit, tag target, workflow SHA, and checked-out `HEAD`
   are identical. Lightweight, malformed, oversized, mismatched, or moved tags
   never reach binary construction. It also requires the immutable candidate
   release and exact five-asset inventory, verifies every candidate checksum
   and GitHub attestation against this workflow and protected-main source SHA,
   and byte-checks the candidate review bundle against the reviewed digest. The
   matrix also rebuilds and smoke-tests all three platforms, but those fresh
   binaries are diagnostic: stable publication downloads the immutable
   candidate again, repeats its inventory, checksum, and attestation checks,
   byte-compares the rebuilt source bundle, and promotes the exact verified
   candidate payload bytes. Immediately before creation it rechecks the remote
   annotated-tag object, protected-main commit, and original candidate release
   identity and inventory.
6. The workflow publishes those promoted candidate assets plus the exact
   `RELEASE-EVIDENCE.json` and preserved `CANDIDATE-SHA256SUMS`, writes a new
   stable `SHA256SUMS`, attests the manifest itself, and uses that manifest to
   attest every listed artifact for the stable tag. After creation it requires
   GitHub's normal release record to be immutable, complete, and byte-for-byte
   consistent with the local manifest and API asset digests. The bytes reviewed
   and independently verified are therefore the bytes users download from
   stable. Download the complete inventory and verify its checksums and GitHub
   attestations before announcing the release.

### Human trust boundary

The automated gate binds the candidate tag, source commit, workflow provenance,
artifact digests, and reviewed bundle bytes. It cannot authenticate the humans
named in `reviewer` or `verified_by`, establish their independence, or judge the
linked report. Until reviewer-signed evidence is pinned to a separately verified
identity, the maintainer must verify authorship, independence, and disposition
out of band. A 9/9 machine result proves evidence-to-source binding; by itself it
does not prove that an independent review occurred.

Before tagging a pre-1.0 build, run
`msc readiness --require-automatic --json`. The committed
`docs/1.0-external-gates.json` remains an incomplete template; filling or
committing it alone cannot make the repository report 9/9. Stable evidence must
be carried by the annotated tag that points to the exact reviewed candidate.

The release workflow performs full remote candidate inventory, checksum,
manifest-provenance, artifact-provenance, and evidence checks before starting
the native build matrix, then repeats the source, tag, bundle, and candidate
bindings and promotes the verified candidate bytes immediately before
publication. Branch, pull-request, candidate, and `v0.*` builds require all
seven automatic gates. Any later stable `v*` tag requires all nine gates and the
candidate seal, so a manual dispatch, filled template, fake commit, or direct
lightweight tag cannot publish a stable release.
