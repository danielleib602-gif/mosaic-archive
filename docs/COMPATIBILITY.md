# Compatibility and upgrade policy

Status: frozen for MSC 1.0 as of package v0.11.

## On-disk format

The MSC6 writer format is frozen for the 1.0 release line. Package releases may
improve performance, routing, diagnostics, and security without changing MSC6
decoder semantics or existing mode identifiers.

Current readers restore MSC1 through MSC6. Every committed compatibility fixture
must remain decodable throughout the 1.x package line. An encoder may stop
emitting an ineffective mode, but its decoder remains.

An incompatible on-disk change requires all of the following:

1. a new `MSC<n>` magic and format version;
2. an additive decoder path that leaves MSC1 through MSC6 unchanged;
3. permanent encode/decode fixtures for the new version;
4. format and threat-model documentation before release.

Old readers are not forward-compatible with new format versions. Upgrade the
reader before decoding an archive written with a newer format.

## Package and CLI compatibility

Public CLI options and documented Python APIs receive deprecation warnings for
at least two minor package releases before removal. Removal or a breaking
semantic change requires the next major package version.

Security fixes may reject inputs that older readers accidentally accepted when
those inputs violate existing size, authentication, canonicalization, or
integrity rules. Such tightening is not considered a format break.

Encoder profiles and benchmark output timing are not stable APIs. Machine
readable JSON field removal or incompatible type changes follow the same
deprecation rule as other documented interfaces.

## Upgrade guidance

- Keep at least one independently verified copy of important archives.
- Upgrade readers before relying on a newly introduced format version.
- Verify permanent fixtures and representative private archives before a major
  package upgrade.
- Do not rewrite old archives solely to obtain a newer package version; current
  readers intentionally preserve old decoder support.

The current machine-readable contract is available with:

```console
msc compatibility --json
```
