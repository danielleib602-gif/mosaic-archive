# v0.39.0 release verification

- Verified: 2026-07-06
- Release: https://github.com/danielleib602-gif/mosaic-archive/releases/tag/v0.39.0
- Source commit: `f99495cfc5be73617da8f929f89c3c044abbce89`
- Release workflow: https://github.com/danielleib602-gif/mosaic-archive/actions/runs/28795946646

The public release contains the following checksum-verified assets:

| Asset | SHA-256 |
|---|---|
| `msc-windows-x86_64.exe` | `aa12bbd6971553beb32a7fc9876bc726b47589137203e7e7a11082b53f7368bd` |
| `msc-linux-x86_64` | `e501cda0a37c40acb7ed249a8d3d0316844dee42ebbebe21f73593aff8b93eae` |
| `msc-darwin-arm64` | `44cac08b99895aa5062afba901b3376ccd2d8191e72c68fba82bb75fb0e795cb` |
| `mosaic-review-f99495cfc5be73617da8f929f89c3c044abbce89.zip` | `2307cb50355e1b942718364780c8cb1af2dd9228d9550d864213f9d79ac7c130` |

Verification performed after downloading the public assets:

1. every asset matched the published `SHA256SUMS`;
2. the Windows binary reported `msc 0.39.0`;
3. the exact-source review bundle verified 138 files, package version 0.39.0,
   source commit `f99495cfc5be73617da8f929f89c3c044abbce89`, and source tree
   `e8c56dbecc0398deafcbcdf6c2193f503a084b8d`;
4. `gh attestation verify` accepted the Windows binary for
   `danielleib602-gif/mosaic-archive`.

This is maintainer-side release verification, not an independent security
review. It does not complete either external MSC 1.0 gate: the release-readiness
policy requires an independent reviewer to approve the exact source commit
before a corresponding attested release can count.
