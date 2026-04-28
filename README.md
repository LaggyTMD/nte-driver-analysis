# NTE Driver Pre-Launch Analysis (CVE-2025-61155)

Static analysis of `GameDriverX64.sys` (internal version `8.26.2.9`, dated 2026-02-09) shipped with the Neverness to Everness preload installer. The report verifies that the driver retains every documented vulnerability class of CVE-2025-61155.

Full report: [`nte_driver_analysis_public.md`](nte_driver_analysis_public.md).

## Contents

- `nte_driver_analysis_public.md` — the analysis report.
- `SHA256SUMS` — SHA-256 hash of the report.
- `SHA256SUMS.asc` — detached GPG signature over `SHA256SUMS`.
- `LaggyTMD-public.asc` — ASCII-armored public key.

## Verification

```
gpg --import LaggyTMD-public.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

All three must succeed. Commits in this repository are signed by the same key.

## Signing key

```
LaggyTMD
ed25519
CD78 0038 9628 CF6A 4F74  0D9F 759A 9507 61BC 0494
```

The key was generated specifically for this publication and has no prior history. The fingerprint above is anchored in the initial announcement post; any future republication signed under a different fingerprint is not authoritative.

## Scope

The analysis is strictly static and defensive. The driver was never executed on the analysis host. See the Methodology section of the report for full details.
