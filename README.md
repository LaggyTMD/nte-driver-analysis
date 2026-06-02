# NTE Driver Analysis (CVE-2025-61155)

> **Status:** v4.1 (2026-04-30) for the launch-window driver; v2 report (2026-06-02) for the post-launch rebuild. Verdict: **do-not-install** on Windows PCs that matter — unchanged across both builds. See [`CHANGELOG.md`](CHANGELOG.md) for revision history.

Neverness to Everness — a major gacha launch from Hotta Studio / Perfect World — ships a Windows kernel driver with every static-checkable flaw of CVE-2025-61155 still present. The launch-window driver `GameDriverX64.sys` is covered in detail in [`nte_driver_analysis_public.md`](nte_driver_analysis_public.md); the post-launch rebuild `PGameProtectDriver_X64.sys` (build 2026-05-26, four weeks after launch) is covered as a delta report in [`nte_driver_v2_analysis_public.md`](nte_driver_v2_analysis_public.md). The same driver class is already weaponized in the wild by ransomware operators (Interlock's "Hotta Killer" tool, the "Reynolds" family) to disable EDR and antivirus software before encrypting victims' files. Both NTE builds were produced after the public CVE advisory and the deep-dive writeup that documented every primitive analyzed here; cosmetic anti-static-analysis changes were added, but the underlying flaws were not fixed in either build.

The driver is not optional on Windows. Direct runtime verification with Process Explorer (elevated) shows it kernel-resident continuously for the lifetime of the NTE launcher process — including while the launcher sits minimized in the system tray after the game window closes (the default UX path). Standard SCM-based driver enumeration misses it because it loads without registering as an SCM-managed service. For a typical player session the abuse window is effectively "while the user is logged in."

Both builds are signed under the same corporate identity (`N2E Entertainment PTE. LTD.`, Singapore) — same cert serial, same SHA256 leaf-cert thumbprint, no rotation between February and May 2026 builds. Verified absent from the May 2025 published Microsoft Vulnerable Driver Blocklist. A future blocklist entry against any prior Hotta-affiliated signer would not block either build; defenders should track the `N2E Entertainment` thumbprint directly, which covers both files with one rule.

**Bottom line:** mobile (iOS / Android) and console builds don't ship the driver and are substantially safer. On Windows the choice is binary — play with the driver loaded for the full launcher session, or don't play; there is no half-measure that lets the game run without the driver loaded.

Full reports: [`nte_driver_analysis_public.md`](nte_driver_analysis_public.md) (v1 driver, full analysis with Methodology, CVSS 3.1 scoring of 7.8 High post-foothold, YARA hints, and Appendix A reproducibility commands) and [`nte_driver_v2_analysis_public.md`](nte_driver_v2_analysis_public.md) (v2 driver, delta report — what changed and what didn't).

## Contents

- `nte_driver_analysis_public.md` — the v1 analysis report (launch-window driver).
- `nte_driver_v2_analysis_public.md` — the v2 delta report (post-launch rebuild).
- `CHANGELOG.md` — revision history.
- `SHA256SUMS` — SHA-256 hashes of both reports.
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

Static analysis of the driver binary on a Linux host (binary never executed there) plus observational runtime verification on a disposable bare-metal Windows 11 host (Secure Boot, VBS, HVCI / Memory Integrity enabled; no user data or saved credentials). Observation on the Windows host is non-invasive — no kernel debugger, no game instrumentation. See the Methodology section of the report for full details.
