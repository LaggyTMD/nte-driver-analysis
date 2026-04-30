# NTE Driver Analysis (CVE-2025-61155)

> **Status:** v4 (2026-04-30). Verdict: **do-not-install** on Windows PCs that matter. See [`CHANGELOG.md`](CHANGELOG.md) for revision history.

Neverness to Everness — a major gacha launch from Hotta Studio / Perfect World — ships a Windows kernel driver, `GameDriverX64.sys`, with every static-checkable flaw of CVE-2025-61155 still present. The same driver class is already weaponized in the wild by ransomware operators (Interlock's "Hotta Killer" tool, the "Reynolds" family) to disable EDR and antivirus software before encrypting victims' files. The NTE build was produced four days after the public deep-dive writeup that documented every primitive analyzed here; cosmetic anti-static-analysis changes were added, but the underlying flaws were not fixed.

The driver is not optional on Windows. Direct runtime verification with Process Explorer (elevated) shows it kernel-resident continuously for the lifetime of the NTE launcher process — including while the launcher sits minimized in the system tray after the game window closes (the default UX path). Standard SCM-based driver enumeration misses it because it loads without registering as an SCM-managed service. For a typical player session the abuse window is effectively "while the user is logged in."

The driver is signed under a brand-new corporate identity (`N2E Entertainment PTE. LTD.`, Singapore), verified absent from the May 2025 published Microsoft Vulnerable Driver Blocklist. A future blocklist entry against any prior Hotta-affiliated signer would not block this driver; defenders should track the new thumbprint directly.

**Bottom line:** mobile (iOS / Android) and console builds don't ship the driver and are substantially safer. On Windows the choice is binary — play with the driver loaded for the full launcher session, or don't play; there is no half-measure that lets the game run without the driver loaded.

Full report: [`nte_driver_analysis_public.md`](nte_driver_analysis_public.md). Defender guidance, CVSS 3.1 scoring (7.8 High, post-foothold), YARA hints, and full reproducibility commands in the report's Recommendations and Appendix A sections.

## Contents

- `nte_driver_analysis_public.md` — the analysis report.
- `CHANGELOG.md` — revision history (v1–v4).
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

The analysis combines static analysis of the driver binary (which is never executed on the analysis host) with observational runtime verification of an unmodified live install in a sacrificial Windows VM. See the Methodology section of the report for full details.
