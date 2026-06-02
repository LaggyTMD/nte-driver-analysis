# Neverness to Everness — Driver Analysis Report (Second Build)

**Status:** Initial publication 2026-06-02. Companion to [`nte_driver_analysis_public.md`](nte_driver_analysis_public.md) ("v1 report").

**Subject:** `PGameProtectDriver_X64.sys`, the kernel anti-cheat driver shipping with Neverness to Everness (NTE) as of late May 2026, replacing the launch-window driver `GameDriverX64.sys` analyzed in the v1 report.

**Scope:** static-only re-verification of CVE-2025-61155 primitives C1–C5 plus C6 (timestamp) and C7 (signing). Runtime check C8 is not re-run; structurally inherited from v1. Methodology and CVE-2025-61155 background are in the v1 report and not repeated. Every C1–C5 verdict from the v1 report still applies to this build; this document records only the delta.

---

## Driver fingerprint

```
Filename:           PGameProtectDriver_X64.sys
Size:               62,032 bytes
SHA256:             9211a3d64fe2729190e25c03ddb1e80c58ee78e6b28a37b433899c50952b4730
MD5:                4dbb2d066bb054bacd61a13fda00defb
SHA1:               8cea675d7d044505e5f621ec7783aad73134af51
TLSH:               T12253AFD2919028E1DD4B8AB0D1E58267F9B47D860F21D3EF1694C5A50F337C2BA3C2B6
ssdeep:             1536:gNEg+yS6/k/At9////dFJoZOD7l73ICczJy:+EgE6/k/At9////bJOw7lLCNy
Build timestamp:    2026-05-26T03:09:39Z
Signed:             yes
Signer (CN):        N2E Entertainment PTE. LTD.
Signer jurisdiction: Singapore (Private Limited, registration 202519342H)
Issuer chain:       DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
Cert serial:        054730182D66625D0860EE25E8827858
Cert validity:      2025-09-02 → 2028-09-01
Leaf cert SHA256 thumbprint:
                    94110e51cd37eb303809f4ed99a18821c1d6bc71b65679a064bb3b3db4b5ab48
Internal version:   8.26.5.25
PDB path string:    D:\jenkins\workspace\PGP_Driver\HDDriver\output\x64_Release\
                    PwrdDriver\app\PwrdDriver.pdb
Driver framework:   KMDF (Windows Driver Framework, via WDFLDR.SYS)
VMProtect:          NO — clean PE, no virtualized sections
PE sections:        .text .rdata .data .pdata PAGE INIT .uo10 .rsrc .reloc
```

Verification commands (read-only, no execution; reproducible by anyone with a copy of the same `.sys`):

```
sha256sum PGameProtectDriver_X64.sys
osslsigncode verify -in PGameProtectDriver_X64.sys
```

---

## Changed

- **Filename:** `GameDriverX64.sys` → `PGameProtectDriver_X64.sys`
- **Internal version:** `8.26.2.9` → `8.26.5.25`
- **Build environment:** developer workstation (`D:\Work\AntiCheat\src\HtDriver2.0\…`) → Jenkins CI (`D:\jenkins\workspace\PGP_Driver\HDDriver\…`)
- **Build date:** 2026-02-09 → 2026-05-26
- **Size:** 67,664 → 62,032 bytes (smaller — some code path was trimmed, not added)
- **Resolver layout:** 4 stack-string resolver sites → 5, with one mega-resolver pulling 10 APIs in one function
- **Anti-debug surface:** added `KdDisableDebugger`, `KdChangeOption`, `PsGetProcessDebugPort` dynamic resolution (v1 didn't)
- **New `_stricmp` whitelist gate** covering two Microsoft profiling-tool executable names — net-new name-rename bypass surface, not in CVE; specific names withheld pending vendor notification
- **C4 path:** `_strnicmp` result is discarded; function returns AL=1. Under the most likely caller convention (BOOLEAN read on AL) this makes the gate fail-open — strictly more permissive than the original CVE bug. Other caller conventions are possible and would change the behavior; we did not enumerate every caller.

---

## Unchanged

- **Signer** — N2E Entertainment PTE. LTD., same cert serial `054730182D66625D0860EE25E8827858`, same SHA256 thumbprint `94110e51…b4b48`; no rotation between Feb and May builds
- **C1 magic value** `0xFA123456` and its 5 IOCTL handler sites in `.uo10`
- **C2 kill primitive** — `ZwOpenProcess` + `ZwTerminateProcess` reachable from the IOCTL dispatcher (specifics omitted per v1 policy)
- **C3 `ObRegisterCallbacks`** dynamically resolved via stack-string + registration wrapper; `ExEnumHandleTable` still genuinely absent
- **C4 prefix-match bug pattern** — same `"CrashCapture.e"` literal, same `_strnicmp` length bug structurally present (return-value flow changed — see §Changed)
- **C5 PEB-walk whitelist** — same three documented DLLs (`QmGUI4.dll`, `QmGUI.dll`, `gameuirender.dll`), same dual 64-bit / Wow64 paths
- **C6 timestamp** — still post-disclosure (now also post-launch and post-v1-publication)
- **C7 cert chain** still absent from May 2025 published Microsoft Vulnerable Driver Blocklist (`10.0.27825.0`)
- **C8 runtime model** — hash-keyed mitigations need the v2 SHA256 added; cert-keyed mitigations already cover both files
- **Driver framework** KMDF, no VMProtect, `.uo10` section, `\SystemRoot\Temp\wlog.txt` log path
- **PDB tail** `PwrdDriver\app\PwrdDriver.pdb` — anchors source to same Perfect World codebase
- **Verdict** — `do-not-install` (unchanged)

End of report.
