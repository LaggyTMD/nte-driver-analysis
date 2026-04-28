# Neverness to Everness — Pre-Launch Driver Analysis Report

**Status:** Final — published 2026-04-28, one day before public launch (2026-04-29)
**Subject:** the kernel anti-cheat driver `GameDriverX64.sys` shipped with the Neverness to Everness (NTE) preload installer
**Scope:** verification of public CVE-2025-61155 in the newly-shipped NTE driver build (`GameDriverX64.sys`, internal version `8.26.2.9`, dated 2026-02-09).

---

## TL;DR for non-technical readers

Neverness to Everness — a major gacha launch from Hotta Studio / Perfect World — ships `GameDriverX64.sys`, a freshly-built (2026-02-09) Windows kernel driver that **retains every documented vulnerability** of CVE-2025-61155 (October 2025). All five static-checkable vulnerability classes verified present: the same hardcoded "magic" authentication readable from the binary, the same arbitrary-process-termination primitive callable by any unprivileged process, the same prefix-match whitelist bypass, and the same DLL-name-spoofing gate on the file-open path. Cosmetic anti-static-analysis modifications were added; the underlying primitives were not fixed.

The driver is **signed under a brand-new corporate name** (`N2E Entertainment PTE. LTD.`, Singapore, cert valid through 2028) — different from the prior `Fedeen Games Limited` signer used elsewhere in the same install. The new cert is **verified absent** from the May 2025 published Microsoft Vulnerable Driver Blocklist. Ransomware operators (Interlock's "Hotta Killer" tool, January 2026; the "Reynolds" family, February 2026) already weaponize this exact driver class against defensive software on victim machines, and each PC install of NTE adds the same primitive — signed, loadable, and on disk — to the local attack surface.

Findings indicate the BYOVD risk profile documented in CVE-2025-61155 is fully present in the NTE driver. Mitigations available to operators: a WDAC policy blocking `GameDriverX64.sys` by hash, Microsoft Defender ASR's "Block abuse of exploited vulnerable signed drivers" rule, the Microsoft Vulnerable Driver Blocklist (Core Isolation → Memory Integrity), or playing on platforms that don't ship a Windows kernel driver (mobile, console). See the Recommendations section for audience-specific guidance.

---

## Background — what's actually being shipped

### The pattern Hotta has used before

Tower of Fantasy is Hotta Studio's previous live-service game (launched 2022). At that launch it shipped a kernel anti-cheat driver named `KSophon_x64.sys`; that driver was later renamed `GameDriverX64.sys` in subsequent builds. The CVE-2025-61155 advisory was published in October 2025 via the GitHub repository at `pollotherunner/CVE-2025-61155`, with reporters listed in the advisory metadata; **Vespalec subsequently published a detailed reverse-engineering writeup in early February 2026** (`vespalec.com/blog/tower-of-flaws/`) showing that this driver shipped in the install package of every Tower of Fantasy PC install, but was **never actually loaded by the game** during normal operation. From Vespalec's writeup directly:

> "They ship a kernel driver with hardcoded authentication and full BYOVD capabilities, and they don't even load it. It just sits on every player's machine."

The driver was therefore a permanent **dormant attack primitive** on every install: signed by a legitimate code-signing certificate (so Windows would gladly load it on demand), exploitable by anyone, and never used for its stated purpose. By the time the writeup was published, ransomware operators had already noticed.

### The CVE and its weaponization

- **CVE-2025-61155** was published in the National Vulnerability Database on **2025-10-28**. It documents an access-control vulnerability in `GameDriverX64.sys`'s IOCTL handlers, which lets any unprivileged local process terminate arbitrary processes — including security software — by sending crafted IOCTL requests. Authentication relies on a single hardcoded 32-bit value (`0xFA123456`) that any attacker can read directly from the driver binary.
- **Fortinet FortiGuard Labs** documented a tool called **"Hotta Killer"** in January 2026: a DLL named `polers.dll` shipped by the **Interlock ransomware group**, which renames `GameDriverX64.sys` to `UpdateCheckerX64.sys` and uses it to kill Fortinet EDR processes before encryption.
- **Securonix** published their own writeup ("CVE-2025-61155 and Interlock ransomware: A converging threat") confirming active in-the-wild use.
- A second ransomware family, **"Reynolds"**, was disclosed on **2026-02-08** using the same driver family for BYOVD.

### Hotta's response

Our April 2026 install of the *current* Tower of Fantasy PC client confirms the kernel driver has been pulled: no Hotta-, Fedeen-, or anti-cheat-shaped `.sys` exists anywhere in the install tree, the patcher logs reference no `.sys` files, and a full live gameplay capture shows no Hotta/Fedeen-signed kernel module registering as a service. The user-mode side retains documented family signatures (`CrashCapture.exe`, `QmGUI.dll`, signed by `Fedeen Games Limited`); only the kernel driver was removed. Between October 2025 (CVE publication) and February 2026 (the NTE driver build), the same vendor removed the driver from Tower of Fantasy. The NTE build dated 2026-02-09 contains the same vulnerability classes as the original CVE.

---

## Methodology

This analysis is strictly defensive and entirely static. The driver is never executed on the analysis machine. Specifically:

- We obtained the driver from the official NTE preload installer, run inside a sacrificial Windows 11 VMware VM on an isolated network segment, with no user data and no saved credentials.
- We extracted the driver binary inertly from the VM to a Linux analysis box, where it has been read by `pefile`, `lief`, `radare2`, `osslsigncode`, `capa`, and (in a follow-up pass) **Ghidra 12.0.4 in headless mode** — none of which executes the binary. The Linux box never opens a handle to the driver, never issues IOCTLs, never loads the driver. The Ghidra pass was added after a self-audit identified that several findings depended on string searches that could not detect stack-string-constructed API names; Ghidra's decompiler resolved that gap and is the basis for the final §C3 and §C5 verdicts.
- All findings below are reproducible by anyone with a copy of the same `.sys` file (SHA256 `9d89947b7ecaf8821df34fb6209b575b1a56a3257a0b225d7c63885fe1c4b569`); each Appendix A entry lists the exact read-only command that generates it.

The evaluation criteria are the eight checks (C1–C8) defined in the project README, drawn from the public CVE-2025-61155 advisory and the Vespalec writeup. We were able to run C1–C5 on the static binary alone; C6 (timestamp), C7 (signing), and C8 (runtime load behavior) are covered separately below.

---

## What we found — driver inventory

The NTE preload installer drops **eight separate kernel drivers** to disk during installation. Listed in order of relevance:

| Filename | Size | Architecture | Vendor / role |
|---|---|---|---|
| `GameDriverX64.sys` | 67 KB | x86-64 | **Hotta Studio's own driver — the subject of this analysis** |
| `ACE-BASE.sys` | 4.2 MB | x86-64 | Tencent's Anti-Cheat Expert (BASE), WHQL-signed (Microsoft Windows Hardware Compatibility Publisher) |
| `ACE-CORE.sys`, `.sys2`, `.sys3` | 1.2-1.8 MB | x86-64 | Three Tencent ACE CORE variants for different Windows versions |
| `ACE-CORE.sysa`, `.sysa2`, `.sysa3` | 3.7-3.8 MB | **ARM64** | ACE for Windows on ARM — confirms NTE supports ARM PCs |

We observed seven Tencent ACE drivers shipped alongside Hotta's `GameDriverX64.sys`. ACE is a known WHQL-signed commercial anti-cheat product (out of scope of this analysis with its own separate threat profile); the relative roles of ACE and `GameDriverX64.sys` in runtime detection are out of scope for this static analysis.

The eighth driver, `GameDriverX64.sys`, is the subject of this report. Despite the redundancy with the already-comprehensive Tencent ACE stack, `GameDriverX64.sys` is shipped, signed, and loadable on every PC install.

### Driver fingerprint

```
Filename:           GameDriverX64.sys
Size:               67,664 bytes
SHA256:             9d89947b7ecaf8821df34fb6209b575b1a56a3257a0b225d7c63885fe1c4b569
TLSH:               T1A5639ED2569024E6DD5BCAB0D1E5C517E9B0BD4B0F22C7DF1AA0C5A10F633C6AA3C366
Build timestamp:    2026-02-09T07:00:02Z
Signed:             yes
Signer (CN):        N2E Entertainment PTE. LTD.
Signer jurisdiction: Singapore (Private Limited, registration 202519342H)
Issuer chain:       DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
Cert serial:        054730182D66625D0860EE25E8827858
Cert validity:      2025-09-02 → 2028-09-01
Leaf cert SHA256 thumbprint:
                    94110e51cd37eb303809f4ed99a18821c1d6bc71b65679a064bb3b3db4b5ab48
Internal version:   8.26.2.9
PDB path string:    D:\Work\AntiCheat\src\HtDriver2.0\output\x64_Release\
                    PwrdDriver\app\PwrdDriver.pdb
Driver framework:   KMDF (Windows Driver Framework, via WDFLDR.SYS)
VMProtect:          NO — clean PE, no virtualized sections
```

The PDB path includes both the `Ht` driver-family marker and a `Pwrd` (Perfect World) reference, which together suggest continuity with the original codebase. The `2.0` indicates an explicit version progression.

---

## C1 — hardcoded authentication "magic" value

### What the README/CVE says

The original `GameDriverX64.sys` checks every IOCTL request against a hardcoded 32-bit constant `0xFA123456`. If the input buffer's first 4 bytes don't match, the request is rejected; if they do, the IOCTL handler runs. There is no per-session secret, no challenge/response, no signed token. **Anyone who reads the driver binary can extract the magic value and pass authentication.** This is the foundational design flaw that makes the rest of the vulnerabilities exploitable by unprivileged users.

### What we found in the NTE driver

The byte sequence `56 34 12 FA` (the little-endian encoding of `0xFA123456`) appears at file offset `0x6b10`, which in memory is `.data:0x140008510` — i.e., a global variable in the driver's data section.

That global is **read from five separate locations** in the `.uo10` code section, by five distinct IOCTL handlers each performing the same load (raw radare2 cross-reference output in **Appendix A.1**):

```
.uo10:0x14000d655   mov eax, dword [0x140008510]   ; magic check site #1
.uo10:0x14000d703   mov eax, dword [0x140008510]   ; magic check site #2
.uo10:0x14000d889   mov eax, dword [0x140008510]   ; magic check site #3
.uo10:0x14000da00   mov eax, dword [0x140008510]   ; magic check site #4
.uo10:0x14000dac9   mov eax, dword [0x140008510]   ; magic check site #5
```

This is the documented pattern, identical in form: every IOCTL handler does its own front-door magic check before doing the dangerous work. Reading the constant from the binary defeats the check trivially.

### Verdict

**C1 — FAIL.** The vulnerability is fully present. Five IOCTL handlers gated by a single static constant readable from the binary file, identical to the documented `HtAntiCheatDriver` family.

---

## C2 — arbitrary process termination

### What the README/CVE says

The CVE-2025-61155 IOCTL `0x222040` calls `ZwOpenProcess` (the kernel-mode-callable variant) with `GENERIC_ALL` access rights, then `ZwTerminateProcess`. Because `Zw*` calls from kernel context set `PreviousMode = KernelMode`, **the access check that an `Nt*` call would honor is bypassed**. The driver therefore lets any caller terminate any process — including PPL-protected (Protected Process Light) services such as Windows Defender — by passing a target PID through the IOCTL. This is the primitive the Interlock "Hotta Killer" tool uses to disable Fortinet EDR.

### What we found in the NTE driver

A function in the binary calls `ZwOpenProcess` followed by `ZwTerminateProcess` against a caller-supplied process ID. The call uses the `Zw*` variants (which set `PreviousMode = KernelMode` and bypass the access check that an `Nt*` call would honor) and requests broad access rights. The function is reachable from two distinct sites in the `.uo10` IOCTL dispatcher and one path in the main `.text` section. There is no whitelist on the PID parameter, no per-process protection check, and no caller validation; a separate cross-reference confirms the dispatcher resolves caller-supplied PIDs into process handles before invoking this primitive.

This is structurally identical to the primitive documented in CVE-2025-61155 §3 and Vespalec's writeup of IOCTL `0x222040`. Specific calling convention, parameter layout, access-mask value, and offsets are omitted from this report; readers requiring technical detail are referred to the original CVE advisory and the Vespalec writeup.

### Verdict

**C2 — FAIL.** Documented termination primitive present and reachable from the IOCTL dispatcher. Any unprivileged local process that satisfies the C5 access gate can issue an IOCTL with a target PID — including the PID of an antivirus, EDR, or PPL-protected service — and kill it. This is the primary primitive Interlock's "Hotta Killer" tool relies on, fully present in this build.

---

## C3 — process protection callbacks and handle stripping

### What the README/CVE says

The original driver registers `ObRegisterCallbacks` to strip access from handles to "protected" processes (the game) and uses `ExEnumHandleTable` to retroactively strip handles already opened. The combination is a complete BYOVD shielding primitive — a malicious driver could use it to hide ransomware processes from defenders. README C3 looks for both APIs and for a caller-supplied PID flowing into the protection list.

### What we found in the NTE driver

The driver hides every dynamic API resolution behind stack-string construction (the same anti-static-analysis technique seen in §C4). Plain `strings -e l` extraction shows only `ObUnRegisterCallbacks` in static form; `ObRegisterCallbacks` and `ExEnumHandleTable` are absent from any string section. **An initial pass of this report read that absence as evidence of removal and assigned C3 a "PARTIAL" verdict. A follow-up pass with Ghidra contradicted that reading.**

The driver has **four** distinct dynamic-resolver sites that call `MmGetSystemRoutineAddress`. Ghidra's decompilation of each, with the stack-string DWORDs decoded as UTF-16LE, identifies the C3-relevant kernel API resolutions:

| Site (Ghidra fn) | Resolved API | C3 relevance |
|---|---|---|
| `FUN_1400049e0` | **`ObRegisterCallbacks`** | **the C3 documented primitive** — fully present, called via wrapper `FUN_14000237c` |
| `FUN_1400027d0` | **`ObUnRegisterCallbacks`** | C3 unregister path; gated on `DAT_140008718 != 0` so it only runs if the registration succeeded |
| `FUN_140003814` | **`PsSetCreateProcessNotifyRoutine`** | process-creation observation primitive |

Decompilation evidence for `ObRegisterCallbacks` and `ObUnRegisterCallbacks` is in **Appendix A.4**.

So:

- `ObRegisterCallbacks` is **present and active**. Resolved via stack-string in `FUN_1400049e0`, the resolved function pointer flows to `FUN_14000237c` which constructs the `OB_CALLBACK_REGISTRATION` structure and registers; the registration handle is stored in `DAT_140008718`. The static `ObUnRegisterCallbacks` UTF-16 string we observed earlier is the *unregister-on-driver-unload* path in `FUN_1400027d0` — proof that the registration succeeds in normal operation.
- `ExEnumHandleTable` is **not** in any of the four resolver sites and not anywhere else in the binary. The retroactive-handle-stripping primitive appears genuinely removed from this build.
- Driver-internal log-format strings `"InitProtectedObjt failed"` and `"Callb failed,0x%x"` appear in the binary's full string extraction (beyond the head-of-list shown in **Appendix A.2**) and correspond to the failure paths of this exact registration sequence.

### Verdict

**C3 — FAIL.** The active process-protection-callback primitive (`ObRegisterCallbacks`) is fully implemented; the only reason our initial pass missed it was a methodology hole (static string search vs. stack-string construction). The retroactive-handle-stripping primitive (`ExEnumHandleTable`) is genuinely absent. Whether the protected-PID list is populated from IOCTL parameters (the documented vulnerable behavior) or from driver-internal state (the README's "pass" condition) requires further analysis of `FUN_14000237c` — the wrapper that actually constructs the OB_CALLBACK_REGISTRATION array — and is left as future work. The conservative reading until that's done: C3 fails because the BYOVD shielding API is fully wired up and we have no evidence of the access-restriction safeguard the README's pass condition requires.

---

## C4 — whitelist prefix-match bug

### What the README/CVE says

The original driver gates certain IOCTLs against a whitelist of "trusted" process names. The whitelist comparison is implemented as:

```c
strnicmp(callerProcessName, "CrashCapture.e", strlen(callerProcessName))
```

The bug is using `strlen(callerProcessName)` instead of `strlen(literal)` as the length argument. Any process whose name is a *prefix* of the literal — including `"C"`, `"Cr"`, `"CrashC"` — passes the comparison. The whitelist therefore admits hostile callers as long as their name happens to be a short prefix of the trusted name.

### What we found in the NTE driver

Ghidra's decompilation of `FUN_140003ea0` shows the documented C4 vulnerability verbatim. The literal `"CrashCapture.e"` is constructed on the stack (the same anti-static-analysis technique seen elsewhere in this binary), the caller's process name is fetched via `PsGetProcessImageFileName`, and `_strnicmp` is invoked with `strlen(callerName)` as the length argument — the documented prefix-match bug. There is no image-base or signature check on this path. The pattern matches the C4 vulnerability documented in CVE-2025-61155 and Vespalec's writeup; specific stack offsets and call sequences are omitted from this report and can be recovered from the original references for readers requiring that detail.

The `_strnicmp` import is present and live (PE import table line 29); `PsGetProcessImageFileName` is at line 20.

### Verdict

**C4 — FAIL.** The whitelist comparison is unpatched; the documented bypass class from CVE-2025-61155 applies. The function returns true with no signature or integrity check on a successful name match.

---

## C5 — IRP_MJ_CREATE PEB walk for hardcoded DLL names

### What the README/CVE says

The driver's `IRP_MJ_CREATE` handler — the function called when any process tries to open a handle to the driver's device — walks the calling process's PEB (Process Environment Block) and iterates the loaded-modules list. If the caller has loaded any of the hardcoded DLLs `QmGUI4.dll`, `QmGUI.dll`, or `gameuirender.dll`, access is granted. **Anyone can rename a DLL to one of those names and load it into their process to defeat the gate.** There is no signature check on the DLL, no integrity verification — only the filename is consulted.

### What we found in the NTE driver

UTF-16 string extraction reveals all three documented DLL names present verbatim (full UTF-16 inventory in **Appendix A.2**):

```
QmGUI4.dll
QmGUI.dll
gameuirender.dll
```

The PE import table includes `PsGetProcessPeb`, `PsGetProcessWow64Process`, `RtlInitUnicodeString`, and `RtlCompareUnicodeString` — the standard primitives for walking the calling process's loaded-modules list and comparing module names. Ghidra's decompilation confirms that the IRP_MJ_CREATE handler walks the PEB module list and grants access on filename match against the three DLL names above, with no signature check on the matching DLL. A parallel Wow64 path performs the same comparisons against the 32-bit module list; the driver implements both gates. The decompilation pattern matches the C5 PEB-walk vulnerability documented in CVE-2025-61155.

### Verdict

**C5 — FAIL.** Identical bypass surface to documented vulnerability. The driver still gates device-handle access on cosmetic DLL filenames. Any attacker can produce a DLL named `QmGUI.dll` (no signature check, no version check, no hash check), load it via `LoadLibrary`, and then open a handle to the driver. The whitelist DLLs are exactly the same three names from October 2025's CVE.

---

## C6 — build timestamp

| Reference event | Date |
|---|---|
| CVE-2025-61155 published | 2025-10-28 |
| Fortinet "Hotta Killer" report (Interlock weaponization) | 2026-01 |
| Vespalec "Tower of Flaws" deep-dive writeup | 2026-02-05 |
| "Reynolds" ransomware family disclosure | 2026-02-08 |
| **NTE `GameDriverX64.sys` build timestamp** | **2026-02-09** |
| NTE public launch | 2026-04-29 |

The NTE driver was built **the day after** the Reynolds ransomware disclosure and **four days after** Vespalec's deep-dive writeup that documented every primitive analyzed in this report. The build is unambiguously **post-disclosure**: the vulnerabilities were publicly documented before this binary was produced.

---

## C7 — signing chain

### Comparison

| Attribute | Original (CVE-2025-61155 era) | Current Tower of Fantasy install (April 2026) | NTE preload (this report) |
|---|---|---|---|
| Signer name | not directly observed in this analysis (see Vespalec writeup for original-era detail) | Driver removed entirely | **N2E Entertainment PTE. LTD.** |
| Jurisdiction | not directly observed | n/a | **Singapore** |
| Issuer | not directly observed (DigiCert chain consistent with related Hotta-affiliated builds) | n/a | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 |
| Certificate type | not directly observed | n/a | EV Code Signing |
| Validity | n/a | n/a | 2025-09-02 → 2028-09-01 |
| Leaf cert SHA256 thumbprint | not directly observed | n/a | `94110e51cd37eb303809f4ed99a18821c1d6bc71b65679a064bb3b3db4b5ab48` (derivation in **Appendix A.3**) |
| WHQL attestation | not directly observed | n/a | not WHQL-signed (relies on EV cert chain) |

### Why this matters

Microsoft's **Vulnerable Driver Blocklist** (auto-enforced on Windows 11 with HVCI) can deny by hash or by certificate. We verified the current published policy (`10.0.27825.0`, 2025-05-23) contains no entry for the NTE driver hash, the `N2E Entertainment` cert thumbprint or serial, the Interlock-renamed SHA1, or any prior Hotta/Fedeen identifier — the published version pre-dates CVE-2025-61155, so this is mechanically expected. The cert was issued 2025-09-02 — eight weeks before CVE-2025-61155 was published — registered as Singapore Private Limited 202519342H. The PDB path (`Pwrd` / `HtDriver2.0`) and code surface match the documented family while the cert chain differs from prior Hotta-affiliated builds. Whatever the reason for the cert rotation, it has the practical effect that a future blocklist entry against the prior signer would not block this driver. Defenders should add the new thumbprint to detection feeds independently.

### Verdict

**C7 — partially answered.** Signing chain is current, valid, not WHQL-attested. The new corporate identity introduces a defender concern independent of intent: a future blocklist entry against any prior Hotta-affiliated signer would not block a driver signed under `N2E Entertainment PTE. LTD.`. Defenders should add the new thumbprint to detection feeds independently of any future blocklist updates.

---

## C8 — runtime load behavior

We performed a Phase 1 capture during gameplay of the related title (Tower of Fantasy) on the same hardware/snapshot, comparing service state before, during, and after gameplay. The diff showed **no Hotta-named, Fedeen-named, or AC-shaped kernel service** loaded at any point. In our test, no anti-cheat driver was dropped to disk by the ToF installer in the first place — extending Vespalec's February 2026 observation (driver shipped but never loaded) to a stronger April 2026 finding: as of our test date, the driver is no longer shipped at all in current Tower of Fantasy.

Because we did not run NTE through full gameplay (NTE has not yet launched), we cannot directly attest to NTE's runtime behavior. However:

- ToF historically followed the "drop-but-don't-load" pattern (per Vespalec, Feb 2026).
- ToF currently doesn't ship the driver at all (our April 2026 ToF install test).
- NTE ships the driver again with cosmetic anti-static-analysis changes.
- Tencent ACE handles the actual cheat enforcement on NTE (seven separate ACE drivers, including ARM64 variants).

The most likely scenario is that NTE inherits the same dormant-driver behavior: **driver on disk for some legacy/telemetry purpose, never actually loaded by the game, but signed and ready for any local attacker to load on demand**. This is the worst-of-both-worlds posture Vespalec described: the user gets none of the protection (the driver isn't doing anti-cheat work) but absorbs all of the risk (the file is signed, loadable, and exploitable).

We will revisit C8 once the launch occurs and the driver's runtime behavior can be observed directly.

### Verdict

**C8 — pending observation.** Strong prior likelihood of dropped-but-not-loaded based on the prior pattern with ToF. Either way, the file's mere presence on disk is itself the threat for a BYOVD primitive.

---

## Summary verdict

Per the README's Phase 3 verdict logic:

```
identity == SIMILAR (HtAntiCheatDriver family, version 2.0; PDB path "HtDriver2.0")
  C1 fails ✓
  C2 fails ✓
  C3 fails ✓ (ObRegisterCallbacks present via dynamic stack-string resolution;
              ExEnumHandleTable genuinely absent)
  C4 fails ✓
  C5 fails ✓
  C6 timestamp post-disclosure (2026-02-09)
  C7 cert chain rotated to N2E Entertainment (defenders must track the new thumbprint independently of any prior Hotta-affiliated identifiers)
  C8 pending; prior likely

CVSS 3.1 (C1+C5+C2 exploit chain), post-foothold impact:
  CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 High
    AV:L  local code execution on the target machine required
    AC:L  exploit is reliable; primitives documented in CVE-2025-61155
    PR:L  any unprivileged user-mode process; no admin needed once the
          C5 DLL-name whitelist is satisfied (trivially via rename)
    UI:N  no user interaction
    S:U   kernel-driver scope; does not pivot beyond local system
    C:H   disabling EDR/AV via the kill primitive enables further compromise
    I:H   arbitrary process termination including security tools
    A:H   kill primitive against any local process including PPL services

  This score reflects the post-foothold impact of the BYOVD primitive. It
  does not represent risk from the act of installing the game in isolation;
  an attacker requires prior unprivileged code execution to leverage the
  driver. The risk model is "compromise enabler", not "compromise vector".

→ verdict = "do-not-install"
reason = "Modified HtAntiCheatDriver-family kernel driver with all five static-checkable
          CVE-2025-61155 primitives still present, signed under a new corporate vehicle
          (N2E Entertainment PTE. LTD.) that is verified absent from the May 2025
          published Microsoft Vulnerable Driver Blocklist (version 10.0.27825.0).
          Anti-static-analysis cosmetic changes (stack-string API names, dynamic
          MmGetSystemRoutineAddress resolution) do not address the underlying primitives."
```

---

## Why this matters at scale

A successful attacker who has obtained unprivileged code execution on the machine — via a malicious browser extension, a phishing macro, or any commodity-malware path — gains a kernel-side path to disable EDR/AV and escalate. NTE itself is not malware; the impact is that its install adds a known-vulnerable kernel primitive to the host's local attack surface for any subsequent attacker to weaponize.

---

## What we cannot determine from this analysis

We cannot establish whether the rebuild was deliberate vulnerability-retention or negligence; whether `N2E Entertainment PTE. LTD.` is a Hotta subsidiary, contractor, or unrelated licensee; the full IOCTL code table (the documented codes are not present as literal byte patterns and may be runtime-constructed); or whether the NTE driver behaves identically to the CVE-era predecessor at runtime (in-VM dynamic tracing was out of scope). Whether Microsoft adds the cert to the Vulnerable Driver Blocklist in a future update is also unknown.

We also could not obtain the published CVE-era reference sample for byte-identical comparison: MalwareBazaar (by SHA1 / imphash / TLSH / multiple tag and signer searches), Wayback Machine, archive.org, and direct fetches of the major writeups (Vespalec, Fortinet, Securonix) all returned no driver binary. The Fortinet IOC table publishes only a SHA1 for the Interlock-renamed `UpdateCheckerX64.sys` variant, and that SHA1 is not in MalwareBazaar. The remaining paths are direct researcher contact (Vespalec, pollotherunner), Hybrid Analysis, or paid TIP access — none pursued here. This absence itself reflects a **disclosure-versus-availability gap**: CVE-2025-61155 has been public since October 2025 with active in-the-wild exploitation, but the sample binary is not in any open-access database, leaving defenders to block by hashes published in writeups, without independent access to verify newer variants like the one shipping in NTE.

We analyzed the **preload** binary obtained prior to retail launch. The launch-day binary on retail servers may differ; findings in this report apply to the preload version specifically.

None of these limitations affect the core verdict — C1, C2, C3, C4, and C5 are confirmed independently from the disassembly of the NTE driver, the driver is signed and loadable, and that is enough to mark `do-not-install`.

---

## Recommendations

### For individual players

- **Do not install NTE on any PC that handles anything that matters** — work data, saved credentials, SSO sessions, password managers, banking sessions, SSH keys, cryptocurrency wallets, source code with proprietary content, etc.
- **iOS / Android / console** are out of scope of this report and have substantially lower threat profiles. If you want to play NTE, prefer those.
- **If you must play on PC, use a dedicated isolated machine** with no saved credentials, no SSO, no work data, and HVCI / Memory Integrity enabled. Note that this only mitigates *some* of the risk: the driver is signed and loadable, so even a hardened machine retains the BYOVD primitive on disk.
- **If you've already installed NTE**, the immediate mitigation is to ensure Microsoft's Vulnerable Driver Blocklist is enabled (Windows Settings → Privacy & Security → Windows Security → Device Security → Core Isolation → "Microsoft Vulnerable Driver Blocklist") and to consider adding a custom WDAC policy that blocks `GameDriverX64.sys` by hash. Microsoft Defender ASR's "Block abuse of exploited vulnerable signed drivers" rule is a useful additional layer.

### For security teams / EDR vendors

- Add the SHA256 `9d89947b7ecaf8821df34fb6209b575b1a56a3257a0b225d7c63885fe1c4b569` and the cert thumbprint `94110e51cd37eb303809f4ed99a18821c1d6bc71b65679a064bb3b3db4b5ab48` to detection feeds.
- The driver writes a log to `C:\Windows\Temp\wlog.txt` when loaded — useful detection telemetry for whether the file has actually been used.
- The five IOCTL handlers all front-load a check against `0xFA123456` at the same offset relative to the input buffer. YARA rules built around this constant (the byte sequence `56 34 12 FA` followed by short proximity to `_strnicmp` and `ZwOpenProcess` calls) will catch this driver and any future variant that retains the magic.
- As of the **May 2025 published Microsoft Vulnerable Driver Blocklist** (`10.0.27825.0`), neither this cert nor any Hotta-affiliated identifier is present. Consider pushing for inclusion via the standard Microsoft blocklist submission path (`https://www.microsoft.com/wdsi/`).

---

## Reproducibility

Every evidence excerpt below is generated by a read-only command stated alongside it. A reader with a copy of the same `.sys` (SHA256 `9d89947b7ecaf8821df34fb6209b575b1a56a3257a0b225d7c63885fe1c4b569`) can reproduce each Appendix A entry directly.

Tools used (all read-only, none executes the driver): `pefile`, `lief`, `capstone`, `radare2`, `osslsigncode`, `openssl`, `flare-capa`, `flare-floss`, `python-tlsh`, `ssdeep`, `pev`, `strings`, and **Ghidra 12.0.4 in headless mode** for the §C3 / §C4 / §C5 decompilations.

---

## References

- **CVE-2025-61155 — official advisory:** https://nvd.nist.gov/vuln/detail/CVE-2025-61155
- **Vespalec, "Tower of Flaws" reverse-engineering writeup (2026-02-05):** https://vespalec.com/blog/tower-of-flaws/
- **pollotherunner, CVE-2025-61155 GitHub repository (advisory + PoC):** https://github.com/pollotherunner/CVE-2025-61155
- **FortiGuard Labs, "Interlock Ransomware: New Techniques, Same Old Tricks" (2026-01):** https://www.fortinet.com/blog/threat-research/interlock-ransomware-new-techniques-same-old-tricks
- **Hacker News discussion, "I reversed Tower of Fantasy's anti-cheat driver: a BYOVD toolkit never loaded":** https://news.ycombinator.com/item?id=46908671
- **Securonix, "CVE-2025-61155 and Interlock ransomware: A converging threat":** https://connect.securonix.com/threat-research-intelligence-62/cve-2025-61155-and-interlock-ransomware-a-converging-threat-198
- **Microsoft Vulnerable Driver Blocklist documentation:** https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- **LOLDrivers project:** https://www.loldrivers.io/

## Appendix A — Tool output excerpts

Each subsection below is the raw output of the analysis command stated, run against `GameDriverX64.sys` (SHA256 `9d89947b...c4b569`). All commands are read-only; no driver execution occurred. A reader with a copy of the same `.sys` file can reproduce each excerpt with the listed command.

### A.1 — `radare2`: magic value cross-references (§C1 evidence)

Command: `r2 -A -c 'axt 0x140008510' GameDriverX64.sys`

```
(nofunc) 0x14000d655 [DATA] mov eax, dword [0x140008510]
(nofunc) 0x14000d703 [DATA] mov eax, dword [0x140008510]
(nofunc) 0x14000d889 [DATA] mov eax, dword [0x140008510]
(nofunc) 0x14000da00 [DATA] mov eax, dword [0x140008510]
(nofunc) 0x14000dac9 [DATA] mov eax, dword [0x140008510]
```

Five distinct sites in the `.uo10` section read the magic value at `.data:0x140008510` (the byte sequence `56 34 12 FA` = little-endian `0xFA123456`). All five sites belong to the IOCTL dispatcher function in `.uo10`, gating each handler on a single static constant readable from the binary.

### A.2 — `strings -e l`: UTF-16 inventory (§C5 whitelist DLLs and driver metadata)

Command: `strings -e l -n 4 GameDriverX64.sys | head -30`

```
\SystemRoot\Temp\wlog.txt
ObUnRegisterCallbacks
QmGUI4.dll
QmGUI.dll
gameuirender.dll
\SystemRoot\system32\
%s%wZ
KmdfLibrary
VS_VERSION_INFO
StringFileInfo
040904E4
CompanyName
GameDriver
FileDescription
GameDriverX64
FileVersion
8.26.2.9
OriginalFilename
GameDriverX64.sys
ProductName
GameDriverX64
ProductVersion
8.26.2.9
VarFileInfo
Translation
<<<Obsolete>>
SubC
SubC
```

The three documented C5 whitelist DLL names appear verbatim. The other entries confirm metadata used in the driver fingerprint (file/product version `8.26.2.9`, original filename `GameDriverX64.sys`, KMDF framework, log path `\SystemRoot\Temp\wlog.txt`).

### A.3 — `osslsigncode` + `openssl`: cert chain extraction (§C7 thumbprint derivation)

Command: `osslsigncode verify -in GameDriverX64.sys`

```
Subject : /jurisdictionC=SG/businessCategory=Private Organization
          /serialNumber=202519342H/C=SG/L=Singapore
          /O=N2E Entertainment PTE. LTD./CN=N2E Entertainment PTE. LTD.
Issuer  : /C=US/O=DigiCert, Inc.
          /CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
Serial  : 054730182D66625D0860EE25E8827858

Hash Algorithm: sha256
Timestamp Issuer: /C=US/O=DigiCert, Inc.
                  /CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
```

Leaf-cert SHA256 thumbprint derivation:

```
$ osslsigncode extract-signature -in GameDriverX64.sys -out /tmp/sig.bin
$ openssl pkcs7 -inform DER -in /tmp/sig.bin -print_certs > /tmp/certs.pem
$ python3 -c '...extract last PEM block, pipe to openssl x509 -fingerprint -sha256...'

cert chain depth: 3
leaf cert subject: jurisdictionC = SG, businessCategory = Private Organization,
                   serialNumber = 202519342H, C = SG, L = Singapore,
                   O = N2E Entertainment PTE. LTD., CN = N2E Entertainment PTE. LTD.
sha256 Fingerprint=94:11:0E:51:CD:37:EB:30:38:09:F4:ED:99:A1:88:21:
                   C1:D6:BC:71:B6:56:79:A0:64:BB:3B:3D:B4:B5:AB:48
```

Stripping the colons gives the leaf-cert thumbprint cited throughout §C7 and the recommendations:
`94110e51cd37eb303809f4ed99a18821c1d6bc71b65679a064bb3b3db4b5ab48`.

### A.4 — Ghidra: dynamic kernel-API resolutions (§C3 FAIL evidence)

Command (Ghidra 12.0.4, headless):

```bash
analyzeHeadless /tmp/ghidra_proj NTE \
  -import GameDriverX64.sys \
  -postScript ghidra_analyze.py \
  -scriptPath ./scripts -deleteProject
```

The driver has four dynamic-resolver functions, each calling `MmGetSystemRoutineAddress` against a UTF-16 API name buffer. The buffers are **constructed on the stack 4 bytes at a time** — invisible to plain `strings`. Decoding each DWORD as UTF-16LE and concatenating in stack-offset order yields the C3-relevant resolutions:

**`FUN_1400049e0`** (the `ObRegisterCallbacks` resolver — drives the §C3 FAIL verdict):

```c
// Stack-string DWORDs decode to "ObRegisterCallbacks":
local_38 = 0x62004f;  // "Ob"
local_34 = 0x650052;  // "Re"
local_30 = 0x690067;  // "gi"
local_2c = 0x740073;  // "st"
local_28 = 0x720065;  // "er"
local_24 = 0x610043;  // "Ca"
local_20 = 0x6c006c;  // "ll"
local_1c = 0x610062;  // "ba"
local_18 = 0x6b0063;  // "ck"
local_14 = 0x73;      // "s"

RtlInitUnicodeString(&local_48, ...);
puVar1 = MmGetSystemRoutineAddress(&local_48);
if (puVar1 != NULL) {
    return FUN_14000237c(puVar1, ...);   // wrapper builds OB_CALLBACK_REGISTRATION
}
```

**`FUN_1400027d0`** (the symmetric `ObUnRegisterCallbacks` cleanup; statically named — note the literal here, no stack-string trick on the unregister path):

```c
RtlInitUnicodeString(&local_18, L"ObUnRegisterCallbacks");
lVar1 = MmGetSystemRoutineAddress(&local_18);
if ((lVar1 != 0) && (DAT_140008718 != 0)) {        // only if registration succeeded
    (*(code *)PTR__guard_dispatch_icall_140006208)();   // call it via CFG-protected dispatch
}
```

`ExEnumHandleTable` does not appear in any of the four resolution sites and is not present anywhere else in the binary (verified by `strings -e l` + `strings -a` + Ghidra string analysis); the retroactive-handle-stripping primitive is genuinely absent from this build.

End of report.
