# Changelog — NTE Driver Analysis

Revision history for `nte_driver_analysis_public.md` (entries v1–v4.1) and `nte_driver_v2_analysis_public.md` (v2-report entry). Static-analysis primitives (§C1–§C7) have been stable since v1; revisions concentrate in §C8 (runtime behavior) and the privilege model.

## v2 report — 2026-06-02 (`nte_driver_v2_analysis_public.md`)

Initial publication of the delta report for `PGameProtectDriver_X64.sys` (SHA256 `9211a3d6…b4730`, build 2026-05-26), the post-launch rebuild that replaces `GameDriverX64.sys` four weeks after NTE launch. Static-only re-verification of CVE-2025-61155 primitives C1–C5 plus C6 (timestamp) and C7 (signing); C8 not re-tested, structurally inherited from v1. Findings:

- **C1–C5 verdicts unchanged from v1 — all five primitives still present.** Same hardcoded magic `0xFA123456`, same `ZwOpenProcess`/`ZwTerminateProcess` kill primitive, same `ObRegisterCallbacks` dynamically resolved via stack-string, same three C5 whitelist DLLs, same `_strnicmp` C4 bug pattern.
- **C7 cert unchanged.** Same `N2E Entertainment PTE. LTD.` signer, same serial, same SHA256 thumbprint — no rotation between February and May 2026 builds. Hash-keyed mitigations need the v2 SHA256 added; cert-keyed mitigations already cover both files.
- **Surface metadata moved.** Renamed `GameDriverX64.sys` → `PGameProtectDriver_X64.sys`, version `8.26.2.9` → `8.26.5.25`, build env developer workstation → Jenkins CI (PDB `D:\Work\AntiCheat\src\HtDriver2.0\…` → `D:\jenkins\workspace\PGP_Driver\HDDriver\…`), size 67,664 → 62,032 bytes.
- **C4 path altered, strictly more permissive.** The documented prefix-bug pattern (stack-string `"CrashCapture.e"` + `_strnicmp` with caller-name length) is still in the binary, but the function's return-value flow now most plausibly makes the gate fail-open under idiomatic BOOLEAN-read calling conventions.
- **New name-only whitelist surface added** covering two Microsoft profiling-tool executables via `_stricmp` — net-new bypass primitives not in CVE; specific filenames withheld in the v2 report pending vendor notification.
- **Anti-debug surface expanded.** `KdDisableDebugger`, `KdChangeOption`, `PsGetProcessDebugPort` now dynamically resolved; v1 did not.
- **Resolver footprint broader.** 4 stack-string resolver sites → 5, with one mega-resolver pulling 10 APIs in a single function. Total `MmGetSystemRoutineAddress` call sites moved from 4 to 13.

Overall verdict for the v2 build: **do-not-install** (unchanged from v1). README updated to point at both reports; `SHA256SUMS` updated to cover both reports; signature regenerated under the same LaggyTMD ed25519 key.

## v4.1 — 2026-04-30 (methodology clarification)

The Methodology section of `nte_driver_analysis_public.md` and the Scope section of the README were clarified to honestly describe the §C8 runtime-verification testbed: a disposable bare-metal Windows 11 host (Secure Boot, VBS, HVCI / Memory Integrity enabled; no user data or saved credentials), distinct from the Linux static-analysis host. The previous wording carried "strictly defensive and entirely static" from v1, which was true for §C1–§C7 but stale once v2/v3/v4 added runtime evidence. No findings change.

## v4 — 2026-04-30

Two runtime findings reverse v3's understanding of the deployment, both verified with Process Explorer (Sysinternals) running elevated across a full Launch → DLL-load → Main Menu → In Game session:

**1. Residency is continuous, not transient.** `GameDriverX64.sys` is loaded by `System` / PID 4 immediately on launcher start and remains kernel-resident continuously until the launcher process terminates — not the transient single-load pattern v3's SCM-based enumeration suggested. Closing only the game window does not unload the driver: the launcher minimizes to the system tray and the driver stays loaded with it. With the launcher's "close to tray" setting enabled (the default UX path), the launcher process effectively persists across game-window close and re-open, leaving the driver kernel-resident indefinitely. Explicit launcher quit triggers a 30–45 second delay before the driver unloads.

**2. ACE is not kernel-resident at runtime.** Despite seven Tencent ACE `.sys` files shipping on disk (including ARM64 variants), no ACE driver appears in the live kernel module list during gameplay. Only `GameDriverX64.sys` is kernel-resident at runtime; ACE's user-mode `ACE-Base64.dll` injection into `HTGame.exe` handles the user-mode anti-cheat layer. The v3 hedge that ACE was "plausibly the primary cheat-enforcement layer" and that `GameDriverX64.sys`'s runtime role was unestablished is tightened: at runtime `GameDriverX64.sys` is the lone kernel-mode anti-cheat component actually loaded.

The v3 "unresolved blindspot" caveat — citing [`winsiderss/systeminformer` #2729](https://github.com/winsiderss/systeminformer/issues/2729) to claim live-kernel-module-list verification was blocked by Tencent ACE — is removed. That issue is specific to System Informer; Process Explorer is a separate Sysinternals tool and runs cleanly throughout gameplay. The blindspot is resolved, with the opposite conclusion to the one v3's SCM-only evidence pointed toward.

§"Privilege required to abuse the driver" updated: the "brief in-kernel window" framing is replaced with continuous-residency-for-launcher-session. §"What we cannot determine" narrowed: `GameDriverX64.sys` is now established as the kernel-mode anti-cheat (the only kernel-mode anti-cheat component loaded); what remains unestablished is the specific runtime work it performs. TL;DR rewritten in plain language for non-technical readers and surfacing the residency finding. Editorial pass throughout for redundancy: duplicate post-disclosure framings collapsed in §"Hotta's response" and §C6, the v2 retail-binary "Update" footnote folded into §C8, ACE-related prose in §"What we found — driver inventory" deferred to §C8, and the §C7 verdict tightened. The C8 FAIL verdict and overall **do-not-install** conclusion stand; the runtime threat model is materially worse than v3 stated. §C1–§C7 verdicts unchanged.

## v3 — 2026-04-29

Added §C8 runtime residency observation and System Informer caveat; added "Privilege required to abuse the driver" subsection clarifying load vs. use privilege requirements (admin to load, standard user to abuse during the brief load window). No changes to §C1–§C7 verdicts or the overall do-not-install verdict.

> **Superseded by v4:** the v3 transient-load reading and the System Informer blindspot caveat are both reversed in v4 based on direct Process Explorer verification.

## v2 — 2026-04-29

§C8 elevated from "pending observation" to FAIL based on retail-binary testing (SHA256 byte-identical to preload; WDAC deny-by-hash test confirms launcher requires successful kernel-mode load). TL;DR, §C6, §Summary, §Recommendations, and §"What we cannot determine" updated accordingly. Static-analysis findings §C1–§C7 unchanged.

## v1 — 2026-04-28

Initial publication. NTE driver pre-launch analysis verifying CVE-2025-61155 against `GameDriverX64.sys` (SHA256 `9d89947b...c4b569`, build 2026-02-09) extracted from the NTE preload installer. Static-analysis findings §C1–§C7 reported; §C8 deferred pending retail-binary access. Verdict: do-not-install.
