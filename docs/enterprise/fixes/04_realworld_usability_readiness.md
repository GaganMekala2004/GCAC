# GCAC Real-World Usability Fixes — Production Readiness & Verification Sign-Off

**Document ID**: `GCAC-FIX-04-READY`  
**Automated Gate Status**: All 13 JS regression suites (with host-expected `G3-06 SANDBOX_UNAVAILABLE` live container skip) and all 66 .NET tests passed cleanly after final edits.

---

## 1. Automated Readiness Matrix

| Block | Capability | Verification Method | Status |
|---|---|---|---|
| A | Empty input, submodule & false-positive resistance + cross-repo historical isolation | `realWorldUsability.test.js`, `reScanVerification.test.js`, `findingsStore.test.js` | Verified (Automated) |
| B | External repository selection, multi-root workspace, spaces in path, Windows 8.3 & Trust/Path containment | `realWorldUsability.test.js`, `security.test.js`, `RealWorldUsabilityTests.cs` | Verified (Automated) |
| C | `SCAN-NUGETA-003` SEC-02 reproduction, `GCAC-FINDING-CTX-1.0` contract, Copilot request builder (no `using scan ""`), `.NET` MCP fallback | `realWorldUsability.test.js`, `phase1Security.test.js`, `RealWorldUsabilityTests.cs` | Verified (Automated) |
| D | Multi-project test aggregation, 10 distinct failure categories, baseline vs post-fix reporting, `testStatus` UI crash fix | `realWorldUsability.test.js`, `testRunner.test.js`, `reportParser.test.js` | Verified (Automated) |
| E | Eligibility-enforced `retryStage`, attempt archiving, backoff/limits, reload interruption recovery, `reviseFix` + fresh Stage 4 gate | `realWorldUsability.test.js`, `phase2Security.test.js`, `stateMachine.test.js` | Verified (Automated) |
| G | Minimal CSP-compliant dashboard controls, disabled-retry reasoning & mapping banner | `realWorldUsability.test.js`, `phase1Security.test.js` (`preview-dashboard.js`) | Verified (Automated) |
| Phase 3 Container Live Smoke (`G3-06`) | Real Docker/Podman Linux container test execution | Local workstation check | Not Verified on Host (`SANDBOX_UNAVAILABLE`) |

---

## 2. MANUAL VERIFICATION REQUIRED — USER AND GAGAN

Because automated headless suites cannot drive interactive VS Code desktop dialogs, live GitHub Copilot Chat subscriptions, visual CSS theme rendering, or missing container daemons on this workstation, the following checks must be performed manually by the User / Gagan before production sign-off:

1. **Interactive VS Code Extension Host Session (`F5` in VS Code)**:
   - Launch Extension Development Host (`F5` from GCAC root) and open **GCAC: Open Remediation Dashboard**.
   - Open Developer Tools console in the Webview and confirm zero JS runtime errors (`testStatus` crash eliminated) when opening Test Evidence on failed/unexecuted/passed findings.
2. **External Repository Portability & Multi-Root Switching**:
   - Click **Change** (`btnBrowseRepo`) / **Choose Folder...** in **Local Security Scanners** and select a disposable external `.NET` or Java/Maven repository located outside the GCAC directory (including a folder path containing spaces).
   - Confirm the Target Context header updates to show the external repository path, deterministic `LOCAL-<8HEX>` identity badge, and detected technology.
   - Verify scanning an empty directory or an uninitialized `sample-repos/*` gitlink displays the **No Scannable Inputs** warning banner with `0` findings and does not pull in findings from any previously scanned repo.
   - Open a multi-root VS Code workspace (`File -> Add Folder to Workspace...`) and confirm the **Workspace** dropdown lets you switch active folders cleanly and scans respect Workspace Trust (open a folder in Restricted Mode to verify scan/remediate/Copilot are blocked).
3. **Scan-to-Copilot End-to-End Flow (`SCAN-NUGETA-003` & Mapping Action)**:
   - Test selecting an unmapped finding (lacking `Application_Number`/`Repository`) and clicking **Run with Copilot**: verify GCAC blocks Copilot launch and displays the **Repository / Application Identity Required (SEC-02)** banner with **Map Repository...**.
   - Click **Map Repository...**, bind it to an authorized local repo, then click **Run with Copilot**: confirm VS Code Chat opens prefilled with `@vulnerability-orchestrator /remediate-vulnerability <ID> in repository "<valid-repo>" using scan "<scan-or-csv>"` (never `using scan ""`), and submit the chat prompt interactively with live GitHub Copilot.
4. **Failure Diagnostics, Retry Stage & Review Failure / Revise Fix UX**:
   - Trigger or inspect both a transient stage interruption (e.g. kill/reload VS Code mid-run or simulate timeout) and a genuine post-fix test failure:
     - Confirm failed stage title, failure category badge, command, exit code, count/unknown status, root error, report path, and next-action hint appear in **Test Evidence** & **Failure Recovery**.
     - Confirm **Retry Stage** is enabled for transient/interrupted failures (creating Attempt #2 while preserving `attempts/att-1-.../`), and disabled with an explicit explanation during active execution or genuine `TESTS_FAILED` / `BUILD_FAILED`.
     - Confirm clicking **Review Failure / Revise Fix** synthesizes a revised diff and stops at **Human Approval Gate (Stage 4)** requiring fresh authorization.
5. **Visual Theme Check (Light, Dark & Auto)**:
   - Toggle the header theme selector across Light, Dark, and Auto themes and inspect the Target Context bar, Repository Mapping banner, Scan Coverage banner, Failure Recovery panel, and Diagnostic Strip for contrast and layout alignment.
6. **Live Phase 3 Container Runtime Verification (`G3-06`)**:
   - On a machine with WSL2 + Docker Desktop (Linux container mode) or Podman v4+ and pre-pulled pinned toolchain images matching [`extension/config/approved-toolchain-profiles.json`](../../extension/config/approved-toolchain-profiles.json), re-run `node tests/extension/run-all-tests.js` and verify `G3-06` executes inside the Linux container rather than skipping as `SANDBOX_UNAVAILABLE`.

