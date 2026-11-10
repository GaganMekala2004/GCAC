# Phase 1 — Automated & Manual Verification Test Results

**Document ID:** `GCAC-PH1-TESTS`  
**Phase:** Phase 1 — P0 Containment and Core Integrity Fixes (`Gate G1`)  
**Verification Principle:** Zero fabricated results; all counts, timings, and outputs reported below were observed directly from commands executed after the final source and test edits.

---

## 1. Automated Verification Summary

| Check Suite | Exact Command Executed | Result | Observed Counts & Timing | Notes / Honest Disclosures |
| :--- | :--- | :---: | :--- | :--- |
| **JavaScript Syntax Validation** | `Get-ChildItem -Path extension,scripts,tests\extension -Filter *.js -Recurse \| ForEach-Object { node --check $_.FullName ... }` | **PASS** | `0` syntax errors across all `.js` files in `extension/`, `scripts/`, `tests/extension/` (Exit `0`) | Re-run after final JS edit. |
| **Extension Unit & Security Suite** | `npm test` (`node tests/extension/run-all-tests.js`) | **PASS** | **10 / 10 suites PASSED**, `0` failed (`2.08s`) | Re-run after final JS edit. Includes repaired `scannerAdapters.test.js` (temp fixture repo), fixed `reScanVerification.test.js`, and new `phase1Security.test.js`. |
| **.NET Solution Clean Build** | `dotnet build VulnerabilityRemediation.sln --no-restore -p:UseSharedCompilation=false /nr:false` | **PASS** | **0 Warning(s), 0 Error(s)** (`8.50s`), all 7 projects built cleanly | Built cleanly after final C# edit (`VulnerabilityDataMcp/Program.cs` & tests). |
| **.NET Automated Test Suite (Unfiltered)** | `dotnet test VulnerabilityRemediation.sln --no-build --verbosity normal` | **PASS** | **50 / 50 tests PASSED**, `0` failed, `0` skipped (`1.2619m`) | Unfiltered full run after final C# edit. Includes **40** baseline tests, **2** isolated `McpServerTests` JSON-RPC process tests, and **8** new `Phase1SecurityTests`. See `MockTestValidationAgent` disclosure below. |
| **CLI Policy Enforcement Check** | `dotnet run --project src\VulnerabilityRemediation.Cli --no-build -- publish VUL-1` & `-- batch-execute VUL-1 VUL-2` | **PASS** | Both returned **Exit `1`** with `[POLICY_BLOCKED - Phase 1 P0-B]` and `[SEC-02 POLICY_BLOCKED]` | Executed against isolated temp `GCAS_WORKSPACE_ROOT` with `GCAS_AUTO_SEED_SAMPLES="0"`. |

---

## 2. JavaScript Regression & Phase 1 Security Suite Details (`10 / 10 PASSED`)

1. **`CSV Parser & Row Isolation`**: Ingested `17` historical CSV rows intact, verified RFC 4180 parsing & isolated single-row updates.
2. **`Report Parser & Evidence Discovery`**: Verified ID normalization, `11/11` output report resolution, missing timing `null` honesty, and `13` cataloged reports.
3. **`Security Containment & Webview Hardening`**: Canonical path containment, symlink escape blocking, IPC allowlist validation, Stored XSS escaping, strict CSP meta tag, and random nonce generation.
4. **`Deterministic Test Runner Execution`**: Executable allowlist enforcement, real local `dotnet` availability check, framework runner detection (`dotnet`, `mvn`, `npm`), and output secret redaction.
5. **`Workflow State Machine & Approval Gates`**: Direct final gate approval blocked without Stage 4, duplicate concurrent runs prevented, snapshot rollback verified, run state persistence verified.
6. **`Dashboard Metrics & Quality Accuracy`**: Accurate `17` total / `5` critical / `5` remediated (overcounting removed) / `1` pending review / zero-denominator handling / genuine counters replacing hardcoded values.
7. **`Scanner Adapters & Controller Execution` *(Repaired from Phase 0 fail)***: Uses self-contained disposable fixture in `os.tmpdir()` containing `appsettings.json` (`SEC-001`), `LegacyCrypto.cs` (`SEC-003`), and `PaymentsAPI.csproj` — independent of mode-`160000` unpopulated `sample-repos/*` gitlinks. Verifies Roslyn SARIF, compiler warning filter, NuGet audit parsing + offline detection, CodeQL null-byte binary guard + SARIF parsing, and `ScanController` execution (`10ms`, `4` progress events).
8. **`Normalized Findings Model & Storage`**: Fingerprint deduplication, CSV schema adaptation, bounded `20`-session scan history, and combined CSV + scanned findings without mutating `vulnerabilities.csv`.
9. **`Post-Remediation Re-Scanning & Verification` *(Repaired wiring)***: Fixed `RemediationEngine(workspaceRoot, null, { findingsStore: store, reScanVerifier: verifier })` + `instanceof ReScanVerifier` check; verifies `STILL PRESENT`, `RESOLVED`, `REGRESSION DETECTED`, and `NOT VERIFIED`.
10. **`Phase 1 P0 Security Containment & Core Integrity` *(New)***:
    * **P0-A:** `Scanner_ID` mapping without fallback to `secrets-config`; unknown/missing scanner -> `NOT VERIFIED`; zero-test outputs (`dotnet`, `mvn`, `npm`) -> `UNTESTED`; compile error -> `FAILED`; `NOT EXECUTED` test result with clean scan NEVER resolves finding; diagnostic suppression (`#pragma warning disable`) blocked cleanly at Stage 5 (`Security Policy Violation (P0-A)`).
    * **P0-C (`SEC-02`):** Comma-separated, `BATCH-*`, `ALL`, `*`, ambiguous duplicate CSV IDs, missing `Application_Number`, and missing `Repository` rejected deterministically before LLM calls; modified `proposedDiffSha256` on Stage 4 resume rejected (`Gate Integrity Violation`).
    * **P0-D:** `buildMinimizedSingleFinding` rejects multi-finding arrays, strips `Product_Owner`, `Primary_Manager`, `Subscription`, `Resource_Group`, `VM_Name`, `RawValuesJson`, and masks keys; `OutboundContextGate` blocks `.env`, GitHub PAT, Stripe-pattern key, SSN, corporate email, NUL/binary bytes, oversize source, high-entropy literal, prompt injection (`Ignore all previous instructions ... RESULT: PASS`), and `>1` target files while recording redacted logs with zero leaked secret literals; verified `LlmClient.generateCompletion` blocks BEFORE `getAvailableModels()`.
    * **P0-E (`SEC-09`):** Blocks Critical->Low downgrade, preserves `CRITICAL` and `Out of SLA`, sets `MANDATORY_INDEPENDENT_REVIEW` and `PENDING_HUMAN_GOVERNANCE` for downgrades and High/Critical no-action proposals.
    * **P0-F:** Verifies CSPRNG nonce (`>= 32` chars, unique), strict rendered CSP (no `'unsafe-inline'`, no `https:` in `img-src`), zero inline `style=` HTML attributes across `dashboard.html` and `dashboard.js`, all 5 refactored `dashboard.js` data aggregators, and real HTTP loopback negative tests against `preview-dashboard.js` (`403` on `/api/approve-final`, `../../package.json` traversal, `/api/scan/target` traversal, cross-origin `evil.example`, `/api/remediate-stream?approved=true`, verifying `vulnerabilities.csv` stays byte-for-byte intact).
    * **Step 8 Smoke Check:** Mocked VS Code Extension Host subprocess activates cleanly, registers `gcac.scanRepository` and `gcac.vulnerability-orchestrator`, renders participant welcome markdown, executes `gcac.scanRepository` cleanly, loads CSV via `selectCsv`, and dispatches `launchCopilot` opening `workbench.action.chat.open` with `@vulnerability-orchestrator`.

---

## 3. .NET Test Suite Details (`50 / 50 PASSED`)

* **Existing Baseline Tests (`40` tests):** `DomainValidatorTests`, `RouteDerivationTests`, `VulnerabilityBatchingTests`, `ExcelIngestionTests`, `VulnerabilityRepositoryTests`, `RepositoryRegistryTests`, `WorkspaceManagerTests`, `AgentUnitTests`, and `EndToEndRemediationTests` (`8` scenarios).
  * **Honest Mock Disclosure:** `EndToEndRemediationTests` lines 88–89 continue to inject `MockTestValidationAgent` for git-workspace end-to-end orchestration flow checks; those 8 tests prove orchestrator flow/routing/evidence generation, **not** live compiler execution. Unmocked validation fail-closed behavior (`UNTESTED` on non-code projects, missing/0-test enforcement, `OutcomeContractEvaluator`) is tested separately in `Phase1SecurityTests` and Extension `testRunner`/`phase1Security` suites.
* **`McpServerTests` (`2` live STDIO JSON-RPC process tests — now unfiltered & isolated):**
  1. `McpServer_InitializeAndToolsList_ReturnsValidJsonRpcSchema`: Executes real `VulnerabilityDataMcp` process inside isolated temp `GCAS_WORKSPACE_ROOT` (`GCAS_AUTO_SEED_SAMPLES="0"`), verifying `initialize` & `tools/list`.
  2. `McpServer_NegativeSecurityControls_EnforcesPolicyBlockedAndMinimization`: Sends live JSON-RPC `tools/call` requests over STDIO: verifies `approve_pr` (omitted, `false`, and `true`), `publish_remediation_pr`, `execute_batch_remediation`, and comma-separated `execute_remediation` return `"isError":true` (`POLICY_BLOCKED` / `SEC-02`), and verifies `get_vulnerability` omits PII/infra/`RawValues` and masks credentials under schema `GCAC-MIN-1.0`.
* **`Phase1SecurityTests` (`8` new security tests):**
  1. `P0A_DotNetFixAgent_NoMatchingRule_DoesNotReturnFalseSuccess`
  2. `P0A_SecurityReviewAgent_EmptyDiffOrDiagnosticSuppression_FailsClosed`
  3. `P0A_OutcomeContractEvaluator_ZeroTestsWhereRequired_NeverPasses`
  4. `P0A_TestValidationAgent_NonCodeProject_DoesNotFabricatePass`
  5. `P0B_PublishAndCommitAndPush_AlwaysBlockedEvenWithBooleanTrue`
  6. `P0C_BatchExecutionAndMultiId_BlockedBySec02Policy`
  7. `P0D_QuarantineSensitiveHistoricalMetadata_PreservesRowsAndQuarantinesPii` (including idempotency check `0` moved on 2nd run and preservation of non-deleted row)
  8. `P0E_ApplyAdvisoryGovernance_PreventsCriticalSeverityDowngrade`

---

## 4. Environment Constraints & Headless Verification Limits (`NOT VERIFIED`)

1. **VS Code `.NET` Sandbox Constraint:** Inside the IDE sandbox, `dotnet build` / `VSTest` previously blocked on NuGet/IPC access; running `dotnet` builds and tests cleanly in the standard Windows host shell resolved all packages and IPC cleanly.
2. **Interactive VS Code Extension Host & Live Copilot UI (`NOT VERIFIED` Headlessly):**
   Because automated CI/headless tests cannot launch a graphical authenticated VS Code Extension Development Host (`F5`) signed in with GitHub Copilot entitlements, live interactive testing of the following paths remains **`NOT VERIFIED`** until human verification:
   * Visual inspection of Webview CSS rendering across Light/Dark VS Code themes under strict CSP (`style-src ${webview.cspSource}` with zero `'unsafe-inline'`).
   * End-to-end live click of **"Analyze & Remediate"** -> live `vscode.lm` GPT-4o / GPT-4o-mini stream -> Gate 1 diff review -> Stage 5–9 execution -> native `vscode.diff` editor.
   * End-to-end interactive Copilot Chat `@vulnerability-orchestrator /remediate-vulnerability <ID>` and `launchCopilot` (`workbench.action.chat.open`) submission with live Copilot entitlement.
   * Visual UI click of **"Run Vulnerability Scan"** & `GCAC: Scan Workspace` command inside active desktop window.

