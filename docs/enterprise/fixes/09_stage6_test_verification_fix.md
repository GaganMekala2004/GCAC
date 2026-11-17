# Fix Report: Genuine .NET Test Verification and Remediation Evidence

**Date:** 2026-11-15  
**Component:** GCAC Remediation Hub (VS Code Extension, Sandbox Runtime & Test Verification Engine)  
**Target Finding:** `SCAN-SECRET-016` (Rule `SEC-005`, `CWE-89`)  
**Target Repository:** `sample-repos/payments-api`  
**Status:** COMPLETE (Automated Verification Passed; Manual VS Code / Copilot Acceptance Pending)

---

## 1. Executive Summary

During remediation of `SCAN-SECRET-016` (SQL Injection in `PaymentController.cs`), GCAC previously reported:
`dotnet test exited 0 without recognizable test summary output.` (`PARSE_FAILED`). Stage 3 baseline was `UNTESTED`, Stage 5 applied a patch, Stage 6 failed to verify tests, Stage 7 security review failed (and erroneously emitted secret rotation requirements for a pure SQL injection finding), and Stage 8 final human sign-off was blocked.

This reliability correction establishes deterministic, machine-readable .NET test verification using standard TRX reports, fixes container sandbox NuGet asset caching, enforces strict approval and baseline gate integrity, eliminates spurious secret rotation instructions on pure SQL injection findings, and provides genuine SQL injection regression tests.

---

## 2. Confirmed Root Causes

1. **Host NuGet Cache Path Mismatch in Isolated Worktrees (`workspaceStaging.js`):**
   When `workspaceStaging.js` prepared isolated workspaces, it copied host-generated `obj/project.assets.json` and `*.nuget.g.props` files containing absolute macOS host paths (`/Users/ksglrohith/.nuget/packages`). Inside the Linux Docker container, these paths did not exist. MSBuild silently skipped importing test SDK props and targets (`Microsoft.NET.Test.Sdk.props`), causing `dotnet test` to skip test execution entirely and exit 0 without executing any tests.

2. **Missing Sandbox Package Cache Mount in Docker Sandbox (`containerSandboxBackend.js`):**
   The Docker container ran with `--network none` but lacked a read-only volume mount for offline NuGet packages at `/sandbox-cache/nuget`. Consequently, `dotnet test --no-restore` could not locate resolved packages if fallback resolution was triggered.

3. **Missing `<IsTestProject>true</IsTestProject>` in Test Project:**
   `PaymentsAPI.Tests.csproj` did not explicitly specify `<IsTestProject>true</IsTestProject>`. When MSBuild ran without full test target imports, it treated the project as a library rather than a test project, printing `Skipping running test for project...` with exit code 0.

4. **Brittle Console-Output Parsing Over Machine-Readable Artifacts:**
   `testRunner.js` previously relied solely on parsing regexes from human-oriented console output. Variations in .NET 10 console format or missing summary lines triggered `PARSE_FAILED` despite exit code 0. Standard machine-readable TRX logging was not requested or collected from the container.

5. **Approval Progression Permitted on Baseline `UNTESTED`:**
   Stage 4 human review was permitted to advance even when Stage 3 baseline testing was `UNTESTED`, creating workflow integrity violations where an untested baseline was followed by patch application.

6. **Spurious Credential Rotation Guidance on SQLi Findings:**
   `isSecretOrCredentialFinding` in `evidenceChecklist.js` inspected the finding ID string (`/secret/i`). Because the finding was named `SCAN-SECRET-016` (due to being flagged by `secrets-config` scanner), it produced mandatory credential rotation and invalidation tasks, even though the vulnerability was pure SQL Injection (`CWE-89` / `SEC-005`).

7. **Vulnerable Database Query Snippet in `PaymentController.cs`:**
   The original code concatenated unescaped user input into `SELECT * FROM Payments WHERE AccountNumber = '{accountNumber}'`, creating a classic SQL injection vulnerability (`CWE-89`). Furthermore, the proposed patch snippet needed to ensure actual parameterized query execution with correct types and connection management.

---

## 3. Actual Test Command, Runner, and Discovery Results

### Test Project Discovery Result
- **Discovered Test Project:** `tests/PaymentsAPI.Tests/PaymentsAPI.Tests.csproj`
- **Solution File:** `PaymentsAPI.sln`
- **Target Framework:** `net10.0`
- **Test SDK Properties:** Explicit `<IsTestProject>true</IsTestProject>` configured.

### Detected Test Runner
- **Runner Framework:** `VSTest` (Standard .NET Test Runner with `Microsoft.NET.Test.Sdk` v17.12.0)
- **MTP Support:** Checked and not enabled (`<EnableMicrosoftTestingPlatform>` absent); VSTest-only switches (`--logger trx`) correctly applied. When MTP is detected with `Microsoft.Testing.Extensions.TrxReport`, GCAC automatically switches to `--report-trx`.

### Actual Test Command
```bash
dotnet test PaymentsAPI.sln --no-restore --nologo -v normal --logger trx --results-directory /sandbox-out
```

- **Exit Code:** `0`
- **Output Artifact Produced:** `/sandbox-out/_9c5ce7a04141_2026-11-15_13_34_13_net10.0.trx`
- **TRX Provenance:**
  - `outcome="Passed"`
  - `total="1"`
  - `passed="1"`
  - `failed="0"`
  - `skipped="0"`
- **Collected Machine-Readable Status:** `TESTS_PASSED` (Passed: 1, Failed: 0, Total: 1)

---

## 4. Files Changed

| File | Changes Made |
|---|---|
| `extension/workspaceStaging.js` | Added `normalizeProjectAssetsCachePaths` to rewrite host NuGet package paths to `/sandbox-cache/nuget` in `project.assets.json` and `*.nuget.g.props`. |
| `extension/sandbox/containerSandboxBackend.js` | Added host `.nuget/packages` volume mount to `/sandbox-cache/nuget:ro`; ensured `cacheDirHost/nuget` directory exists on host prior to container start; collected `/sandbox-out/*.trx` artifacts into gateway response before container termination. |
| `extension/config/approved-toolchain-profiles.json` | Updated `dotnet-10.0-lts` profile to permit TRX arguments (`--logger`, `trx`, `--results-directory`, `/sandbox-out`, `--report-trx`, `--report-trx-filename`, `test-results.trx`) without metacharacter security violations; recomputed SHA-256 profile digest. |
| `extension/testRunner.js` | Added `detectDotnetRunnerFramework` (MTP vs VSTest); added `parseTrxReport` with schema validation and failure categorization; updated `executeRealTestRunner` to extract machine-readable TRX counts before console text; updated `runBaselineTests` and `runPostFixTests` to check sandbox availability and return `UNTESTED` with `NO_TESTS_DISCOVERED` for empty repositories. |
| `sample-repos/payments-api/tests/PaymentsAPI.Tests/PaymentsAPI.Tests.csproj` | Added `<IsTestProject>true</IsTestProject>` property. |
| `src/VulnerabilityRemediation.Repository/Services/SampleRepositoriesSeeder.cs` | Added `<IsTestProject>true</IsTestProject>` to seeded template for `PaymentsAPI.Tests.csproj`. |
| `sample-repos/payments-api/src/PaymentsAPI/Controllers/PaymentController.cs` | Refactored `GetPaymentsByAccount` to use parameterized queries (`@accountNumber`) with `SqlParameter(SqlDbType.VarChar, 50)` and proper connection disposal. |
| `sample-repos/payments-api/tests/PaymentsAPI.Tests/PaymentControllerTests.cs` | Implemented genuine SQL injection regression assertions verifying malicious input payloads (`' OR '1'='1`) are safely passed as parameters rather than executed as SQL commands. |
| `extension/remediationEngine.js` | Enforced Stage 4 approval gate blocking when Stage 3 baseline testing is `UNTESTED` unless an explicit authorized exception is documented (`allowBaselineException: true`); bound approval strictly to `proposedDiffSha256`. |
| `extension/evidenceChecklist.js` | Corrected `isSecretOrCredentialFinding` to exclude CWE-89 (SQLi), CWE-78 (Command Injection), and CWE-327/328 from secret-rotation checklists, basing guidance on vulnerability classification rather than finding ID regexes. |
| `extension/copilotOutputFormatter.js` | Updated markdown summary formatters to display `Workflow Lifecycle`, `Baseline Outcome`, `Post-Fix Test Outcome`, machine-verified test counts, re-scan status, and final review eligibility. |
| `extension/media/dashboard.js` | Updated dashboard rendering to display verified machine test counts (`Passed: X, Failed: Y`), distinguish `PARSE_FAILED` from unexecuted tests, and show clear review recommendations. |
| `tests/extension/stage6TestVerification.test.js` | Comprehensive 16-scenario automated test suite validating all Task 8 requirements. |
| `tests/extension/run-all-tests.js` | Registered Stage 6 test suite into the master regression harness. |

---

## 5. Actual Tests Executed and Counts

Live sandboxed execution in the container sandbox produced verified machine-readable results:

```xml
<TestRun id="9c5ce7a0-4141-4c12-9fa9-43c2da9f9ff2" name="root@9c5ce7a04141 2026-11-15 13:34:13" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Counters total="1" executed="1" passed="1" failed="0" error="0" timeout="0" aborted="0" inconclusive="0" passedButRunAborted="0" notRunnable="0" notExecuted="0" disconnected="0" warning="0" completed="0" inProgress="0" pending="0" />
  <ResultSummary outcome="Passed">
    <Counters total="1" executed="1" passed="1" failed="0" error="0" timeout="0" aborted="0" inconclusive="0" passedButRunAborted="0" notRunnable="0" notExecuted="0" disconnected="0" warning="0" completed="0" inProgress="0" pending="0" />
  </ResultSummary>
</TestRun>
```

- **Tests Executed:** 1
- **Tests Passed:** 1
- **Tests Failed:** 0
- **Tests Skipped:** 0
- **Validation Outcome:** `TESTS_PASSED`

---

## 6. SQL Injection Patch-Quality Assessment

### Vulnerability Verification (`CWE-89`)
- **File:** `sample-repos/payments-api/src/PaymentsAPI/Controllers/PaymentController.cs`
- **Original Code:**
  ```csharp
  string query = $"SELECT * FROM Payments WHERE AccountNumber = '{accountNumber}'";
  using var command = new SqlCommand(query, connection);
  ```
- **Remediated Implementation:**
  ```csharp
  const string query = "SELECT * FROM Payments WHERE AccountNumber = @accountNumber";
  using var command = new SqlCommand(query, connection);
  command.Parameters.Add(new SqlParameter("@accountNumber", SqlDbType.VarChar, 50)
  {
      Value = accountNumber ?? (object)DBNull.Value
  });
  ```
- **Security Assessment:**
  - Uses constant query string with `@accountNumber` parameter placeholder.
  - Parameter is bound with explicit type (`SqlDbType.VarChar`) and length bound (`50`).
  - Nulls are safely mapped to `DBNull.Value`.
  - Both `SqlConnection` and `SqlCommand` are managed via `using` statements.
  - Parameter is executed via `command.ExecuteReader()`.

---

## 7. Re-Scan Evidence

The remediation was verified against the `secrets-config` scanner using rule `SEC-005` ("Potential SQL Injection via Unparameterized Query"):
- **Pre-Fix Scan:** `SEC-005` triggered on line 15 with unparameterized query concatenation.
- **Post-Fix Re-Scan:** Rule `SEC-005` evaluated clean (zero matches).
- **Re-Scan Verification Status:** `RESOLVED`.
- **Finding Status:** Verified remediated; evidence captured with SHA-256 bound patch diff.

---

## 8. Approval Gate and Checklist Verification

1. **Baseline Gate Integrity:**
   Stage 4 human review strictly blocks progression if Stage 3 baseline testing resulted in `UNTESTED` or `COULD NOT RUN`, preventing untested patches from advancing without authorized exception metadata (`allowBaselineException: true` with documented rationale).

2. **Diff Hash Binding:**
   The exact SHA-256 digest of the proposed patch diff is recorded upon Stage 4 authorization (`proposedDiffSha256`). `verifyApprovalForExecution` verifies that the patch applied in Stage 5 matches this hash bit-for-bit. Any altered or tampered diff throws `DIFF_HASH_MISMATCH`.

3. **CWE-Specific Review Guidance:**
   - Pure SQL Injection findings (`CWE-89`, rule `SEC-005`) generate zero secret rotation or invalidation tasks.
   - Genuine credential exposure findings (`CWE-798`, rule `SEC-001`) retain mandatory secret rotation and invalidation requirements.

4. **Sign-off Eligibility:**
   Final human sign-off (Stage 8) is only unlocked when post-fix validation tests pass and scanner re-scan confirms `RESOLVED`.

---

## 9. Automated Test Outcomes

All 18 automated regression test suites executed and passed cleanly:

| # | Test Suite | Result |
|---|---|---|
| 1 | CSV Parser & Row Isolation | PASS |
| 2 | Report Parser & Evidence Discovery | PASS |
| 3 | Security Containment & Webview Hardening | PASS |
| 4 | Deterministic Test Runner Execution | PASS |
| 5 | Workflow State Machine & Approval Gates | PASS |
| 6 | Dashboard Metrics & Quality Accuracy | PASS |
| 7 | Scanner Adapters & Controller Execution | PASS |
| 8 | Normalized Findings Model & Storage | PASS |
| 9 | Post-Remediation Re-Scanning & Verification | PASS |
| 10 | Phase 1 P0 Security Containment & Core Integrity | PASS |
| 11 | Phase 2 Trust Controls & Secure Remediation Governance | PASS |
| 12 | Phase 3 Execution Isolation, Approved Toolchains & Supply Chain Security | PASS |
| 13 | Real-World Usability, Scan Accuracy, Portability & Retry | PASS |
| 14 | Production Workflow Stabilization & Reliability | PASS |
| 15 | Live Scanner Profile Selection & Toolchain Hardening | PASS |
| 16 | Docker Sandbox Scenarios & Boundary Hardening (A-I) | PASS |
| 17 | Stage 3 Toolchain Selection & Workflow-State Integrity | PASS |
| 18 | **Stage 6 .NET Test Verification & Remediation Evidence** | **PASS** |

### Detailed Breakdown of Stage 6 Test Scenarios (16/16 Passed)
- **Scenario 1:** VSTest genuine passing tests verified via TRX counters (`Passed: 2, Failed: 0, Total: 2`).
- **Scenario 2:** VSTest genuine failing tests extracted test-level failure diagnostics (`Assert.Equal() Failure`).
- **Scenario 3:** MTP detected accurately; VSTest-only switches not applied indiscriminately.
- **Scenario 4:** Repository with no tests reports `NO_TESTS_DISCOVERED` without fabricated pass.
- **Scenario 5:** Application project selected for testing correctly flagged `TEST_PROJECT_NOT_FOUND`.
- **Scenario 6:** Malformed/unclosed TRX reports reliably categorized as `PARSE_FAILED`.
- **Scenario 7:** Missing TRX artifact correctly maps to `TEST_RESULTS_MISSING` without synthetic counts.
- **Scenario 8:** Machine-readable TRX artifact takes precedence over unrecognized console text.
- **Scenario 9:** Sandbox output artifacts extracted and bound to gateway response before cleanup.
- **Scenario 10:** Compilation error before tests recognized as `BUILD_FAILED`.
- **Scenario 11:** Unsupported toolchain mapped cleanly to `TOOLCHAIN_IMAGE_UNAVAILABLE`.
- **Scenario 12:** Genuine SQL injection regression assertions verified for both states.
- **Scenario 13:** Baseline `UNTESTED` strictly blocks approval unless explicit exception authorized.
- **Scenario 14:** Exact approved diff hash binding enforced; changed patch requires fresh approval (`DIFF_HASH_MISMATCH`).
- **Scenario 15:** Missing post-fix scanner re-scan blocks final human review eligibility (`REVIEW_REQUIRED`).
- **Scenario 16:** CWE-89 SQL injection produces zero secret rotation actions; CWE-798 retains mandatory actions.

---

## 10. Remaining Blockers

- **Zero Core Blockers:** All automated execution paths, TRX parsing, container sandbox extraction, and gate checks are fully verified and passing.
- **Deferred Acceptance:** Interactive VS Code Extension UI and Copilot chat webview live user acceptance remain deferred until final acceptance testing.
