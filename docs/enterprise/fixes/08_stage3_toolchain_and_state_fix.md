# Fix Report: Stage 3 Toolchain Selection and Workflow-State Integrity

**Date:** 2026-11-15  
**Component:** GCAC Remediation Hub (VS Code Extension, Sandbox Runtime & Canonical State Engine)  
**Target Finding:** `SCAN-SECRET-016` (Rule `SEC-005`, `CWE-89`)  
**Target Repository:** `sample-repos/payments-api`  
**Status:** COMPLETE (Automated Verification Passed; Manual Acceptance Pending)

---

## 1. Executive Summary

This correction addresses a critical toolchain resolution failure during Stage 3 Baseline Testing for finding `SCAN-SECRET-016` in `sample-repos/payments-api`. The remediation pipeline previously requested an unprovisioned template digest (`dotnet-9.0-sts` @ `sha256:9f6b8c...`) despite a verified genuine .NET 10 ARM64 image being provisioned locally (`dotnet-10.0-lts` @ `sha256:fe0fd4...`). 

Furthermore, upon encountering this container image policy block, the extension previously misclassified the container policy stop as a generic `RUNNER_CRASH`, presented incomplete baseline execution as `Validation Failed`, showed Stage 4 as `AWAITING REVIEW` with a synthetic diff placeholder string (`Diff-bound upon Stage 4 pause`), and offered an invalid retry.

The implementation establishes deterministic framework resolution, enforces verified container image selection, corrects the canonical workflow state machine across the Webview and Copilot surfaces, hardens approval gate integrity, prevents blind retries of unprovisioned toolchains, and verifies vulnerability provenance for `SCAN-SECRET-016`.

---

## 2. Confirmed Root Causes

1. **Framework Mismatch in Disposable Fixture:**
   `sample-repos/payments-api` originally targeted `net9.0`. The local Docker daemon hosted only .NET 10 SDK (`mcr.microsoft.com/dotnet/sdk:10.0` containing .NET 10.0.15 runtime and SDK 10.0.404). When GCAC inspected `PaymentsAPI.csproj`, it resolved `dotnet-9.0-sts`, which was configured with an unprovisioned template digest (`sha256:9f6b8c...`).
2. **Unsupported Runtime Assumption:**
   .NET 10 SDK container images cannot execute `net9.0` test assemblies without the `Microsoft.NETCore.App 9.0.0` runtime pack installed. Running .NET 9 binaries against .NET 10 SDK causes `testhost.dll` to abort.
3. **Misclassification of Container Policy Blocks as `RUNNER_CRASH`:**
   In `remediationEngine.js`, `_classifyPipelineError(err)` lacked matching for `TOOLCHAIN_IMAGE_UNAVAILABLE` and unprovisioned image digest blocks, falling through to `RUNNER_CRASH`.
4. **Cascading State Drift in Report Parser & Webview:**
   `reportParser.js` marked Stage 3 as `completed` whenever static `details.classification` was populated, cascading Stage 4 to `awaiting_review`. This occurred even when Stage 3 baseline testing failed or was blocked.
5. **Synthetic Diff Placeholder in UI Gate:**
   `dashboard.js` contained a fallback string `Diff-bound upon Stage 4 pause` when `proposedDiffSha256` was absent, creating the false illusion of a diff-bound approval state.
6. **Premature Retry Eligibility:**
   `evaluateRetryEligibility` treated `RUNNER_CRASH` as transient without verifying if the required toolchain image was provisioned in the local container cache.
7. **Cross-Platform Path Separator in Solution File:**
   `PaymentsAPI.sln` used Windows backslashes (`src\PaymentsAPI\PaymentsAPI.csproj`), preventing Linux MSBuild inside the container from discovering project and test targets during sandboxed testing.

---

## 3. Files Modified

| File | Changes Made |
|---|---|
| `sample-repos/payments-api/src/PaymentsAPI/PaymentsAPI.csproj` | Migrated TargetFramework to `net10.0`; added `System.Data.SqlClient` reference. |
| `sample-repos/payments-api/tests/PaymentsAPI.Tests/PaymentsAPI.Tests.csproj` | Migrated TargetFramework to `net10.0`. |
| `sample-repos/payments-api/PaymentsAPI.sln` | Corrected backslashes to forward slashes for Linux Docker compatibility. |
| `src/VulnerabilityRemediation.Repository/Services/SampleRepositoriesSeeder.cs` | Updated seeder templates to `net10.0` and forward slashes. |
| `extension/sandbox/toolchainProfiles.js` | Updated `assertProfileProvisioned` to set `TOOLCHAIN_IMAGE_UNAVAILABLE` and `COULD_NOT_RUN`. |
| `extension/sandbox/trustedExecutionGateway.js` | Enforced `COULD NOT RUN` status, `TOOLCHAIN_IMAGE_UNAVAILABLE` failure category, and `OUTCOME_STATUS.COULD_NOT_RUN` machine status on template digest detection. |
| `extension/sandbox/containerSandboxBackend.js` | Enforced `COULD_NOT_RUN` and `TOOLCHAIN_IMAGE_UNAVAILABLE` when pinned image is missing from local cache. |
| `extension/testRunner.js` | Added `TOOLCHAIN_IMAGE_UNAVAILABLE` to `FAILURE_CATEGORIES` and diagnostic guidance; conditionally enforced `requireProvisioned` for real container execution. |
| `extension/runStateContract.js` | Added `BLOCKED` to `WORKFLOW_LIFECYCLE`; updated `mapLegacyStatusToLifecycle` and `deriveTerminalBanner` to map `TOOLCHAIN_IMAGE_UNAVAILABLE` and `BLOCKED` cleanly. |
| `extension/remediationEngine.js` | Updated `_classifyPipelineError`; handled `TOOLCHAIN_IMAGE_UNAVAILABLE` in Stage 3 to set `status: 'BLOCKED'`, `baselineOutcome: COULD_NOT_RUN`, `workflowLifecycle: BLOCKED`, Stage 4 `blocked_by_prerequisite`, Stages 5–9 `not_started`; updated `evaluateRetryEligibility` to check local image cache before enabling retry; guarded `executePipeline` against authorizing blocked/unverified diffs. |
| `extension/reportParser.js` | Prevented Stage 3 completion and Stage 4 review when Stage 3 is blocked or failed; normalized details to `BLOCKED` and `TOOLCHAIN_IMAGE_UNAVAILABLE`. |
| `extension/media/dashboard.js` | Stepper handles `blocked_by_prerequisite` and `not_started`; badge displays `Blocked`; eliminated synthetic `Diff-bound upon Stage 4 pause`; labeled unverified proposals `[NON-APPROVABLE DRAFT RECOMMENDATION]`; disabled approval button when prerequisites are blocked. |
| `extension/media/dashboard.css` | Added styling for `blocked_by_prerequisite` and `not_started`. |
| `extension/copilotOutputFormatter.js` | Added `formatTerminalConclusionMarkdown` handler for `BLOCKED` and `TOOLCHAIN_IMAGE_UNAVAILABLE`; prevented `formatGateMarkdown` from displaying approval gate when blocked. |
| `extension/extension.js` | Added guard in `approveRemediation` handler to reject approval when Stage 3 prerequisites are not satisfied or diff digest is missing. |
| `tests/extension/stage3ToolchainAndStateFix.test.js` | Created comprehensive 12-point regression suite covering all Task F requirements. |
| `tests/extension/run-all-tests.js` | Integrated new test suite into regression runner. |

---

## 4. Framework Detection and Profile Selection

- **Repository Inspected:** `sample-repos/payments-api`
- **Detected Framework:** `net10.0` (validated from `PaymentsAPI.csproj` and `PaymentsAPI.Tests.csproj`)
- **Selected Profile:** `dotnet-10.0-lts`
- **Pinned Image Digest:** `sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb`
- **Image Reference:** `mcr.microsoft.com/dotnet/sdk@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb`
- **Digest Status:** `VERIFIED_IMAGE_DIGEST`
- **Negative Test Verification:** A repository targeting `net9.0` selects `dotnet-9.0-sts` with template digest `sha256:9f6b8c...` (`TEMPLATE_PLACEHOLDER`). `assertProfileProvisioned` immediately fails closed with `UNPROVISIONED_TOOLCHAIN_PROFILE` / `TOOLCHAIN_IMAGE_UNAVAILABLE` and `COULD_NOT_RUN`. No backward compatibility assumption is made.

---

## 5. Docker Execution Results

Execution of `dotnet test` within the genuine .NET 10 ARM64 container sandbox (`mcr.microsoft.com/dotnet/sdk:10.0`):

```text
Passed!  - Failed:     0, Passed:     1, Skipped:     0, Total:     1, Duration: 6 ms - PaymentsAPI.Tests.dll (net10.0)
```

- **Backend Type:** `local-container` (Docker Engine on macOS arm64)
- **Exit Code:** `0`
- **Network Mode:** Isolated (`--network=none` enforced; auto-pull disabled)
- **Volume Mounts:** Disposable isolated worktree mounted to `/sandbox-work:rw`, credential-free staging enforced.
- **Host Fallback:** ZERO silent host-shell fallback.

---

## 6. Canonical State Transition Verification

When a toolchain image is unavailable (as demonstrated on finding `SCAN-SECRET-016`):

| Surface / State Field | Required Value | Verified Output |
|---|---|---|
| Stage 3 Status | `BLOCKED` | `blocked` |
| Failure Category | `TOOLCHAIN_IMAGE_UNAVAILABLE` | `TOOLCHAIN_IMAGE_UNAVAILABLE` |
| Baseline Outcome | `COULD_NOT_RUN` | `COULD_NOT_RUN` |
| Workflow State | `BLOCKED` | `BLOCKED` |
| Post-Fix Validation | `NOT_EXECUTED` | `NOT_EXECUTED` |
| Stage 4 Status | `BLOCKED_BY_PREREQUISITE` | `blocked_by_prerequisite` |
| Stages 5–9 Status | `NOT_STARTED` | `not_started` |
| Overall Webview Badge | `Blocked` | `badge-status-blocked` (`Blocked`) |
| Terminal Banner | `Workflow Blocked — Toolchain Image Unavailable` | `Workflow Blocked — Toolchain Image Unavailable` |

---

## 7. Approval and Retry Governance

1. **Diff-Bound Approval Readiness:**
   - Synthetic placeholder string `Diff-bound upon Stage 4 pause` is eliminated.
   - Stage 4 approval requires a valid 64-character SHA-256 diff digest and verified patch.
   - Textual draft recommendations are labeled `[NON-APPROVABLE DRAFT RECOMMENDATION]`.
   - Attempting approval via Copilot Chat (`/approve`) or Webview when Stage 3 is blocked throws `Gate Integrity Violation: Stage 4 approval is blocked because Stage 3 baseline testing did not succeed (status: BLOCKED). Resolve prerequisites first.`
2. **Retry Stage Correctness:**
   - While the required toolchain image remains unprovisioned, `evaluateRetryEligibility` returns `retryEligible: false` (`reasonCode: 'TOOLCHAIN_IMAGE_UNAVAILABLE'`).
   - Attempting `retryStage` when ineligible fails closed with `Retry Blocked: Prerequisites not satisfied`.
   - Retry attempts are not consumed (`retryCount: 0` preserved) for operations that never started.
   - Once the toolchain is provisioned or the repository is migrated to supported .NET 10 LTS, `evaluateRetryEligibility` permits retry at Stage 3.

---

## 8. Vulnerability Provenance Validation (SCAN-SECRET-016)

- **Scanner ID:** `secrets-config` (v1.3.0)
- **Rule ID:** `SEC-005` ("Potential SQL Injection via Unparameterized Query")
- **Target File:** `src/PaymentsAPI/Controllers/PaymentController.cs:15`
- **Code Inspected:**
  ```csharp
  string query = "SELECT * FROM Payments WHERE AccountId = '" + request.AccountId + "' AND Amount = " + request.Amount;
  ```
- **Provenance Conclusion:** Source argument `request.AccountId` is concatenated directly into raw SQL command string without parameterized placeholders (`SqlParameter`). Concrete source-to-sink data flow supports CWE-89 SQL Injection. Classification `CWE-89 SQL Injection` is verified and preserved.

---

## 9. Automated Test Evidence

All 12 items in Task F are automated in `tests/extension/stage3ToolchainAndStateFix.test.js`:

```text
===============================================================
GCAC Stage 3 Toolchain Selection & Workflow-State Integrity Tests
Target: Task F Requirements (Items 1-12)
===============================================================

[TEST 1] Compatible .NET 10 Profile Selection for Migrated Repository
  ✓ Verified approved .NET 10 profile selected with pinned local digest.
[TEST 2] Unsupported .NET 9 Runtime Handling
  ✓ .NET 9 runtime not assumed compatible with .NET 10 SDK; fail-closed enforcement verified.
[TEST 3] Unavailable or Placeholder Image Detection
  ✓ Unavailable/placeholder image detected before execution and mapped to TOOLCHAIN_IMAGE_UNAVAILABLE.
[TEST 4] Stage 3 Blocked Before Execution
  ✓ Stage 3 BaselineTest cleanly intercepted prior to container spawn.
[TEST 5] Correct Canonical State & Stage Lifecycle When Stage 3 Fails Toolchain
  ✓ Canonical state verified: Stage 3 BLOCKED, Stage 4 BLOCKED_BY_PREREQUISITE, Stages 5-9 NOT_STARTED.
[TEST 6] Approval Disabled When Stage 3 Is Blocked
  ✓ Gate integrity enforced: Approval strictly prohibited when Stage 3 is blocked.
[TEST 7] No False Diff Digest Emitted
  ✓ Fallback placeholder string eliminated; actual 64-char SHA-256 digest strictly required.
[TEST 8] Retry Disabled Until Prerequisites Are Restored
  ✓ Retry disabled while toolchain is unavailable; zero retry quota consumed.
[TEST 9] Safe Recovery After Restoring Required Toolchain
  ✓ Eligibility re-evaluated: Recovery permitted once verified toolchain is present.
[TEST 10] Copilot & Webview Status Consistency
  ✓ Copilot terminal output reflects verified canonical state without misleading validation errors.
[TEST 11] Original Scanner Finding Provenance Validation (SCAN-SECRET-016)
  ✓ Finding provenance confirmed: scanner secrets-config (SEC-005), line 15, verified CWE-89.
[TEST 12] Zero Host-Shell Fallback Enforcement
  ✓ No host-shell fallback: Execution strictly blocked when sandbox unavailable.

===============================================================
All 12 Stage 3 Toolchain and State Fix tests PASSED cleanly.
===============================================================
```

---

## 10. Outstanding Manual Checks

The following checks will be performed during interactive application acceptance:
1. Open the GCAC Remediation Hub in the VS Code Extension Host.
2. Select `SCAN-SECRET-016` in the dashboard list and verify visual rendering of the `Blocked` status badge and stepper showing Stage 3 `BLOCKED`, Stage 4 `BLOCKED_BY_PREREQUISITE`, and Stages 5–9 `NOT_STARTED`.
3. Verify that the `Approve & Continue` button is disabled with tooltip indicating prerequisites are blocked.
4. Verify that Copilot Chat displays the blocked conclusion banner without interactive human gate prompt when queried with `@vulnerability-orchestrator /remediate-vulnerability SCAN-SECRET-016`.
