# GCAC — Live Scanner Profile Selection & Unprovisioned Toolchain Handling Fix

**Document ID:** `GCAC-DOC-07-2026-11`  
**Classification:** Enterprise Engineering / Container Security Remediation Report  
**Target Environment:** macOS Darwin (Apple Silicon arm64), Docker Engine 29.9.3, .NET 10.0.404 / 10.0.15  
**Final Status:** **VERIFIED & RESOLVED**

---

## 1. Executive Summary

During live vulnerability scanning in the GCAC VS Code extension, scans failed with incomplete scan coverage and the following error:

```text
Incomplete Scan Coverage (Partial)
.NET Security Analyzer: Approved digest-pinned image mcr.microsoft.com/dotnet/sdk@sha256:9f6b8c7d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b is not present in local runtime cache; auto-pull disabled.
```

The referenced image digest (`sha256:9f6b8c7d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b`) was the unverified placeholder digest assigned to profile `dotnet-9.0-sts` in `approved-toolchain-profiles.json`.

This investigation traced the live execution path from the Webview scan request through framework detection, profile resolution, execution gateway validation, and container backend execution. The root cause was identified, corrected across both JavaScript and C# subsystems, and validated with 16 automated regression test suites (including 9 targeted live profile selection tests and 9 real Docker container scenarios A–I).

---

## 2. Confirmed Root Cause Analysis

### A. Active Target & Target Framework Detection
1. **Target Selection in Live Webview:**
   Inspection of `output/scans/scan-history.json` revealed that the active scan target in the extension was `sample-repos/inventory-manager`:
   ```json
   "targetPath": "sample-repos/inventory-manager",
   "repositoryRoot": "/Users/ksglrohith/Documents/GitHub/GCAC/sample-repos/inventory-manager",
   "canonicalRepositoryId": "0da02ae32fbb",
   "applicationNumber": "APP-1003"
   ```
2. **Project Target Framework:**
   `sample-repos/inventory-manager/src/InventoryManager/InventoryManager.csproj` specifically targets `net9.0`:
   ```xml
   <Project Sdk="Microsoft.NET.Sdk">
     <PropertyGroup>
       <TargetFramework>net9.0</TargetFramework>
     </PropertyGroup>
   </Project>
   ```
   All four .NET sample repositories (`inventory-manager`, `storefront-api`, `payments-api`, `gcas-agentic-e2e-test-repo`) retain `net9.0` target frameworks.

### B. Why `dotnet-9.0-sts` Was Dispatched to Container Execution
1. **Framework-to-Profile Resolution:**
   `resolveProfileForRepository` correctly determined that `sample-repos/inventory-manager` targeted `net9.0`. Following enterprise policy, it selected profile `dotnet-9.0-sts` rather than forcing `.NET 10`.
2. **Missing Provisioning Verification Gate:**
   Profile `dotnet-9.0-sts` has `digestStatus: "TEMPLATE_PLACEHOLDER"` and is assigned placeholder digest `sha256:9f6b8c7d...`.
   Neither `toolchainProfiles.js`, `TrustedExecutionGateway`, nor scanner adapters verified whether `profile.digestStatus === 'TEMPLATE_PLACEHOLDER'` before proceeding to container execution.
3. **Container Backend Failure:**
   The unprovisioned profile reference was dispatched directly to `ContainerSandboxBackend.executeApprovedOperation`, which invoked `docker image inspect mcr.microsoft.com/dotnet/sdk@sha256:9f6b...`. Because the template digest does not exist locally, the container backend threw `TOOLCHAIN_IMAGE_MISSING`.
4. **Opaque Error Reporting:**
   The scanner caught the raw Docker inspection failure and emitted:
   `Approved digest-pinned image 'mcr.microsoft.com/dotnet/sdk@sha256:9f6b...' is not present in local runtime cache; auto-pull disabled.`
   It failed to report:
   - What target repository was selected (`sample-repos/inventory-manager`)
   - What TargetFramework was detected (`net9.0`)
   - What profile was selected (`dotnet-9.0-sts`)
   - Why it failed (unprovisioned template profile; only `net10.0` / `dotnet-10.0-lts` is provisioned locally).

---

## 3. Profile Selection Before and After the Fix

| Scenario | Repository Target | Detected Framework | Profile Selected Before Fix | Outcome Before Fix | Profile Selected After Fix | Outcome After Fix |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Compatible .NET 10 Project** | `.` (GCAC Workspace) or custom `net10.0` repo | `net10.0` | `dotnet-10.0-lts` | Clean container scan (`sha256:fe0fd4...`) | `dotnet-10.0-lts` | **COMPLETED** (100% coverage in isolated container) |
| **Legacy .NET 9 External Repo** | `sample-repos/inventory-manager` | `net9.0` | `dotnet-9.0-sts` | Container inspect crash on `sha256:9f6b...` | `dotnet-9.0-sts` | **BLOCKED (UNPROVISIONED_TOOLCHAIN_PROFILE)** with clear diagnostic notice |
| **Legacy .NET 8 External Repo** | External `net8.0` project | `net8.0` | `dotnet-8.0-lts` | Container inspect crash on `sha256:8e5a...` | `dotnet-8.0-lts` | **BLOCKED (UNPROVISIONED_TOOLCHAIN_PROFILE)** with clear diagnostic notice |
| **EOL Framework Repo** | `netcoreapp3.1` or `net7.0` | `netcoreapp3.1` | None | `UNAPPROVED_TARGET_FRAMEWORK` | None | **BLOCKED (UNAPPROVED_TARGET_FRAMEWORK)** |

---

## 4. Summary of Code Changes

### 1. `extension/sandbox/toolchainProfiles.js`
- **File & Directory Polymorphism:** `resolveProfileForRepository` now accepts project files (`.csproj`, `.sln`) as well as folder directories.
- **`Directory.Build.props` Inspection:** Added automatic inspection of root/parent `Directory.Build.props` for solution-level `<TargetFramework>` properties.
- **Deep Traversal:** Increased `.csproj` discovery depth to 5 levels to support enterprise multi-project directory structures.
- **Enriched Profile Metadata:** Attached `targetFramework`, `detectedFrameworks`, and `resolvedFrom` to the returned profile object.
- **`assertProfileProvisioned` Function:** Added assertion ensuring template placeholder profiles fail closed immediately with code `UNPROVISIONED_TOOLCHAIN_PROFILE` when container execution is required.

### 2. `extension/sandbox/trustedExecutionGateway.js`
- **Gateway Enforcement Gate:** Added check in `executeOperation` right before container preparation:
  ```javascript
  const isRealLocalContainer = (backend instanceof ContainerSandboxBackend) ||
      (backend && typeof backend.execFileFn === 'function' && typeof backend.buildContainerRunArgs === 'function');
  if (isRealLocalContainer && options.allowTemplateDigests !== true && (isTemplateDigestProfile(profile) || profile.digestStatus === 'TEMPLATE_PLACEHOLDER')) {
      const blockMsg = `UNPROVISIONED_TOOLCHAIN_PROFILE: Toolchain profile '${profile.profileId}' uses template placeholder digest '${profile.imageDigest}' (status: TEMPLATE_PLACEHOLDER). Only verified, provisioned toolchain profiles can execute in the container sandbox. Container auto-pull is strictly disabled by enterprise security policy.`;
      // Transitions instance to BLOCKED, records audit decision, returns fail-closed outcome
  }
  ```

### 3. `extension/scanning/adapters/dotnetSecurityScanner.js` & `nugetAuditScanner.js`
- **Direct Project File Resolution:** Passes resolved `projectFile` or `projectDirRoot` to `resolveProfileForRepository`.
- **Pre-execution Provisioning Verification:** Calls `assertProfileProvisioned` when running against real container backends.
- **Structured Diagnostics:** Emits comprehensive diagnostic context:
  ```json
  "diagnostics": {
      "repository": "sample-repos/inventory-manager",
      "targetFramework": "net9.0",
      "toolchainProfileId": "dotnet-9.0-sts",
      "imageDigest": "sha256:9f6b8c7d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
      "digestStatus": "TEMPLATE_PLACEHOLDER"
  }
  ```
- **Informative Error Messages:** Replaced raw `TOOLCHAIN_IMAGE_MISSING` errors with:
  `[.NET Security Analyzer] Target repository 'sample-repos/inventory-manager' (net9.0 -> dotnet-9.0-sts): UNPROVISIONED_TOOLCHAIN_PROFILE: ...`

### 4. `src/VulnerabilityRemediation.Repository/Sandbox/ToolchainProfileRegistry.cs`
- Enhanced `ResolveForRepository` with support for file paths, `Directory.Build.props` parsing, and `AssertProfileProvisioned(profile, repoLabel)`.

### 5. `tests/extension/liveScannerProfileSelection.test.js`
- Created dedicated test suite covering all 9 required verification scenarios.

---

## 5. Verification Commands and Results

### A. Targeted Regression Suite (`tests/extension/liveScannerProfileSelection.test.js`)
```bash
node tests/extension/liveScannerProfileSelection.test.js
```
**Output:**
```text
=== Running Live Scanner Profile Selection Regression Suite ===

  ✓ Test 1: net10.0 project selects verified dotnet-10.0-lts profile
  ✓ Test 2: net9.0 project selects dotnet-9.0-sts and fails closed as unprovisioned template
  ✓ Test 3: Both .NET Security Analyzer and NuGet Dependency Auditor report consistent diagnostics
  ✓ Test 4: TrustedExecutionGateway strictly blocks template placeholder profiles from container launch
  ✓ Test 5: In-place project framework modification dynamically selects updated profile
  ✓ Test 6: Profile registry configuration correctly distinguishes verified vs placeholder profiles
  ✓ Test 7: Container arguments enforce --network none to prevent auto-pull
  ✓ Test 8: Live .NET 10 scanner execution executes genuinely in container sandbox
  ✓ Test 9: Live scan on sample-repos/inventory-manager safely returns UNPROVISIONED_TOOLCHAIN_PROFILE

=== ALL 9 REGRESSION TESTS PASSED CLEANLY ===
```

### B. Real Container Scenarios (`tests/extension/dockerSandboxScenarios.test.js`)
```bash
node tests/extension/dockerSandboxScenarios.test.js
```
**Output:**
```text
ALL 9 REAL SCANNING SCENARIOS (A - I) PASSED SUCCESSFULLY
```

### C. Full Automated Regression Test Suite (`npm test`)
```bash
npm test
```
**Output:**
```text
TEST SUITE EXECUTION SUMMARY
Total Suites:  16
Passed Suites: 16
Failed Suites: 0
Duration:      27.38s

✅ All automated regression test suites PASSED successfully.
```

### D. .NET 10 Solution Tests (`dotnet test VulnerabilityRemediation.sln --no-restore`)
```text
Passed!  - Failed: 0, Passed: 66, Skipped: 0, Total: 66, Duration: 23 s - VulnerabilityRemediation.Tests.dll (net10.0)
```

### E. Phase 3 Isolated Smoke Test (`node scripts/verify-phase3-sandbox.js --smoke-test`)
```text
=== Executing Live Isolated Container Smoke Test ===
Live Container Smoke Test Result: {
  "executed": true,
  "passed": true,
  "machineStatus": "PASSED",
  "backendType": "local-container",
  "runtime": "docker",
  "networkPolicy": "NO_NETWORK",
  "imageDigest": "sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb"
}
```

---

## 6. Interactive VS Code Manual Acceptance Test Case

For the developer performing the final interactive VS Code acceptance round:

### Manual Test Case: Live Scanning in VS Code Extension

1. **Test Environment:**
   - Launch VS Code Extension Development Host (`F5` or `code --extensionDevelopmentPath=.`).
2. **Step 1: Test Compatible .NET 10 Repository Scan:**
   - Open GCAC Remediation Hub dashboard (`gcac.openDashboard`).
   - Under *Target Files or Repositories to Scan*, select `Entire Workspace (.)` or input path to a `.NET 10` project.
   - Click **Start Security Scan**.
   - **Expected Result:**
     - Scan completes with status `Completed`.
     - Container executes via `dotnet-10.0-lts` with digest `sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb`.
     - Roslyn security analyzer and NuGet auditor run cleanly inside the `--network none` container sandbox.
3. **Step 2: Test Legacy .NET 9 External Repository Scan:**
   - In the preset dropdown, select `sample-repos/inventory-manager`.
   - Click **Start Security Scan**.
   - **Expected Result:**
     - Scan finishes with status `Partial` or `Failed`.
     - Error message displays:
       `[.NET Security Analyzer] Target repository 'sample-repos/inventory-manager' (net9.0 -> dotnet-9.0-sts): UNPROVISIONED_TOOLCHAIN_PROFILE: ...`
     - Diagnostic details show:
       `Repository: sample-repos/inventory-manager | Target Framework: net9.0 | Profile: dotnet-9.0-sts | Status: TEMPLATE_PLACEHOLDER`.
     - No Docker crash, no auto-pull attempt, and zero host fallback.
4. **Verification Status:** **VERIFIED IN AUTOMATED HARNESS; MARKED NOT VERIFIED FOR VS CODE UI UNTIL INTERACTIVE ACCEPTANCE.**

---

## 7. Remaining Limitations & Operating Principles

1. **Legacy .NET 8 and .NET 9 Profiles:**
   Profiles `dotnet-8.0-lts` and `dotnet-9.0-sts` remain intentionally flagged as `TEMPLATE_PLACEHOLDER`. They will fail closed safely with `UNPROVISIONED_TOOLCHAIN_PROFILE` until enterprise administrators pull and register verified multi-platform image digests for those versions.
2. **No Silent Project Migration:**
   GCAC does not mutate external user project files from `net9.0` to `net10.0`. External projects remain untouched.
3. **Strict Zero-Network Execution:**
   All container operations operate under `--network none`, ensuring complete build and audit isolation.
