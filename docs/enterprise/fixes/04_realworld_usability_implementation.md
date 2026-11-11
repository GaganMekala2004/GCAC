# GCAC Real-World Usability, Scan Accuracy, Portability & Retry Implementation Report

**Document ID**: `GCAC-FIX-04-IMPL`  
**Scope**: Blocks A–G across Extension Host, Scanning Subsystem, Test Runner, Remediation Engine, Webview Dashboard, Preview Server, .NET Core/Repository Libraries, and MCP Server  

---

## 1. Confirmed Defects Reproduced & Root Causes Fixed

1. **False/Stale Findings & Uninitialized Submodule Walk-Up (Block A)**:
   - Uninitialized Git submodules / gitlinks (`sample-repos/*` stored as `160000` gitlinks in the parent repo) caused `dotnetProjectLocator.js` to climb out of empty directories into the parent GCAC root (`VulnerabilityRemediation.sln`), while `CodeQLScanner._detectLanguage` fell back blindly to `'csharp'`.
   - `SecretsConfigScanner` scanned empty/comment lines or hardcoded placeholder references, while `NuGetAuditScanner` could run on dependency-free `.csproj` files and parse lowercase vs camelCase advisory keys inconsistently.
   - `FindingsStore` stored findings across repositories without separating historical findings from other repositories (`isHistorical`), and colliding sequential IDs could overwrite across scans.
2. **Workspace Confinement Blocking External Repositories & Windows 8.3 Path Mismatch (Block B)**:
   - `extension/extension.js` and `extension/isolatedWorkspaceManager.js` strictly confined targets to `workspaceFolders[0]` via single-root `assertPathWithinWorkspace(..., currentWorkspaceRoot)`.
   - `assertPathWithinWorkspace` (`extension/pathUtils.js`) checked lexical `path.relative` before resolving canonical realpaths, breaking valid contained paths on Windows when `os.tmpdir()` used 8.3 short paths (`SAIGAN~1`) alongside canonical paths.
   - `agentConfigIntegrity.js` failed when scanning/remediating external Git repositories lacking `.github/agents/` in their workspace folder.
   - `.NET` `RepositoryWorkspaceManager` assumed `main` default branch on clone checkouts without falling back cleanly to valid active branches such as `master` on external repositories.
3. **Scan-to-Copilot Metadata Mapping & `using scan ""` (Block C)**:
   - `NormalizedFinding.toCsvCompatibleRecord()` (`extension/scanning/findingModel.js`) hardcoded `Application_Number: 'APP-SCAN-001'` and `Technology: 'dotnet'`.
   - Scanner adapters left `repository`, `repositoryRoot`, `applicationNumber`, and `canonicalRepositoryId` unset outside `sample-repos/`.
   - `extension.js` (`launchCopilot`) built `@vulnerability-orchestrator /remediate-vulnerability ... in repository "..." using scan ""` when `currentCsvPath` was empty, and fell back blindly to `currentWorkspaceRoot` when `finding.Repository` was empty.
   - `mcp/VulnerabilityDataMcp/Program.cs` (`GetOrImportFinding`) looked up only SQLite/Excel, missing findings from `output/scans/findings.json` such as `SCAN-NUGETA-003`.
4. **Test Execution Diagnostics & Active Webview Crash (Block D)**:
   - `extension/media/dashboard.js` had an active `ReferenceError: testStatus is not defined` inside `renderTestEvidenceView`.
   - `extension/testRunner.js` blindly fell back to `dotnet` in `detectRunner`, undercounted multi-project VSTest runs and Maven Surefire `Results:` aggregates, missed `node --test` `ℹ` reporter lines, and lost structured root-cause categories (`BUILD_FAILED`, `RESTORE_FAILED`, `TEST_TOOL_MISSING`, `NO_TESTS_DISCOVERED`, `PARSE_FAILED`, `SANDBOX_UNAVAILABLE`).
   - `extension/reportParser.js` (`inferStageStatuses`) emitted a generic `"Targeted unit tests failed (0 passed, 0 failed)."` message for failures including unexecuted or compilation errors.
5. **Non-Functional Retry Stage & State Loss (Block E)**:
   - `extension/media/dashboard.js` hardcoded `fromStage: 5` on `btnRetryStage`, hardcoded `'0 of 3'` retries, hardcoded `'Validation Failed at Stage 5 (Bench Testing)'`, and never disabled retry during active execution or ineligible failures.
   - `RemediationEngine._doExecutePipeline` lacked outer exception persistence into `run-state.json`, lacked bounded retry limits, backoff enforcement, attempt archiving, reload-interruption reconciliation, and a separate patch-revision path (`reviseFix`).

---

## 2. Implemented Changes by Component

### Repository Context & Containment
- **[`extension/repositoryContext.js`](../../extension/repositoryContext.js)**: Added canonical path resolution, sensitive OS/credential root blocking (`~/.ssh`, `~/.aws`, OS roots), `assertPathWithinAuthorizedRoots`, `isUninitializedGitSubmodule` (detecting empty `160000` gitlinks, `.gitmodules` entries, and broken `.git` pointers), bounded `discoverProjectManifests`, `inspectRepositoryTarget`, `computeCanonicalRepoId`, deterministic `computeLocalApplicationId` (`LOCAL-<8HEX>`), `RepositoryContextRegistry` (`config/repositories.json` + `.gcac/local-repositories.json`), and canonical contract `GCAC-FINDING-CTX-1.0` (`buildCanonicalFindingContext`, `validateFindingContextContract`).
- **[`extension/pathUtils.js`](../../extension/pathUtils.js)**: Updated `assertPathWithinWorkspace` (`resolveCanonicalWithExistingAncestor`) so Windows 8.3 short aliases match their canonical targets while traversal (`..`) and symlink escapes continue to be rejected.
- **[`extension/agentConfigIntegrity.js`](../../extension/agentConfigIntegrity.js)**: Scopes strict workspace `.github/` integrity check to workspaces that actually contain `.github/agents` or `.github/copilot-instructions.md`, verifying the GCAC installation's baseline `.github/` bundle otherwise.
- **[`extension/isolatedWorkspaceManager.js`](../../extension/isolatedWorkspaceManager.js)**: Added `authorizedRoots` / `setAuthorizedRoots()` support and `isUninitializedGitSubmodule` rejection.

### Scanning & Verification Accuracy
- **[`extension/scanning/dotnetProjectLocator.js`](../../extension/scanning/dotnetProjectLocator.js)**: Restricted directory target discovery to bounded downward search only (stopping ancestor climbs at `.git` or `workspaceRoot` on single-file targets); added `hasDotnetPackageDependencies`.
- **[`extension/scanning/findingModel.js`](../../extension/scanning/findingModel.js)**: Added `SCANNER_STATUS.NO_SCANNABLE_INPUTS`, `inferTechnologyFromFilePath`, provenance fields (`applicationNumber`, `repositoryRoot`, `canonicalRepositoryId`, `projectPath`, `detectionMethod`, `evidenceRef`, `packageName`, `currentVersion`, `fixedVersion`, `advisoryUrl`, `isHistorical`, `lastSeenScanId`, `contextSchemaVersion: 'GCAC-FINDING-CTX-1.0'`), mapped `'Detected'` -> `'Pending'` for CSV compatibility, and removed hardcoded `'APP-SCAN-001'` / `'dotnet'`.
- **[`extension/dataMinimization.js`](../../extension/dataMinimization.js)**: Expanded `ALLOWED_SINGLE_FINDING_FIELDS` with repository/scanner/package provenance fields while continuing to strip PII, ownership/manager metadata, and cloud/VM fields.
- **[`extension/scanning/findingsStore.js`](../../extension/scanning/findingsStore.js)**: Implemented repository-scoped deduplication (`repoKey::fingerprint`), collision-free `_nextUniqueFindingId`, automatic `isHistorical = true` marking for inactive prior-repository findings and absent findings on full scans, `updateFindingMapping`, and scoped filtering in `getFindings`.
- **Scanner Adapters**:
  - **[`secretsConfigScanner.js`](../../extension/scanning/adapters/secretsConfigScanner.js)**: Skips empty/whitespace files, comment lines, and placeholders; tightens `SEC-002`; marks `SEC-006` `Low`/`HEURISTIC_PATTERN`; returns `NO_SCANNABLE_INPUTS` on 0 non-empty inputs; canonicalizes authorized roots.
  - **[`dotnetSecurityScanner.js`](../../extension/scanning/adapters/dotnetSecurityScanner.js)**: Returns `NO_SCANNABLE_INPUTS` when no `.sln`/`.csproj` exists; propagates repository metadata.
  - **[`nugetAuditScanner.js`](../../extension/scanning/adapters/nugetAuditScanner.js)**: Returns `NO_SCANNABLE_INPUTS` when dependency manifests are missing or contain zero dependencies; handles `advisoryUrl` / `advisoryurl`; preserves `fixedVersion: ''` rather than fabricating fixed versions.
  - **[`codeqlScanner.js`](../../extension/scanning/adapters/codeqlScanner.js)**: Removes blind `'csharp'` fallback in `_detectLanguage`, checks `extensionRoot` for bundled CodeQL CLI, and returns `NO_SCANNABLE_INPUTS` on empty/unsupported targets.
- **[`extension/scanning/scanController.js`](../../extension/scanning/scanController.js)**: Integrates `authorizedRoots` + `RepositoryContextRegistry`, fast-paths uninitialized git submodules / empty targets for built-in scanners while preserving custom adapters, guarantees `isScanning` reset in `finally`, and flags `unverifiedCoverage: true` whenever any scanner fails.
- **[`extension/scanning/reScanVerifier.js`](../../extension/scanning/reScanVerifier.js)**: Maps `NO_SCANNABLE_INPUTS` on target file during post-fix re-scan to `'INCONCLUSIVE'` (`OUTCOME_STATUS.INCONCLUSIVE`), preventing empty-file false resolution.

### Test Runner, Report Parser & Remediation Engine
- **[`extension/testRunner.js`](../../extension/testRunner.js)**: Added `FAILURE_CATEGORIES`, `resolveRepoWorkingDirectory`, technology-aware disk-first `detectRunner`, multi-project VSTest / Maven Surefire `Results:` / Node TAP+spec parsing, `discoverTestReportArtifacts`, structured diagnostics (`stage`, `testPhase`, `failureCategory`, `rootError`, `countsKnown`, `testReportLocation`, `retryEligible`, `suggestedNextAction`), and preserved strict fail-closed `SANDBOX_UNAVAILABLE` (zero host-shell fallback).
- **[`extension/remediationEngine.js`](../../extension/remediationEngine.js)**:
  - Integrated `validateFindingContextContract`, `authorizedRoots`, and external absolute path resolution in `resolveSourceFile` and `_doExecutePipeline`.
  - Added per-attempt tracking (`attemptId`, `attemptNumber`, `attemptHistory`), artifact archival (`remediation-output/<id>/attempts/<attemptId>/`), `reconcileInterruptedRuns()`, outer exception failure persistence into `run-state.json`, explicit `evaluateRetryEligibility()`, bounded `retryStage()` (max retry limit, backoff, diff-bound approval verification, concurrency protection), and `reviseFix()` for genuine post-fix failures requiring a new patch and fresh Stage 4 approval.
- **[`extension/reportParser.js`](../../extension/reportParser.js)**: Loads `run-state.json`, `baseline-validation.json`, `re-scan-verification.json`, and `finding-context.json`; fixes `inferStageStatuses` so `BUILD_FAILED`, `RESTORE_FAILED`, `TIMED_OUT`, `CANCELLED`, `NO_TESTS_DISCOVERED`, `PARSE_FAILED`, and `NOT EXECUTED` surface honest diagnostic summaries rather than generic `(0 passed, 0 failed)`.

### Extension Host, Preview Server & Webview UI
- **[`extension/extension.js`](../../extension/extension.js)**: Added multi-root `workspaceFolders` awareness, external repo selection via `showOpenDialog` (guarded by Workspace Trust + sensitive path checks), repository-scoped `getCombinedFindings`, CodeQL CLI lookup against `extensionRootPath`, exported `buildCopilotRemediationPrompt` (blocking unmapped findings with `REPOSITORY_MAPPING_REQUIRED` and emitting real `scanId`/`scannerId`/`applicationId` instead of `using scan ""`), and IPC handlers `mapFindingRepository`, `retryStage` (eligibility-enforced), `reviseFix`, and `selectWorkspaceFolder`.
- **[`scripts/preview-dashboard.js`](../../scripts/preview-dashboard.js)**: Synced read-only preview endpoints (`/api/config`, `/api/vulnerabilities`, `/api/details`, `/api/copilot-prompt`, `/api/codeql-status`, `/api/source-code`) with repository-scoped filtering and fixed `ReScanVerifier(scanController)` constructor invocation.
- **[`extension/media/dashboard.html`](../../extension/media/dashboard.html)**, **[`dashboard.js`](../../extension/media/dashboard.js)**, **[`dashboard.css`](../../extension/media/dashboard.css)**:
  - Fixed `ReferenceError: testStatus is not defined` via `computeTestEvidenceSummary` and rendered full structured test diagnostics (`stage`, phase, command, repo tested, exit code, reliable counts vs `Unknown`, root diagnostic, report artifact, next action).
  - Added Target Context repo identity badge, multi-root workspace selector, inspector **Map Repository...** banner, heuristic detection provenance label, scan coverage warning banner (`No Scannable Inputs` / `Unsupported Repository` / partial coverage), real dynamic `failedStageTitle`, retry unavailability explanation, `Review Failure / Revise Fix` (`btnReviseFix`), quick diagnostic/log navigation buttons, real retry count (`X of N`), and attempt history list — maintaining strict CSP (zero inline `style=`) and light/dark/auto themes.

### .NET Repository, Validation & MCP Server
- **[`src/VulnerabilityRemediation.Repository/RepositoryRegistry.cs`](../../src/VulnerabilityRemediation.Repository/RepositoryRegistry.cs)**: Added deterministic `ComputeCanonicalRepoId` / `ComputeLocalApplicationId` (`LOCAL-<8HEX>`), `.gcac/local-repositories.json` loading (`LoadLocalRegistry`), `TryResolveByRepositoryPath`, and `RegisterLocalRepository`.
- **[`src/VulnerabilityRemediation.Repository/RepositoryWorkspaceManager.cs`](../../src/VulnerabilityRemediation.Repository/RepositoryWorkspaceManager.cs)**: Preserves valid existing local default branches (such as `master`) on external repositories when `main` is absent rather than failing branch verification.
- **[`src/VulnerabilityRemediation.Repository/Agents/TestValidationAgent.cs`](../../src/VulnerabilityRemediation.Repository/Agents/TestValidationAgent.cs)**: Sums multi-project VSTest counts (`ParseDotNetTestOutput`), prefers Maven Surefire `Results:` aggregates (`ParseMavenTestOutput`), and extracts concrete compiler/restore diagnostics into `FailureReason`.
- **[`mcp/VulnerabilityDataMcp/Program.cs`](../../mcp/VulnerabilityDataMcp/Program.cs)**: Loads `.gcac/local-repositories.json`, adds `TryLoadScannedFindingFromStore` (`output/scans/findings.json` lookup for scanned IDs such as `SCAN-NUGETA-003`), and enforces fail-closed SEC-02 metadata validation across `get_remediation_context` and `execute_remediation`.

