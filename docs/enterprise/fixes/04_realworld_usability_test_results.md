# GCAC Real-World Usability Fixes — Verification & Test Results

**Document ID**: `GCAC-FIX-04-TESTS`  
**Verification Scope**: Automated JavaScript regression suites (`tests/extension/run-all-tests.js`) and .NET xUnit suites (`VulnerabilityRemediation.sln`) executed after final code changes.

---

## 1. JavaScript Extension & Security Regression Suite Results

**Command Executed**:
```powershell
node tests/extension/run-all-tests.js
```

**Observed Summary**:
- **Total Suites**: 13
- **Passed Suites**: 13
- **Failed Suites**: 0
- **Duration**: 24.25s
- **Exit Code**: 0

| # | Suite Name | Outcome | Notes |
|---|---|---|---|
| 1 | CSV Parser & Row Isolation | PASS | Verified 17 CSV records, RFC 4180 parsing, and target-row isolation |
| 2 | Report Parser & Evidence Discovery | PASS | Verified ID normalization, missing-report handling, null missing timings, and catalog discovery |
| 3 | Security Containment & Webview Hardening | PASS | Verified canonical path containment (with Windows short-path fix), IPC allowlist, XSS defense, and strict CSP |
| 4 | Deterministic Test Runner Execution | PASS | Verified executable allowlist, `detectRunner` tech-aware selection (`dotnet`, `mvn`, `npm`), and output secret redaction |
| 5 | Workflow State Machine & Approval Gates | PASS | Verified bypass blocking, concurrency locks, snapshots/rollback, and `run-state.json` persistence |
| 6 | Dashboard Metrics & Quality Accuracy | PASS | Verified exact KPIs and genuine quality metrics |
| 7 | Scanner Adapters & Controller Execution | PASS | Verified Secrets (`2` findings in isolated fixture), Roslyn SARIF, NuGet Audit, CodeQL SARIF/missing binary, and progress events |
| 8 | Normalized Findings Model & Storage | PASS | Verified fingerprinting, CSV compatibility mapping, deduplication, status preservation, and non-destructive `getCombinedFindings` |
| 9 | Post-Remediation Re-Scanning & Verification | PASS | Verified `STILL PRESENT`, `RESOLVED`, regression detection, `NOT VERIFIED`, and Stage 6 integration |
| 10 | Phase 1 P0 Security Containment & Core Integrity | PASS | Verified P0-A through P0-F + mocked VS Code Extension Host activation (`@vulnerability-orchestrator`, `gcac.scanRepository`, `launchCopilot`) |
| 11 | Phase 2 Trust Controls & Secure Remediation Governance | PASS | Verified Groups A–H (worktree isolation, diff-bound approval, scope/tamper gates, Stage 5 restart recovery, evidence SHA-256 ledger) |
| 12 | Phase 3 Execution Isolation, Approved Toolchains & Supply Chain Security | PASS (with host-env skip on G3-06) | Groups 1–6 verified with mock backends; live container smoke test `G3-06` skipped cleanly as `SANDBOX_UNAVAILABLE` because Docker/Podman is not installed/running on host |
| 13 | Real-World Usability, Scan Accuracy, Portability & Retry (`tests/extension/realWorldUsability.test.js`) | PASS | Verified all newly added Block A, B, C, D, E, and G automated assertions |

### Coverage Details in [`tests/extension/realWorldUsability.test.js`](../../tests/extension/realWorldUsability.test.js)
- **Block A**: Empty repository, empty source files, dependency-free `.csproj` (`hasDotnetPackageDependencies === false`), uninitialized `160000` gitlink submodules (never climbing to parent `.sln`), unsupported Python repo classification, failing-scanner `unverifiedCoverage: true`, cross-repo `isHistorical` isolation between disposable Repo Alpha & Repo Beta, false-positive comment/placeholder suppression, explicit `HEURISTIC_PATTERN` / `Low` labeling for `SEC-006`, NuGet `fixedVersion === ''` non-fabrication, and `ReScanVerifier` marking emptied targets `INCONCLUSIVE`.
- **Block B**: Disposable external Git repos outside GCAC (`.NET` with spaces in directory path on `master` branch preserving uncommitted WIP, Java/Maven repo with `pom.xml`, unauthorized external repo blocking, restricted-mode scan rejection, deterministic `LOCAL-<hash>` identity without `APP-*` invention, and `resolveSourceFilePath` within authorized roots).
- **Block C**: Reproduced exact `SEC-02 Blocked: Finding 'SCAN-NUGETA-003' has missing or ambiguous Application_Number/Repository metadata` block; confirmed `buildCopilotRemediationPrompt` rejects unmapped findings and never emits `using scan ""` or GCAC fallback; bound explicit local repository mapping and verified valid Copilot prompts across all 4 scanner IDs (`secrets-config`, `dotnet-security`, `nuget-audit`, `codeql`).
- **Block D**: Verified multi-project `parseDotnetOutput`, Surefire `Results:` `parseMavenOutput`, Node `ℹ` reporter `parseNpmOutput`; exercised all 10 failure/outcome categories through `TrustedExecutionGateway` (`PASS`, `TESTS_FAILED` baseline vs post-fix, `NO_TESTS_DISCOVERED`, `BUILD_FAILED`, `RESTORE_FAILED`, `TEST_TOOL_MISSING`, `TIMED_OUT`, `CANCELLED`, `PARSE_FAILED`, `SANDBOX_UNAVAILABLE` fail-closed); verified `reportParser.inferStageStatuses` and `dashboard.js` `computeTestEvidenceSummary`.
- **Block E**: Verified Stage 3 `TIMED_OUT` persistence, `reconcileInterruptedRuns()` reload recovery (`INTERRUPTED_BY_RELOAD`), exponential backoff check (`rejectDuringBackoff`), Stage 3 `retryStage` preserving Stages 1–2 and archiving prior attempt artifacts under `attempts/`, Stage 6 `TESTS_FAILED` blocking blind retry, `reviseFix()` rolling back and pausing at Stage 4 requiring fresh diff-bound approval, active/untrusted retry UI disable state (`buildRetryUiState`), and bounded retry limits (`RETRY_LIMIT_EXCEEDED`).
- **Block G**: Verified `dashboard.html` contains zero inline `style=` attributes, `dashboard.js` contains zero references to undefined `testStatus`, and wires `btnReviseFix` / `btnMapFindingRepository`.

---

## 2. .NET Build & xUnit Test Suite Results

**Commands Executed**:
```powershell
dotnet build VulnerabilityRemediation.sln --no-restore
dotnet test VulnerabilityRemediation.sln --no-build
```

**Observed Summary**:
- **Build**: Succeeded (`0 Warning(s)`, `0 Error(s)`) across Domain, Excel, Persistence, Repository, Cli, VulnerabilityDataMcp, and Tests projects.
- **Test Run**: `Passed! - Failed: 0, Passed: 66, Skipped: 0, Total: 66` (`Duration: 1 m 15 s`).

### New .NET Tests Added in [`tests/VulnerabilityRemediation.Tests/RealWorldUsabilityTests.cs`](../../tests/VulnerabilityRemediation.Tests/RealWorldUsabilityTests.cs)
1. `RepositoryRegistry_LocalRegistration_AssignsDeterministicLocalIdAndLoadsLocalRegistryFile`: Verifies deterministic `LOCAL-<hash>` assignment and `.gcac/local-repositories.json` loading without enterprise ID invention.
2. `WorkspaceManager_ExternalRepoOnMasterWithSpaces_PreparesCleanLocalWorkspace`: Verifies local Git clone & workspace preparation on an external repo with spaces using `master` branch while leaving live uncommitted `WIP.txt` untouched and keeping `IsPushed == false`.
3. `TestValidationAgent_MultiProjectDotnetAndMavenResultsAggregate_AccuratelySumsCounts`: Verifies multi-project VSTest aggregation and Maven Surefire `Results:` preference.
4. `McpServer_ScannedFindingWithoutMetadata_EnforcesSec02Block`: Spawns `VulnerabilityDataMcp` with `output/scans/findings.json` containing `SCAN-NUGETA-003` lacking metadata and confirms `get_remediation_context` fails closed with `"isError":true`, `SEC-02 Blocked`, and `REPOSITORY_MAPPING_REQUIRED`.

---

## 3. Environment & Verification Limits Observed
- Live Phase 3 Linux container execution (`G3-06`) did not run on this workstation because no container runtime (Docker/Podman in Linux container mode) is installed/running (`SANDBOX_UNAVAILABLE`). Container execution paths remain verified via `ExecutionBackend` contract doubles and unit/integration suites.
- Interactive VS Code Extension Development Host UI clicks (`showOpenDialog`, Chat Participant rendering, CSS light/dark theme visual check) cannot be clicked automatically in headless test execution and are itemized in `04_realworld_usability_readiness.md`.

