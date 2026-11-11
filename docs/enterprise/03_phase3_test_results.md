# Phase 3 Test Results & Empirical Verification Ledger

**Document ID:** GCAC-ENT-PH3-TESTS  
**Date:** 2026-11-11  
**Host Under Test:** Windows 11 (`win32` / `x64`, `10.0.26200`), `.NET SDK 9.0.317`, Node.js `v24.18.0`, Git `2.55.0.windows.3`

## 1. Execution Summary

| Stack | Command | Result | Total Cases / Suites | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **JS Syntax** | `Get-ChildItem ... node --check` | **PASS** | All `.js` in `extension/`, `scripts/`, `tests/extension/` | Executed after final code edits |
| **VS Code Extension JS** | `npm test` | **PASS** | **12 / 12 Suites** (0 failed) | Includes Suites 1–11 regression + Suite 12 Phase 3 Security |
| **.NET Build** | `dotnet build VulnerabilityRemediation.sln --no-restore -p:UseSharedCompilation=false /nr:false` | **PASS** | **7/7 Projects** (0 warnings, 0 errors) | Full solution verified including `ContainerSandboxBackend.cs` |
| **.NET Unit & Security Tests** | `dotnet test tests/VulnerabilityRemediation.Tests/VulnerabilityRemediation.Tests.csproj --no-build -p:UseSharedCompilation=false /nr:false` | **PASS** | **62 / 62 Passed** (0 failed, 0 skipped) | 55 existing + 7 Phase 3 security tests |
| **Phase 3 CLI Probe** | `node scripts/verify-phase3-sandbox.js` | **PASS (Fail-Closed)** | `SANDBOX_UNAVAILABLE`, `nuget=true, npm=true` | Confirms lockfiles + profile hashes verified; G3-06 & G3-07 open |
| **Live Container Isolation** | `discoverEnvironment()` / `--smoke-test` | **`NOT VERIFIED`** | Host probe verified `SANDBOX_UNAVAILABLE` | Docker, Podman & WSL2 absent; not auto-installed |

---

## 2. Phase 3 Negative & Security Test Coverage Breakdown

### 2.1 JavaScript Suite 12 (`tests/extension/phase3SandboxSecurity.test.js`)
- **Group 1:** `SANDBOX_UNAVAILABLE` detection on real host (`discoverEnvironment`), rejection of Docker Windows container mode (`OSType = windows`), fail-closed `executeRealTestRunner` with zero silent host `dotnet` execution, and fail-closed `EphemeralCiRunnerBackend`.
- **Group 2:** Credential-free workspace staging (`WorkspaceStagingManager`), exclusion of `.env`, `.git`, `vulnerability/`, `remediation-output/`, synthetic outside secret fixture verification, `buildSanitizedContainerEnv` credential rejection, `ContainerSandboxBackend.buildContainerRunArgs` security baseline flags (`--read-only`, `--cap-drop=ALL`, `no-new-privileges:true`, `--network none`, zero `docker.sock`/`--privileged`/home/workspace mounts), and symlink escape rejection (`StagingContainmentError`).
- **Group 3:** Default `NO_NETWORK` policy, rejection of `APPROVED_INTERNAL_MIRROR_ONLY` for test ops, loopback/IMDS (`127.0.0.1`, `169.254.169.254`, `host.docker.internal`) rejection, `nuget.config` `ClearTextPassword` rejection, offline missing dependencies (`NETSDK1004`, `ENOTCACHED`) mapped to `OUTCOME_STATUS.COULD_NOT_RUN`, and mocked offline `PASSED` execution.
- **Group 4:** SHA-256 profile tamper rejection (`TOOLCHAIN_PROFILE_TAMPERED`), unpinned image tag rejection (`UNPINNED_TOOLCHAIN_IMAGE`), EOL SDK `6.0.400` in `global.json` rejection, Gradle `build.gradle` rejection, `TrustedExecutionGateway` free-form command, shell injection (`; whoami`), path traversal (`../../etc/passwd`), multi-finding SEC-02 (`ALL`), untrusted `ContentInjectionScreen` blocking, and audit log verification.
- **Group 5:** Sandbox `TIMED_OUT` + guaranteed cleanup, `CANCELLED` propagation, crash/reload orphan recovery (`RUNNING` -> `FAILED`), `DotnetSecurityScanner` & `NuGetAuditScanner` fail-closed `SANDBOX_UNAVAILABLE`, CycloneDX 1.5 manifest SBOM generation (`externalSbomCliStatus = NOT_AVAILABLE`), fail-closed `RemediationEngine.executePipeline` at Stage 3 without sandbox, and `persistArtifacts` writing `sandbox-execution.json` + `sbom.cdx.json`.
- **Group 6:** Strict Webview CSP zero-inline-style assertion on `dashboard.html` & `dashboard.js`, `ALLOWED_IPC_COMMANDS` verification (`getSandboxStatus`, `recoverSandboxInstances`), `NuGetAuditScanner` dispatching `OPERATION_TYPES.NUGET_AUDIT` (`dotnet list package --vulnerable --include-transitive`) and failing closed on non-zero exit, nested `packages.lock.json` discovery + SBOM extraction, `ScanController`/`ReScanVerifier` sandbox forwarding for `.cs` target files, fail-closed `runLiveContainerSmokeTest`, and live container availability status (`NOT VERIFIED — SANDBOX_UNAVAILABLE`).

### 2.2 .NET Phase 3 Security Suite (`tests/VulnerabilityRemediation.Tests/SecurityTests/Phase3SandboxSecurityTests.cs`)
1. `P3_EnvironmentDiscovery_WhenNoDockerOrPodman_ReturnsSandboxUnavailable`
2. `P3_EnvironmentDiscovery_DockerWindowsContainerMode_NotAccepted`
3. `P3_ToolchainProfileRegistry_VerifiesAuthenticManifestAndBlocksTamper`
4. `P3_TrustedExecutionGateway_RejectsFreeformInjectionMultiFindingAndCredentialLeaks`
5. `P3_TestValidationAgent_BlocksCodeProjectsWhenSandboxUnavailable_WithoutHostFallback`
6. `P3_TestValidationAgent_HandlesPassedTimeoutCancelledAndMissingDepsFromSandbox`
7. `P3_ContainerSandboxBackend_EnforcesHardenedArgsStagingExclusionsAndFailClosed`

