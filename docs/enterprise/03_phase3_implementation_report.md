# Phase 3 Implementation Report — Secure Execution Isolation & Supply Chain Security

**Document ID:** GCAC-ENT-PH3-IMPL  
**Date:** 2026-11-11  
**Scope:** Phases 3A through 3K across VS Code Extension (`extension/`), Verification CLI (`scripts/`), and `.NET 9` (`src/`, `mcp/`, `tests/`)

## 1. Summary of Architecture Changes

Phase 3 eliminates uncontained direct host execution of untrusted repository builds, tests, and build-backed security scanners by routing them through a typed, policy-enforcing **`TrustedExecutionGateway`** backed by an abstract **`ExecutionBackend`** / **`IExecutionBackend`**.

When no approved container runtime (Docker Linux containers mode or Podman) is reachable—as verified on the current Windows host—execution **fails closed (`SANDBOX_UNAVAILABLE` / `OutcomeStatus.BLOCKED`)** with zero silent fallback to host shell execution.

---

## 2. Implemented Modules & Integrations

### 2.1 VS Code Extension Stack (`extension/`)
| Subphase | File Path | Key Symbols & Capabilities |
| :--- | :--- | :--- |
| 3A | `extension/sandbox/environmentDiscovery.js` | `SANDBOX_READINESS`, `discoverEnvironment`, probes OS/arch, Docker/Podman/WSL2, `.NET`/Java/Maven/Node/npm/Git, CodeQL, external SBOM CLIs, and workspace lockfiles/CI configs. |
| 3A | `extension/sandbox/executionBackend.js` | `ExecutionBackend` (7-method contract: `checkAvailability`, `validatePolicy`, `prepareEnvironment`, `executeApprovedOperation`, `cancelOperation`, `collectEvidence`, `cleanup`), `EphemeralCiRunnerBackend` (fail-closed adapter stub), `selectExecutionBackend`. |
| 3B | `extension/sandbox/trustedExecutionGateway.js` | `TrustedExecutionGateway`, `EXECUTION_POLICY_VERSION` (`GCAC-PH3-GW-1.0`), `OPERATION_TYPES` (`DOTNET_BUILD`, `DOTNET_TEST`, `MAVEN_COMPILE`, `MAVEN_TEST`, `NPM_TEST`, `SECURITY_SCAN`, `TARGETED_RESCAN`, `NUGET_AUDIT`, `SBOM_GENERATION`), schema + single-finding SEC-02 checks, metacharacter blocking, `ContentInjectionScreen` output screening, secret redaction, cache/env forwarding, audit log (`getAuditDecisions`). |
| 3C | `extension/sandbox/workspaceStaging.js` | `WorkspaceStagingManager`, `StagingContainmentError`, `buildSanitizedContainerEnv`: credential-free disposable snapshot, symlink escape blocking, excludes `.git`, `.env`, `vulnerability/`, `remediation-output/`, `output/`, `*.pem`/`*.pfx`; bounded cleanup. |
| 3C | `extension/sandbox/containerSandboxBackend.js` | `ContainerSandboxBackend`, `isPinnedImageReference`, `buildContainerRunArgs`: enforces `@sha256:` image digests, `--user 65532:65532`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only`, `--tmpfs`, CPU/memory/PID/timeout quotas, `--network none`, no daemon sockets, no host home/workspace mounts. |
| 3D | `extension/sandbox/networkPolicy.js` | `NETWORK_POLICY_MODES`, `evaluateNetworkPolicy`, `inspectRepositoryFeedConfigs`, `isHostLoopbackOrMetadataUrl`: defaults strictly to `NO_NETWORK`; blocks unapproved public registries, host loopback (`127.0.0.1`), cloud metadata (`169.254.169.254`), and embedded feed credentials (`ClearTextPassword`, `_authToken`). |
| 3E | `extension/config/approved-toolchain-profiles.json`<br>`extension/sandbox/toolchainProfiles.js`<br>`scripts/verify-phase3-sandbox.js` | Declarative SHA-256 tamper-checked registry (`dotnet-8.0-lts`, `dotnet-9.0-sts`, `java-17-maven`, `node-22-lts`) with `NUGET_AUDIT` command template and `digestStatus` (`TEMPLATE_PLACEHOLDER` vs `VERIFIED_IMAGE_DIGEST`); inspects `global.json`, `*.csproj`, `pom.xml`, `package.json`; non-auto-installing CLI helper for readiness verification, local `RepoDigests` pinning (`--pin-from-local-images`), and live `--smoke-test`. |
| 3F | `extension/sandbox/dependencyGovernance.js`<br>`package-lock.json`<br>`*/packages.lock.json` | Offline `--no-restore`/`-o`/`--offline`, discovers root & nested `packages.lock.json` across solution projects, commits root `package-lock.json` + 7 project `packages.lock.json` files generated offline, converts missing offline dependencies (`NETSDK1004`, `NU1101`, `ENOTCACHED`) to `COULD_NOT_RUN`. |
| 3H | `extension/sandbox/sbomGenerator.js` | `generateSupplyChainSbom`, `collectComponentsFromRepo`: offline CycloneDX 1.5 JSON manifest extraction (`sbom.cdx.json`) across root & nested `packages.lock.json`, keeps SBOM status distinct from build/test validation, reports `NOT_AVAILABLE` when external SBOM CLIs are absent. |
| 3I | `extension/sandbox/sandboxLifecycleManager.js` | `SandboxLifecycleManager`: persists instance states (`PENDING`..`COMPLETED`/`FAILED`/`TIMED_OUT`/`CANCELLED`/`BLOCKED`/`CLEANUP_FAILED`), crash/reload recovery (`recoverOrphanedInstances`), GCAC-label-only container cleanup (`label=gcac.managed=true`). |
| 3G | `extension/outcomeContract.js`<br>`extension/testRunner.js`<br>`extension/scanning/dotnetProjectLocator.js`<br>`extension/scanning/scanController.js`<br>`extension/scanning/adapters/dotnetSecurityScanner.js`<br>`extension/scanning/adapters/nugetAuditScanner.js`<br>`extension/scanning/adapters/secretsConfigScanner.js`<br>`extension/scanning/adapters/codeqlScanner.js`<br>`extension/scanning/reScanVerifier.js`<br>`extension/remediationEngine.js`<br>`extension/reportParser.js` | Added `CANCELLED`/`TIMED_OUT` canonical outcomes; routed `executeRealTestRunner`, `DotnetSecurityScanner.scan`, and `NuGetAuditScanner.scan` (`NUGET_AUDIT` -> `dotnet list package --vulnerable --include-transitive`) through `TrustedExecutionGateway` (removed host `spawn()` fallbacks); added `resolveDotnetProjectFile` for `.cs` re-scans, sandbox context forwarding in `ScanController`/`ReScanVerifier`, explicit `READ_ONLY_STATIC_POLICY` tagging on static adapters, and `sandbox-execution.json` + `sbom.cdx.json` persistence in `RemediationEngine`. |
| 3J | `extension/extension.js`<br>`extension/media/dashboard.html`<br>`extension/media/dashboard.js`<br>`extension/media/dashboard.css`<br>`scripts/preview-dashboard.js` | Added `getSandboxStatus` & `recoverSandboxInstances` IPC handlers, crash recovery on activation, theme-aware Settings sandbox governance card (`SANDBOX READY` / `SANDBOX UNAVAILABLE` + `digestStatus` badges), Active Runs backend/network strip, Test Evidence sandbox/SBOM summary (strictly CSP-compliant, zero inline `style=` attributes), and `/api/sandbox-status` preview route. |

### 2.2 .NET Stack (`src/`)
| File Path | Key Symbols & Capabilities |
| :--- | :--- |
| `src/VulnerabilityRemediation.Domain/Models/OutcomeContract.cs` | Added `CANCELLED`, `TIMED_OUT` to `OutcomeStatus`, updated `ToLegacyVerificationDisplay` and `OutcomeContractEvaluator.Evaluate`. |
| `src/VulnerabilityRemediation.Domain/Models/TestExecutionResult.cs` | Added Phase 3 provenance metadata properties (`RunId`, `InstanceId`, `OperationId`, `SandboxStatus`, `BackendType`, `ToolchainProfileId`, `ToolchainProfileHash`, `ImageDigest`, `NetworkPolicy`, `DependencyStatus`, `TimedOut`, `Cancelled`, `SandboxLimitationNote`). |
| `src/VulnerabilityRemediation.Domain/Security/SandboxExecutionContracts.cs` | Added `SandboxLifecycleState`, `SandboxOperationType` (including `NUGET_AUDIT`), `SandboxReadinessStatus`, `ExecutionRequest`, `PreparedSandboxEnvironment` (`ImageRef`, `Executable`, `ApprovedArguments`), `SandboxExecutionEvidence`, and `IExecutionBackend`. |
| `src/VulnerabilityRemediation.Repository/Sandbox/EnvironmentDiscoveryService.cs` | Host Docker/Podman/WSL2/.NET/Java/Maven/Node/Git/SBOM discovery without auto-installation or silent host fallback. |
| `src/VulnerabilityRemediation.Repository/Sandbox/ToolchainProfileRegistry.cs` | Canonical JSON SHA-256 verification compatible byte-for-byte with JS `approved-toolchain-profiles.json`; validates `@sha256:` image digests, exposes `DigestStatus` / `IsTemplateDigest`, and rejects tampered manifests / EOL SDKs / unsupported stacks. |
| `src/VulnerabilityRemediation.Repository/Sandbox/ContainerSandboxBackend.cs` | Hardened .NET `IExecutionBackend` (Docker Linux mode / Podman) enforcing credential-free staging, reparse/symlink rejection, `@sha256:` pinned image inspection, `--user 65532:65532`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only`, `--network none`, CPU/memory/PID/timeout quotas, and owned-container cleanup. |
| `src/VulnerabilityRemediation.Repository/Sandbox/TrustedExecutionGateway.cs` | Defaults to `ContainerSandboxBackend` (plus `FailClosedDiscoveryBackend` for discovery-only enforcement), `TrustedExecutionGateway`, `GenerateSupplyChainSbomJson`, `RedactSensitiveOutput`, request validation, feed secret checks, and missing-dependency `COULD_NOT_RUN` mapping. |
| `src/VulnerabilityRemediation.Repository/Agents/TestValidationAgent.cs` | Replaced direct host `Process.Start("dotnet"/"mvn", ...)` (`RunProcess` removed) with `TrustedExecutionGateway.Execute(req)` (preserving `UNTESTED` for non-code repos). |
| `src/VulnerabilityRemediation.Repository/RemediationOrchestratorEngine.cs`<br>`src/VulnerabilityRemediation.Repository/EvidenceGeneratorService.cs` | Handled `TIMED_OUT` & `CANCELLED` in gate checks; persisted Phase 3 sandbox metadata in `validation.json`, `remediation-report.md`, and `sbom.cdx.json`. |

---

## 3. Preserved Guarantees & Exclusions

- Preserved 100% of Phase 1 & Phase 2 controls: Webview CSP, single-finding SEC-02 isolation, diff-bound Gate 4 approval, Git worktree isolation, `OutboundContextGate`, immutable scanner severity, SHA-256 `integrity-manifest.json`, and working Copilot Chat handoff.
- Added zero third-party AI APIs, zero new MCP dependencies, zero auto-push/PR functionality, and zero host shell fallbacks.

