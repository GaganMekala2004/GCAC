# Phase 3 Security Verification & Boundary Analysis

**Document ID:** GCAC-ENT-PH3-SEC  
**Date:** 2026-11-11

## 1. Threat Controls Verification Matrix

| Security Control Domain | Implemented Enforcement Mechanism | Empirical Verification Method | Status |
| :--- | :--- | :--- | :--- |
| **No Silent Host-Shell Fallback** | Removed host `spawn()` from `extension/testRunner.js`, `DotnetSecurityScanner`, `NuGetAuditScanner`; removed `RunProcess` from `TestValidationAgent.cs`; returns `SANDBOX_UNAVAILABLE` (`BLOCKED`). | Verified via JS Group 1 & 5, and .NET `P3_TestValidationAgent_BlocksCodeProjectsWhenSandboxUnavailable_WithoutHostFallback` on real host lacking Docker/Podman. | **VERIFIED (Code + Policy + Mocked/Host Probe)** |
| **Typed Execution Gateway (3B)** | Rejects `rawCommand`/`shellCommand`, unknown ops, mismatched `policyVersion`, path traversal (`..`, absolute), multi-finding `ALL` (SEC-02), and shell metacharacters. Records ALLOW/DENY audit entries. | JS Group 4 + .NET `P3_TrustedExecutionGateway_RejectsFreeformInjectionMultiFindingAndCredentialLeaks`. | **VERIFIED** |
| **Credential-Free Staging & Env (3C)** | `WorkspaceStagingManager` copies minimized workspace excluding `.git`, `.env`, `vulnerability/`, `remediation-output/`, `output/`, keys/certs; blocks symlinks escaping root; strips `GITHUB_TOKEN`, `AWS_*`, `SSH_AUTH_SOCK`, etc. | JS Group 2 (`stageWorkspace`, `buildSanitizedContainerEnv`, `validatePolicy`) with synthetic outside secrets. | **VERIFIED (Policy + Staging + Args)** |
| **Container Hardening Args (3C)** | Requires `@sha256:` pinned `imageRef`, `--user 65532:65532`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only`, `--tmpfs`, `--memory`, `--cpus`, `--pids-limit`; blocks `--privileged`, host namespaces, `docker.sock`, and original repo mounts across both JS and .NET `ContainerSandboxBackend`. | JS Group 2 (`ContainerSandboxBackend.buildContainerRunArgs` & `validatePolicy`) + .NET `P3_ContainerSandboxBackend_EnforcesHardenedArgsStagingExclusionsAndFailClosed`. Live container kernel/namespace execution on daemon: **NOT VERIFIED** (`SANDBOX_UNAVAILABLE`). | **PARTIAL (`NOT VERIFIED` on Live Runtime)** |
| **Network Egress & Feed Sec (3D)** | Defaults to `NO_NETWORK` (`--network none`); blocks `APPROVED_INTERNAL_MIRROR_ONLY` for build/test ops, loopback/metadata URLs (`127.0.0.1`, `169.254.169.254`, `host.docker.internal`), and embedded credentials (`ClearTextPassword`, `_authToken`). | JS Group 3 + .NET Gateway tests. | **VERIFIED (Policy + Mocked Sandbox)** |
| **Toolchain Digest & Tamper Integrity (3E)** | Canonical JSON SHA-256 (`profileSha256`) verified in both Node.js and .NET; rejects modified executables, unpinned tags, EOL `.NET 6` `global.json`, and unapproved Gradle/Ant/Python repos. | JS Group 4 + .NET `P3_ToolchainProfileRegistry_VerifiesAuthenticManifestAndBlocksTamper`. | **VERIFIED** |
| **Dependency Failure Honesty (3F)** | Missing offline assets (`NETSDK1004`, `NU1101`, `ENOTCACHED`) never pass; mapped strictly to `COULD_NOT_RUN`. | JS Group 3 + .NET `P3_TestValidationAgent_HandlesPassedTimeoutCancelledAndMissingDepsFromSandbox`. | **VERIFIED** |
| **Timeout, Cancel & Orphan Recovery (3I)** | Timed out runs yield `TIMED_OUT`, cancelled runs yield `CANCELLED`, cleanup runs in `finally`; crash recovery marks stale instances `FAILED` without auto-restart. | JS Group 5 + .NET tests. | **VERIFIED** |
| **CSP / Webview Security (3J)** | Zero inline `style=` attributes across new Webview cards and evidence strips; strict IPC allowlist (`getSandboxStatus`, `recoverSandboxInstances`). | JS Suite 3, Suite 10 P0-F, Suite 12 Group 6. | **VERIFIED** |

---

## 2. Explicit Uncontrolled / Out-of-Scope Path Disclosures

1. **GitHub Copilot Chat Native Tools:**
   `TrustedExecutionGateway` controls all VS Code Extension Host and `.NET` CLI build, test, and build-backed scanner subprocesses. It **does NOT intercept** native interactive terminal/filesystem tools invoked directly by GitHub Copilot Chat inside a developer's interactive chat session.
2. **Read-Only Static Scanners (`secrets-config`, `codeql --build-mode=none`):**
   Static non-build scanners run under `READ_ONLY_STATIC_POLICY` on the host file tree / CodeQL no-build database mode rather than container build execution, and `ReScanVerifier` explicitly tags each verification result with its `executionPolicy`.
3. **Live Container Daemon Isolation Verification (`NOT VERIFIED`):**
   Because neither Docker Engine (Linux containers mode), Podman, nor WSL2 is installed on this Windows workstation, real OS/kernel isolation inside a live running container (`--network=none` packet drop at kernel netns, UID/capability drop inside container PID 1) could **not** be executed and remains **`NOT VERIFIED`**.

