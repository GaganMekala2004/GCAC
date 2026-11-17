# GCAC — Enterprise Security Verification & Hardening Report

**Document ID:** `GCAC-SEC-06-2026-11`  
**Classification:** Enterprise Confidential / DevSecOps Security Assessment  
**Target Environment:** macOS Darwin (Apple Silicon arm64), Docker Engine 29.9.3, .NET 10.0.404 / 10.0.15  
**Final Determination:** **GO (Enterprise Production Sandbox Ready for .NET 10 Toolchains)**

---

## 1. Executive Summary

This report documents the security posture, containment boundary verifications, negative security tests, and regression results for the **Google Cloud Autonomous Compliance (GCAC)** containerized analysis sandbox. Following the integration and verification of the official .NET 10 SDK multi-platform container image (`mcr.microsoft.com/dotnet/sdk@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb`), extensive security evaluations were conducted to ensure that:

1. **Host Isolation & Least Privilege:** Execution occurs in fully sandboxed containers under numeric non-root credentials (`65532:65532`), with strict capability dropping (`ALL`), read-only root filesystems, and strict no-new-privileges flags.
2. **Deterministic Network Containment:** All untrusted static code analysis and build evaluation operations operate strictly in `--network none`. No dependency resolution or outbound socket communication occurs during containerized scanner invocation.
3. **Immutability & Integrity Pinning:** The toolchain profile registry enforces canonical SHA-256 profile hashing (`profileSha256`), preventing configuration tampering or runtime digest drift.
4. **Fail-Closed Security Posture:** Image digest mismatches, policy parameter tampering, network egress requests, mount escapes, timeout excursions, and unsupported target frameworks immediately fail closed with structured `BLOCKED` or `COULD_NOT_RUN` verdicts.
5. **Zero Host Fallback:** In no circumstance does container failure or configuration error trigger fallback execution to host shells.

---

## 2. Sandbox Security Architecture & Enforcement Controls

The GCAC Phase 3 Sandbox implements defense-in-depth across the VS Code extension host, the execution gateway, container run arguments, and container execution runtime.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   VS Code Extension Host (Untrusted Target Repo)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Scan Request (Target Framework, Repo Path)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               ScanController & Toolchain Profile Resolver               │
│  - Inspects target csproj / global.json                                │
│  - Selects approved profile (e.g., dotnet-10.0-lts)                   │
│  - Verifies canonical SHA-256 profile integrity                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Validated Profile & Invocation Spec
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       TrustedExecutionGateway                          │
│  - Policy schema validation (EXECUTION_POLICY_VERSION 3.0.0)           │
│  - Restricts cpu limits [0.25..8], memory [128MB..8GB], pids [16..512] │
│  - Rejects unpinned digests or TEMPLATE_PLACEHOLDER profiles           │
│  - Enforces network policy: NO_NETWORK (networkMode: none)             │
│  - Enforces execution timeout [1000ms..300000ms]                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Sanitized Container Execution Spec
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      Workspace Staging Service                         │
│  - Statically copies repo to isolated temp directory                   │
│  - Scrubs .git, .env*, secrets, private keys, compiled binaries        │
│  - Retains required restore manifests (project.assets.json, lockfile)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Sandboxed Staging Path
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Container Sandbox Backend                          │
│  - Mounts staging dir as /work:ro                                      │
│  - Mounts isolated /tmp:rw (128MB tmpfs) & /nuget-cache:ro             │
│  - Enforces --user 65532:65532, --cap-drop=ALL                         │
│  - Enforces --security-opt=no-new-privileges:true                      │
│  - Enforces --read-only filesystem & deterministic container cleanup   │
└────────────────────────────────────────────────────────────────────────┘
```

### Sandbox Parameter Verification Matrix

| Sandbox Parameter | Enforced Configuration | Compliance Verification Evidence |
| :--- | :--- | :--- |
| **Execution User** | `--user 65532:65532` (non-root `app`) | Verified in smoke test; inspect confirms non-root UID |
| **Privileged Mode** | Disabled (`--privileged` disallowed) | Verified; run args never inject `--privileged` |
| **Linux Capabilities** | `--cap-drop=ALL` | Verified; all Linux capabilities dropped |
| **Privilege Escalation** | `--security-opt=no-new-privileges:true` | Enforced; prevents SUID/SGID elevation |
| **Filesystem Root** | `--read-only` | Enforced; write attempts outside tmpfs fail |
| **Network Egress** | `--network none` | Enforced; container sockets blocked, egress tests fail |
| **Host Volume Mounts** | Staged `/work:ro` strictly | Original user repository path is never mounted directly |
| **Host Docker Socket** | Prohibited (`/var/run/docker.sock`) | Gateway rejects any Docker socket mount requests |
| **Developer Credentials** | Prohibited (`~/.nuget`, `~/.ssh`) | Staging directory filters credentials and tokens |
| **Resource Limits** | `--cpus 2.0 --memory 2048m --pids-limit 128` | Verified via `docker inspect` during execution |
| **Execution Timeout** | Default 60,000ms (1000ms..300000ms bounds) | Verified; SIGKILL emitted on timeout excursion |
| **Container Lifecycle** | `--rm` with deterministic SIGKILL cleanup | Verified; orphaned container cleanup on exit |

---

## 3. Negative Security & Policy Attack Testing

To validate sandbox enforcement under hostile or malformed conditions, a dedicated security test harness was executed (`tests/extension/dockerSandboxScenarios.test.js`). All negative security tests passed deterministically.

### Negative Test Results Summary

| Scenario ID | Test Scenario | Expected Outcome | Actual Result | Security Status |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario C** | Missing NuGet Manifest / No Assets | Graceful detection; warning emitted | Return code 0; `0 vulnerabilities`; warning noted | **PASSED** |
| **Scenario D** | Completely Empty Repository | Clean scan; no fake findings fabricated | Zero false findings; exit code 0; valid scan | **PASSED** |
| **Scenario E** | Incompatible Target Framework (`net7.0`) | Rejected; no host fallback or forced .NET 10 | `BLOCKED` / `COULD_NOT_RUN`; message: `No approved toolchain profile found` | **PASSED** |
| **Scenario F** | Missing Dependency Cache / Advisory Data | Warning emitted; incomplete coverage reported | Warning logged; clear notice of missing cached advisory feed | **PASSED** |
| **Scenario G** | Docker Daemon Unavailable | Immediate structured failure; no host fallback | Caught `DockerDaemonUnavailableError`; status `CONTAINER_SANDBOX_UNAVAILABLE` | **PASSED** |
| **Scenario H** | Unapproved / Malformed Image Reference | Policy violation rejection before container launch | `BLOCKED (CONTAINER_POLICY_VIOLATION): Image reference 'invalid-unpinned:latest' is unpinned` | **PASSED** |
| **Scenario I** | Execution Timeout Excursion | Process aborted via timeout mechanism | `TIMED_OUT` returned; container destroyed cleanly | **PASSED** |

---

## 4. Phase 3 Sandbox Smoke Verification Execution

The Phase 3 sandbox verification script was executed directly against the Docker engine:

```bash
node scripts/verify-phase3-sandbox.js --smoke-test
```

### Smoke Test Output Transcript

```json
{
  "profileId": "dotnet-10.0-lts",
  "toolchainType": "dotnet",
  "executed": true,
  "passed": true,
  "runtimeMs": 686,
  "containerState": "exited",
  "containerExitCode": 0,
  "isolationChecks": {
    "nonRootUser": true,
    "readOnlyFs": true,
    "noNetwork": true,
    "pidsLimit": true
  },
  "diagnostics": {
    "engineVersion": "29.9.3",
    "imageDigestVerified": true,
    "profileIntegrityVerified": true
  },
  "machineStatus": "PASSED"
}
```

---

## 5. Comprehensive Regression Test Matrix

All 14 test suites in the JavaScript extension test suite and all 66 unit/integration tests in the .NET 10 solution were executed:

### JavaScript Extension Suite (`tests/extension/run-all-tests.js`)

| Test Suite | Tests Run | Result | Duration |
| :--- | :--- | :--- | :--- |
| `workspaceStaging.test.js` | 13 | PASSED | 0.42s |
| `trustedExecutionGateway.test.js` | 18 | PASSED | 0.38s |
| `containerSandboxBackend.test.js` | 22 | PASSED | 0.81s |
| `networkAudit.test.js` | 9 | PASSED | 0.22s |
| `toolchainProfiles.test.js` | 11 | PASSED | 0.19s |
| `scanController.test.js` | 14 | PASSED | 0.54s |
| `dotnetSecurityScanner.test.js` | 16 | PASSED | 0.61s |
| `nugetDependencyAuditor.test.js` | 12 | PASSED | 0.45s |
| `remediationOrchestrator.test.js` | 15 | PASSED | 0.58s |
| `copilotIntegration.test.js` | 8 | PASSED | 0.31s |
| `policyIntegrityVerification.test.js` | 7 | PASSED | 0.24s |
| `sandboxBoundaryEnforcement.test.js` | 10 | PASSED | 0.72s |
| `dockerSandboxScenarios.test.js` | 9 | PASSED | 4.12s |
| `endToEndScanWorkflow.test.js` | 6 | PASSED | 0.48s |
| **Total** | **170** | **170 PASSED, 0 FAILED** | **10.07s** |

### .NET 10 Solution Test Suite (`dotnet test VulnerabilityRemediation.sln --no-restore`)

| Project / Assembly | Tests Run | Result | Duration |
| :--- | :--- | :--- | :--- |
| `VulnerabilityRemediation.Domain.Tests` | 14 | PASSED | 0.45s |
| `VulnerabilityRemediation.Persistence.Tests`| 12 | PASSED | 0.62s |
| `VulnerabilityRemediation.Repository.Tests` | 18 | PASSED | 0.85s |
| `VulnerabilityRemediation.Excel.Tests` | 10 | PASSED | 0.51s |
| `VulnerabilityRemediation.Cli.Tests` | 12 | PASSED | 0.68s |
| **Total** | **66** | **66 PASSED, 0 FAILED** | **19.04s** |

---

## 6. Real Scanner Executions on Disposable Repositories

### Test Scenario A: Valid .NET 10 Project

- **Target:** Disposable console application targeting `net10.0`.
- **Command Executed in Sandbox:**
  ```bash
  dotnet build /work/ValidApp.csproj --no-restore --configuration Release /p:EnforceCodeStyleInBuild=true
  ```
- **Outcome:** Clean compilation, 0 warnings, 0 errors, exit code 0.
- **Auditor Executed in Sandbox:**
  ```bash
  dotnet list /work/ValidApp.csproj package --vulnerable --include-transitive
  ```
- **Outcome:** 0 vulnerabilities detected, exit code 0.

### Test Scenario B: Known Vulnerable Dependency Fixture

- **Target:** Disposable class library with cryptographic security issues:
  - Direct MD5 and SHA-1 hashing invocation (`System.Security.Cryptography.MD5`, `System.Security.Cryptography.SHA1`).
  - Strict build warnings enabled via `.editorconfig`:
    - `dotnet_diagnostic.CA5350.severity = warning` (Do not use weak cryptographic algorithm SHA-1)
    - `dotnet_diagnostic.CA5351.severity = warning` (Do not use broken cryptographic algorithm MD5)
- **Command Executed in Sandbox:**
  ```bash
  dotnet build /work/VulnApp.csproj --no-restore --configuration Release
  ```
- **Actual Compiler Diagnostics Emitted:**
  ```
  /work/VulnCrypto.cs(11,27): warning CA5351: Do not use broken cryptographic algorithm MD5. [/work/VulnApp.csproj]
  /work/VulnCrypto.cs(16,28): warning CA5350: Do not use weak cryptographic algorithm SHA1. [/work/VulnApp.csproj]
  ```
- **Finding Extraction:**
  - GCAC scanner parsed compiler output and correctly extracted:
    - 1 High Severity Finding: `CA5351: Broken Cryptographic Algorithm (MD5)`
    - 1 Medium Severity Finding: `CA5350: Weak Cryptographic Algorithm (SHA1)`
- **Proof of Genuine Execution:**
  - Findings reflect actual compiler analysis inside the container.
  - No synthetic or mock diagnostics were injected.

---

## 7. Production Readiness & Residual Risks

### Verified Readiness Items
1. **Host Environment:** macOS Apple Silicon ARM64, Docker Desktop Engine 29.9.3.
2. **Local Image Manifest:** `mcr.microsoft.com/dotnet/sdk@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb` fully indexed and cached.
3. **Internal GCAC Codebase:** All 7 projects fully migrated and verified under .NET 10.0.404 / 10.0.15.
4. **Toolchain Profile Catalog:** Cryptographically pinned with updated canonical SHA-256 (`f1f19799b46f6fbc7f9f4455f95ae7a48005133486385eaa90c2cbaaf2a6b884`).
5. **Phase 3 Sandbox:** Fully compliant with defense-in-depth isolation requirements.

### Operational Limitations & Recommendations
1. **Offline Advisory Feeds:** Because `--network none` prohibits outbound HTTP requests, `dotnet list package --vulnerable` depends on pre-cached advisory data or restore assets metadata. When repositories are scanned without an active local NuGet advisory cache, the scanner flags incomplete vulnerability advisory coverage rather than reporting a false clean bill of health.
2. **External Repositories Targeting Legacy Frameworks:** Legacy profiles (`dotnet-8.0-lts` and `dotnet-9.0-sts`) intentionally remain set to `TEMPLATE_PLACEHOLDER`. When external projects target `net8.0` or `net9.0`, GCAC safely returns `BLOCKED (CONTAINER_POLICY_VIOLATION)` or `COULD_NOT_RUN` until enterprise administrators pull and register verified digests for those toolchains.

---

## 8. Final Decision

| Decision Status | Description |
| :---: | :--- |
| **GO** | **Approved for Enterprise Sandbox Deployment.** All container containment boundaries, toolchain integrity checks, compiler analysis parsers, negative security scenarios, and .NET 10 platform migrations have been verified and confirmed operational with zero regressions. |

---

**Sign-off:**  
Principal .NET Engineer & DevSecOps Lead, GCAC Container Security Team
