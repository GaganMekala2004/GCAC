# GCAC Real-World Usability Fixes — Security Review

**Document ID**: `GCAC-FIX-04-SEC`  
**Security Posture Principle**: Fail-closed governance across all usability, portability, test reporting, and retry enhancements.

---

## 1. Preserved Phase 0–3 Security Invariants

1. **SEC-02 Single-Finding & Unambiguous Repository/Application Isolation**:
   - Missing or comma-delimited `Application_Number` or `Repository` metadata blocks execution at both `RemediationEngine._doExecutePipeline`, `buildCopilotRemediationPrompt`, and `VulnerabilityDataMcp` (`get_remediation_context`, `execute_remediation`).
   - Unmapped scanned findings such as `SCAN-NUGETA-003` never silently resolve to GCAC's workspace root (`currentWorkspaceRoot`) and never emit empty `using scan ""` placeholders.
   - Local unregistered repositories receive deterministic local identities (`LOCAL-<8HEX>` derived from SHA-256 of canonical path) via explicit user selection/mapping; enterprise `APP-*` identifiers are never fabricated.

2. **External Repository Containment & Path Traversal Defense (Block B)**:
   - Support for repositories outside the GCAC folder operates strictly through an explicit `authorizedRoots` set populated only from VS Code `workspaceFolders`, validated `config/repositories.json` / `.gcac/local-repositories.json` entries, or explicit interactive folder selection.
   - `isSensitiveSystemOrCredentialRoot` blocks OS system roots (`C:\Windows`, `/etc`, `/usr`, `/var`, `/bin`), user home roots, and credential directories (`~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.gnupg`, `~/.docker`).
   - `assertPathWithinWorkspace` (`extension/pathUtils.js`) resolves existing canonical ancestors before relative checks to support Windows 8.3 paths legitimately inside temp/work dirs while rejecting symlink escapes and `..` directory traversal.
   - Remote Git URLs (`https://`, `http://`, `ssh://`, `git://`, `git@`, `file://`) remain rejected at both Node (`repositoryContext.js`, `isolatedWorkspaceManager.js`) and .NET (`RepositoryWorkspaceManager.cs`) boundaries.

3. **Workspace Trust Enforcement**:
   - External folder/file authorization (`selectRepo`, `selectFile`, `mapFindingRepository`), scanner runs (`scanRepository`), remediation (`runRemediation`, `retryStage`, `reviseFix`, `approveRemediation`, `approveFinalGate`), and Copilot invocation (`launchCopilot`) remain blocked when `vscode.workspace.isTrusted === false`.

4. **Honest Empty-Input, Re-Scan & Test Verification (Blocks A & D)**:
   - Empty directories, empty/comment-only source files, dependency-free manifests, and uninitialized Git submodules (`160000` gitlinks) return `NO_SCANNABLE_INPUTS` rather than fabricated findings or parent-repo walk-ups.
   - Emptying a target file during remediation triggers `NO_SCANNABLE_INPUTS` -> `INCONCLUSIVE` in `ReScanVerifier`, preventing false `RESOLVED` status.
   - Scanner failures set `unverifiedCoverage: true`, preventing failure from masquerading as zero vulnerabilities.
   - `testRunner.js` and `reportParser.js` never return `PASS` on zero discovered tests and never fall back to host shell execution when `SANDBOX_UNAVAILABLE`.

5. **Diff-Bound Approval & Retry Integrity (Block E)**:
   - `retryStage` validates workspace trust, repository mapping validity, active concurrency lock (`activeRuns`), bounded retry limits (`maxRetries = 3`), backoff timing, approval expiration, and diff/post-apply SHA-256 checksums.
   - Any retry targeting Stage <= 5 performs conflict-aware rollback of prior changes, clears Stage 4/5/6 approval flags, and enforces fresh diff-bound Stage 4 human approval.
   - Blind retries (`fromStage >= 6`) on genuine post-fix failures (`TESTS_FAILED`, `BUILD_FAILED`, `NO_TESTS_DISCOVERED`, `STILL_PRESENT`, `REGRESSION_DETECTED`) are rejected; developers must use `Review Failure / Revise Fix` (`reviseFix`), which archives prior failure evidence and requires fresh Stage 4 approval for the new diff.
   - Prior failure artifacts are archived immutably under `remediation-output/<id>/attempts/<attemptId>/` rather than overwritten or deleted.

6. **Webview CSP, DLP & Configuration Integrity**:
   - Zero inline `style=` attributes added to `extension/media/dashboard.html`; CSS tokens maintain strict `style-src` nonce/self policies.
   - `ALLOWED_SINGLE_FINDING_FIELDS` (`dataMinimization.js`) expanded strictly with non-PII repository/scanner/package metadata while keeping Product Owner, Manager, Lead, Subscription, ResourceGroup, VM, and secrets masked/excluded.
   - `.github/copilot-instructions.md` and `.github/agents/*.agent.md` remained unmodified; `approved-agent-bundle.json` baseline hashes pass Group F verification cleanly.

---

## 2. Known Limitations & Non-Goals Preserved
- **Host Kernel Isolation**: Until WSL2 Linux container mode (Docker Desktop / Podman) is provisioned, container-isolated test validation fails closed as `SANDBOX_UNAVAILABLE`.
- **Native Copilot Tool Calls**: Extension Stage 4/8 governance gates apply strictly to GCAC's app-controlled execution path and MCP tools; VS Code's native Copilot editing tools operate under VS Code's own confirmation UX (documented via `COPILOT_APPROVAL_LIMITATION_DISCLOSURE`).
- **Heuristic Secrets Rule (`SEC-006`)**: Labeled explicitly as `HEURISTIC_PATTERN` with `Low` severity/confidence; requires developer triage rather than claiming confirmed exploitability.

