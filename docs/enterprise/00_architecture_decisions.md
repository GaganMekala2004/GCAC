# Phase 0 — Architecture Conflicts & Decisions (Smallest Safe Migration Path)

**Document ID:** `GCAC-PH0-ADR`  
**Phase:** Phase 0 — Implementation Verification and Architecture Reconciliation  
**Reference Documents:** `GCAC Doc.pdf` (`v2.0.0`), Plan B Target Architecture (`Agentic_Vulnerability_Remediation_Updated_From_Clear_Photos.pdf`), Milestone A/B Reports, Observed Repository Codebase.

---

## 1. Architectural Conflicts Identified

### Conflict 1: Split-Brain Dual Stack & Contradictory Claims
* **Description:** The repository ships two disconnected pipelines that duplicate finding ingestion, validation, remediation, testing, review, and evidence generation:
  * **Stack A (`extension/`):** JavaScript CommonJS VS Code extension reading CSV + `output/scans/findings.json`, invoking `vscode.lm` (`llmClient.js`) and `@vulnerability-orchestrator`, mutating files via `fs.writeFileSync`, running `testRunner.js`, and re-scanning via `ReScanVerifier`.
  * **Stack B (`src/` + `mcp/`):** .NET 9 libraries, CLI, and STDIO MCP server (`VulnerabilityDataMcp`) reading `.xlsx` via ClosedXML into SQLite (`data/vulnerabilities.db`), invoking hardcoded regex FixAgents (`DotNetFixAgent`, `JavaFixAgent`, `DependencyFixAgent`, `LargeRefactorAgent`), cloning into `workspaces/<ID>/repository` (`RepositoryWorkspaceManager`), validating via `TestValidationAgent`, and publishing compare URLs via `PrPublisherService`.
* **Contradictions Verified:**
  * `GCAC Doc.pdf` (§2–3) describes Stack A and Stack B as one unified hexagonal platform communicating over MCP JSON-RPC 2.0 with ".NET AOT" 0ms startup and Roslyn/Java AST agents.
  * In reality: `extension/` makes **zero** calls to `VulnerabilityDataMcp` or `VulnerabilityRemediation.Cli`; `dashboard.html:1269` states `"No third-party APIs, GraphQL, MCP, or remote telemetry"`; `VulnerabilityDataMcp` runs as framework-dependent `VulnerabilityDataMcp.dll` rather than Native AOT; `.NET` Fix/Review agents use regexes, not AST syntax rewriters; and `.agents/mcp_config.json` points to an obsolete developer path (`c:/Users/NAGASATYAMEKALA/Desktop/GCAC-main/...`).

### Conflict 2: Plan B Platform Architecture vs VS Code Extension + Copilot Host Boundaries
* **Description:** Plan B assumes 12 enterprise layers (SharePoint vault, Python intake extractor, 8 PowerShell `Test-*.ps1` / `Approve-*.ps1` enforcement scripts, Execution Gateway, Ephemeral Build Sandbox, Evidence Ledger Service, `.github-private/agents` repo, Corporate Proxy/SWG/DLP, and SIEM). None of those enterprise services or PowerShell scripts exist in this repository.
* **Platform Reality:** Inside VS Code, an extension **cannot** intercept, decrypt, or proxy internal GitHub Copilot Chat HTTP traffic or built-in VS Code workspace/terminal tools invoked by Copilot directly. Attempting to rebuild Copilot Chat inside the extension or claiming total network interception in Extension Host JavaScript is technically invalid and violates the requirement to preserve existing working Copilot integration.

### Conflict 3: .NET Dynamic Batching vs Plan B One-Finding Isolation (`SEC-02`)
* **Description:** `GCAC Doc.pdf` §3.4.6 promotes `VulnerabilityBatchingService` and MCP `execute_batch_remediation` to bundle multiple findings (`Large`, `Medium`, `Small`, `Individual`) into multi-finding execution runs and shared branches/PRs.
* **Security Conflict:** Plan B `SEC-02` mandates a hard boundary: *"One finding, one application, one run ID, bounded context and temporary workspace."* Executing multiple findings in a single shared agent run mixes diffs, complicates diff-bound Gate 1 rollback, and expands blast radius.

### Conflict 4: Master Vulnerability Exports & Secrets Stored Inside Agent-Readable Workspace
* **Description:** Legacy docs and code place `vulnerability/vulnerabilities.csv`, SQLite `RawValuesJson` + owner/infra metadata (`ProductOwner`, `PrimaryManager`, `SecondaryManager`, `ApplicationLead`, `Subscription`, `ResourceGroup`, `VmName`), and literal Stripe `sk_live_` strings (`SampleRepositoriesSeeder.cs`, `seed-sample-files.js`) directly inside the repository directory.
* **Security Conflict:** Plan B §5 & §15 supersede *"CSV files in the findings area"* and *"Token map stays client-side"*: any unminimized export or literal credential stored in the workspace directory is directly readable by Copilot Chat / Agent Mode file-search tools regardless of `.gitignore`.

---

## 2. Formal Architecture Decision Records (ADRs)

### ADR-001: Preserve Existing Working Copilot Integration Without Rebuilding or Assuming Total Interception
* **Status:** Accepted (Phase 0 Binding Constraint)
* **Decision:** Keep [`extension.js`](../../extension/extension.js#L351) `@vulnerability-orchestrator` (`vscode.chat.createChatParticipant`), [`launchCopilot`](../../extension/extension.js#L1136-L1185) (`workbench.action.chat.open`), and [`llmClient.js`](../../extension/llmClient.js) (`vscode.lm`) intact as the developer IDE interaction layer.
* **Consequence:**
  * Do **not** build a custom replacement chat UI or proxy wrapper around GitHub Copilot Chat.
  * Enforce extension-side outbound context screening (`SEC-04`) and injection screening directly on **extension-initiated `vscode.lm` calls** inside `llmClient.js` / `remediationEngine.js`.
  * Protect **native Copilot Chat turns** indirectly through workspace hygiene (removing master CSVs/secrets from workspace disk, locking `.vscode/settings.json` terminal policies, removing unsafe `.github/` prompt bypasses) and rely explicitly on **Corporate Proxy / SWG + DLP** (`GAP-04`, Phase 4) for enterprise network inspection of Copilot Chat traffic.

### ADR-002: Canonical Single-Authority Runtime Reconciliation (Smallest Safe Migration Path)
* **Status:** Accepted
* **Decision:** Resolve split-brain dual authority incrementally without throwing away working components:
  1. Designate the **VS Code Extension (`extension/`)** as the single interactive **IDE Orchestrator, Local Gatekeeper (Gate 1 UI + Local Scanners + Fail-Closed State Machine), and Webview Hub**.
  2. Eliminate **all independent mutating/publishing authority** in `VulnerabilityDataMcp` and `PrPublisherService` (quarantine `approve_pr` auto-default, strip `publish_remediation_pr` / `approve_pr` from orchestrator tools, disable unauthenticated remote git push).
  3. Treat **.NET Domain & Excel components (`DomainValidator`, `ExcelIngestionService`, `ExcelInputSanitizer`)** as a **deterministic CLI intake/validation backend utility** invoked via subprocess (with minimized single-finding JSON extract output) rather than maintaining duplicated ad-hoc validation in JS or maintaining competing .NET regex FixAgents.
  4. Deprecate legacy hardcoded regex fixers (`DotNetFixAgent` `#pragma` hacks) and false `"No MCP"` / `"AOT"` documentation claims; align `dashboard.html` copy accurately with actual runtime components.
* **Rationale:** Trying to rewrite everything into C# loses working VS Code native `vscode.chat`/`vscode.lm`/Webview integration; keeping both runtimes active with competing workflows perpetuates critical bypasses and broken invariants.

### ADR-003: Enforce One-Finding, One-Application, One-Run-ID Isolation (`SEC-02`)
* **Status:** Accepted
* **Decision:** Enforce Plan B `SEC-02` strictly at runtime execution: every remediation run executes for **exactly one normalized finding**, targeting **one resolved application repository**, under a unique `runId`.
* **Batching Disposition:** Preserve `VulnerabilityBatchingService` strictly as an **advisory prioritization/grouping plan** (helping developers queue related work in the UI or schedule sequential per-finding runs). Disable/remove `execute_batch_remediation` multi-finding shared execution in `VulnerabilityDataMcp`.

### ADR-004: Replace In-Place Live File Overwrites with Ephemeral Worktree / Clone Isolation & Pre/Post Scope Verification
* **Status:** Accepted
* **Decision:** Retire direct live-workspace `fs.writeFileSync` mutation in `remediationEngine.js:532-537`. All Stage 5 code modifications, baseline/post-fix tests, and re-scans shall execute inside an isolated per-run workspace (temporary `git worktree` or clean local clone referencing an existing local repo, isolated per `runId`, with `.git`/`.github`/`.vscode` write protections), preserving the developer's active checkout completely untouched until reviewed diff application or human branch creation.
* **Phase 1 Scope Note:** Ensure rollback works uniformly for **both CSV findings and `findingsStore` scanner findings** (`rejectRemediation`, `rejectFinalGate`), eliminating partial orphaned state.

### ADR-005: Fail-Closed Validation, Honest Telemetry, & ReScanVerifier Restoration (`SEC-06`)
* **Status:** Accepted (P0 Priority)
* **Decision:** Every validation, test, review, and re-scan stage must operate strictly **fail-closed**:
  * Remove `"NOT EXECUTED -> PARTIAL -> Remediated"` and `'Resolved'` promotion in `remediationEngine.js:658-778`. Only verified `PASS` post-fix test execution + verified originating-scanner `RESOLVED` status may advance to `Ready for Review / Remediated`.
  * Enforce baseline failing verification policy (or explicit deterministic `NOT REPRODUCED / BLOCKED` classification where baseline tests cannot isolate exploit).
  * Fix `ReScanVerifier` (`reScanVerifier.js:70-71`) to read `Scanner_ID` (and `scannerId`), fail closed as `NOT VERIFIED` when scanner mapping is missing or unknown (never fallback blindly to `secrets-config`), and fix `remediationEngine.js:599, 676` comparisons to use `VERIFICATION_STATUS` constants (`'STILL PRESENT'`, `'REGRESSION DETECTED'`) rather than underscored literals.
  * Replace broken `reScanVerification.test.js:116-117` assertion and strip all fake-pass fallbacks from `TestValidationAgent.cs:76-139` (`mvn` missing, unknown tool, 0-test build pass) and `#pragma warning disable` / no-match `Success=true` in `DotNetFixAgent.cs`.
  * Harden `gcac.scanRepository` (`extension.js:274-289`), all 5 `dashboard.js` chart/progress/history defects, `getNonce()` CSPRNG (`crypto.randomBytes`), CSP `'unsafe-inline'` removal, and `preview-dashboard.js` path traversal/CORS/gate-bypass flaws.

### ADR-006: Native Control Modules Matching Existing Stacks Rather Than Duplicating Unimplemented PowerShell Scripts
* **Status:** Accepted
* **Decision:** Implement Plan B security control logic (`OutboundContextGate`, `ContentInjectionScreen`, `RemediationScopeCheck`, `DiffBoundApprovalLedger`, `StageResultVerifier`, `WorkspaceSecretScan`) as **clean cross-platform Node.js modules inside `extension/` (plus matching C# guards in `src/`/`mcp/`)** rather than introducing brittle shell invocations to 8 currently non-existent `.ps1` scripts from Plan B Appendix A.
* **Rationale:** Node.js extension modules run cross-platform inside VS Code Extension Host and `npm test` cleanly without shell-escaping attack surfaces (`execSync` risks seen in `codeqlScanner.js`), while enforcing 100% of Plan B Appendix A functional acceptance criteria and emitting structured JSON/SHA-256 ledger evidence ready for Phase 4 enterprise ingestion.

### ADR-007: Non-Polluting Sample Ecosystem & Test Fixture Hygiene (`SEC-03`)
* **Status:** Accepted
* **Decision:** Resolve broken `sample-repos/*` mode-`160000` gitlinks so `npm test` passes deterministically in CI without tracking live-looking secret literals (`sk_live_...`) or bulky unisolated test repos in default agent-indexed workspace folders:
  * Move automated test fixtures to dedicated isolated `tests/fixtures/` created dynamically inside `os.tmpdir()` during `npm test` / `dotnet test`, or seed test fixtures cleanly with clearly marked test-only fixtures scoped strictly to test execution directories.
  * Keep workspace default folders clean of raw master vulnerability spreadsheets (`vulnerabilities.csv` replaced in production workflows by single-finding minimized extracts sourced outside workspace).

---

## 3. Smallest Safe Migration Roadmap & Exact Approved Phase 1 Scope

To maximize immediate risk reduction without destabilizing working Copilot IDE capabilities or blocking on external enterprise procurement, migration follows a strict staged path:

### Exact Approved Scope for Phase 1 — P0 Containment & Critical Integrity Fixes
*(Strictly local codebase, test, config, and extension changes; zero external enterprise infrastructure blockers.)*

1. **P0 Authorization, Permission & Prompt Containment (`GAP-01`, `GAP-02`, `GAP-05`, `GAP-10`):**
   * Remove `approve_pr` auto-approval default (`isApproved = true`) in `mcp/VulnerabilityDataMcp/Program.cs:574-578` and restrict mutating MCP operations.
   * Remove `vulnerability-data/approve_pr` & `vulnerability-data/publish_remediation_pr` from `.github/agents/remediation-orchestrator.agent.md:41-42` and delete self-bypass/fake-pass clauses in `.github/copilot-instructions.md:118-132` and `remediation-orchestrator.agent.md:53`.
   * Fix stale `.agents/mcp_config.json` path; configure explicit terminal command deny policy in `.vscode/settings.json` (`git`, `gh`, `az`, `tf`, `curl`, `wget`, `ssh`, `scp`, `Invoke-WebRequest`, `Invoke-RestMethod`, package publish commands).
   * Remove `preview-dashboard.js` `/api/approve-final` bypass (`L601-619`), restrict CORS to loopback/disabled wildcard, and enforce `assertPathWithinWorkspace` on `/api/source-code` & `/api/scan/target`.
   * Disable remote `git push` from `.NET` `RepositoryWorkspaceManager.CommitAndPush` / `PrPublisherService` (keep human push outside agent boundary) and strip hardcoded `PASS` strings in `PrPublisherService.cs:79-83`.
2. **P0 Honest Execution, Re-Scan Integrity & False-Pass Elimination (`GAP-07`, `GAP-09`, `GAP-16`, `GAP-17`):**
   * Fix `remediationEngine.js`: fail closed so `NOT EXECUTED`, `PARTIAL`, `BLOCKED`, or failed baseline/post-fix states NEVER convert to `'Remediated'` or `'Resolved'`; fix `'STILL PRESENT'` / `'REGRESSION DETECTED'` space-constant checks; convert `codeqlScanner.js` `_execCodeql` from `execSync` to `execFileSync`/`spawnSync(..., { shell: false })`.
   * Fix `reScanVerifier.js`: read `Scanner_ID` / `scannerId` accurately and fail closed (`NOT VERIFIED`) if scanner identity is absent or disabled rather than defaulting to `secrets-config`.
   * Fix `TestValidationAgent.cs`: remove fabricated `Passed = true; PassedTests = 1` fallbacks (`mvn` missing, unknown tool, zero-test build) and default `.NET` validation to `--no-restore`.
   * Fix `DotNetFixAgent.cs`: remove `#pragma warning disable CS0162` (`L149`) and return `Success = false` when no deterministic fix rule matches (`L181-186`).
   * Fix `gcac.scanRepository` (`extension.js:274-289`) `ReferenceError` & `targetRepo` parameter mismatch, plus fix `rejectRemediation`/`rejectFinalGate` rollback for `findingsStore` findings (`extension.js:997-1069`).
3. **P0 Outbound Context Gate (`vscode.lm`), Single-Finding Data Minimization & Workspace Secret Cleanup (`GAP-03`, `GAP-04`, `GAP-11`, `GAP-14`):**
   * Add deterministic `outboundContextGate.js` before every `llmClient.js` (`vscode.lm`) request (secret/PII/high-entropy scan, path exclusion, byte/file caps, redacted audit log with `runId`).
   * Preserve authoritative scanner severity in Extension Stage 1 (`SEC-09`: LLM may not downgrade Critical/High severity or emit silent no-action).
   * Strip `RawValuesJson` & PO/Manager/Subscription/VM fields from `.NET` SQLite ingestion (`ExcelIngestionService`/`VulnerabilityRepository`) and enforce allowlisted single-finding minimized extract schema (`DomainValidator` + strict allowlist).
   * Disable `execute_batch_remediation` in `VulnerabilityDataMcp` (`SEC-02`), keeping `VulnerabilityBatchingService` plan-only.
4. **P0 Webview Hardening, Telemetry Accuracy & Test Suite Repair (`GAP-15`, `GAP-18`):**
   * Replace `Math.random()` in `getNonce()` (`extension.js:1261-1268`) with `crypto.randomBytes`, tighten Webview CSP by eliminating `'unsafe-inline'` styles, fix all 5 `dashboard.js` chart/progress/history bugs, and update inaccurate `dashboard.html:1269` disclaimer.
   * Fix `tests/extension/reScanVerification.test.js:116-117` broken `RemediationEngine` constructor instantiation + assertion, restore deterministic isolated test fixtures so all JS & .NET tests run green without empty gitlink failures or fake pass mocks hiding defects, and add **P0 negative security tests** covering every containment control above.

### Deferred Out of Phase 1 Scope (Explicitly Scheduled for Phases 2–4)
* **Phase 2 (Trust & Integrity Controls):** Full `git worktree` / ephemeral clone execution isolation in `extension/`, `ContentInjectionScreen` (zero-width, hidden HTML, `RESULT:` smuggling blocker), Pre/Post FS diff `RemediationScopeCheck`, Diff SHA-256 + Non-Self Authenticated Gate 1 local ledger (`runId` + `instructionHash` + artifact SHA-256 manifest), and `.xlsx` minimized extractor bridge.
* **Phase 3 (Build & Test Execution Isolation):** Containerized/ephemeral VM sandbox with pinned digests, non-root read-only FS, blocked public internet egress, approved internal NuGet/Maven feeds, and SBOM output (`SEC-07`).
* **Phase 4 (Enterprise Platform Integration):** Restricted SharePoint master export store (`Layer 1`), `.github-private/agents` signed agent bundle repo (`GAP-10`), Corporate Proxy/SWG + Purview DLP + SIEM correlation (`GAP-04`), Corporate SSO Approval API (`SEC-05`), WORM Evidence Ledger Service (`SEC-06`), and GitHub Enterprise server-side Rulesets / `CODEOWNERS` / Required CI & SAST status checks / Secret Scanning & Push Protection (`SEC-08`).

