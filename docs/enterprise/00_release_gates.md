# Phase 0 — Release Gates, Compliance Verification & Phase 1 Entry Criteria

**Document ID:** `GCAC-PH0-GATES`  
**Phase:** Phase 0 — Implementation Verification and Architecture Reconciliation  
**Reference Baselines:** Plan B Implementation Roadmap (§18), Control Ownership (§16), Non-Functional Security Requirements (`SEC-01`..`SEC-10`, §17), and Go-Live Security Checklist (15 items, §19).

---

## 1. Evidence-Based Phase 0 Decision

| Evaluation Target | Decision | Empirical Basis Observed in Phase 0 |
| :--- | :---: | :--- |
| **Enterprise Production Readiness** | **NO-GO** | Fails all 10 Plan B Non-Functional Security Requirements (`SEC-01`..`SEC-10`) and 15/15 Plan B Go-Live checklist gates; active false-pass defects confirmed in `remediationEngine.js`, `reScanVerifier.js`, `TestValidationAgent.cs`, and `remediation-output/VUL-POC-003/run-state.json`; unauthenticated Gate 1 / MCP bypasses confirmed in `mcp/Program.cs:574-578` and `preview-dashboard.js:601-619`; `npm test` fails (`8/9` suites pass, Suite 7 fails at `scannerAdapters.test.js:60`). |
| **Transition to Phase 1 (P0 Containment & Core Integrity Remediation)** | **CONDITIONAL GO** | Phase 0 architecture conflicts (`Conflict 1–4`), 18-gap traceability, threat boundaries, and ADR-001..007 smallest safe migration plan are baselined and documented across `docs/enterprise/00_*.md`. Phase 1 fixes are strictly localized to codebase/tests/configs without external enterprise infra blockers. |

---

## 2. Phase Gate Roadmap (`Phase 0` through `Phase 5`)

| Gate | Target Phase (Plan B §18) | Primary Deliverables | Mandatory Quantitative Exit Criteria | Primary Owner(s) |
| :--- | :--- | :--- | :--- | :--- |
| **G0** | **Phase 0 — Baseline & Architecture Reconciliation** *(Current)* | `00_actual_capability_inventory.md`, `00_gap_traceability_matrix.md`, `00_threat_model.md`, `00_architecture_decisions.md`, `00_release_gates.md` | All 18 gaps mapped to source lines & test status; ADRs reconciling dual stack & Copilot boundaries signed off; zero unverified source modifications performed during Phase 0. | Architecture, AppSec, Extension & .NET Engineering Leads |
| **G1** | **Phase 1 — P0 Containment & False-Pass Elimination** *(Next Approved Scope)* | MCP & preview bypass removal, orchestrator/instructions hardening, `.vscode/settings.json` command deny list, `OutboundContextGate` (`vscode.lm`), fail-closed `ReScanVerifier`/`remediationEngine`/`TestValidationAgent`, Webview `crypto.randomBytes` nonce + CSP + `dashboard.js` telemetry fixes, `SEC-02`/`SEC-09` guards, clean test suite repair | 1. 100% pass rate on all `npm test` suites (no skipped assertions) and unfiltered `.NET` tests (zero fake `MockTestValidationAgent` hiding broken validation).<br>2. P0 negative test suite passes (omitting `isApproved` fails; `/api/approve-final` blocked; `NOT EXECUTED`/`PARTIAL` never yields `Remediated`/`Resolved`; synthetic `sk_live_`/entropy secret blocked before `vscode.lm`; `execute_batch_remediation` rejects multi-finding run; Critical/High severity downgrade blocked).<br>3. Preserved Copilot workflows (`@vulnerability-orchestrator` & `launchCopilot`) verified functionally intact. | Solution Engineering + QA Lead |
| **G2** | **Phase 2 — Trust Controls & Local Isolation** | Ephemeral `git worktree`/clone isolation, `ContentInjectionScreen`, `RemediationScopeCheck` (pre/post FS diff), diff SHA-256 + non-self authenticated Gate 1 ledger, SHA-256 evidence manifest (`runId`, `instructionHash`, log hashes), `.xlsx`/CSV minimized intake bridge | 1. Negative injection tests fail closed on zero-width, hidden HTML, override phrases, and untrusted `RESULT:` markers.<br>2. Editing `.github/`, `.vscode/`, tests, or adding suppression pragmas/deps blocks run (`BLOCKED`).<br>3. Changing diff after Gate 1 invalidates approval and halts Stage 5 apply. | Solution Engineering + AppSec |
| **G3** | **Phase 3 — Execution Isolation & Supply Chain Control** | Credential-free non-root ephemeral container / CI runner sandbox, pinned container image digests, egress-blocked network except internal package feeds, deterministic stack templates, SBOM generation | 1. Build/test inside sandbox executes with zero Git/SSH/cloud/publish credentials.<br>2. Negative egress & malicious build-hook tests (`csproj` targets / public PyPI/NuGet fetch) fail closed and emit evidence logs. | Infrastructure / Endpoint Security + Solution Engineering |
| **G4** | **Phase 4 — Enterprise Server & Data Platform Controls** | External restricted SharePoint master vault, `.github-private/agents` signed repo, Corporate Proxy/SWG + Purview DLP + SIEM correlation by `runId`, Entra SSO Approval Service, WORM Evidence Ledger, GitHub Enterprise Rulesets + `CODEOWNERS` + CI/SAST/Evidence checks | 1. Direct branch push, same-author PR approval, stale approval retention, or missing SAST/evidence check rejected by GitHub Enterprise.<br>2. Telemetry confirmed end-to-end in SIEM across Gateway, GitHub Audit, DLP, Secret Scanning & Push Protection. | GitHub Admin + Infra Security + Data Owner + SOC/SIEM |
| **G5** | **Phase 5 — Controlled Pilot & Security Sign-Off** | Pilot onboarding across selected repositories, false-positive metrics review, recovery/exception drill exercises | Zero open Critical or High security control gaps across §17 (`SEC-01`..`SEC-10`) & §19 Go-Live Checklist; signed AppSec + Platform authorization. | All Control Owners (§16) |

---

## 3. Plan B `SEC-01`..`SEC-10` Verification & Readiness Baseline

| Req ID | Requirement Summary | Phase 0 Baseline | Verification Method (Plan B §17) | Target Phase | Control Type |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **`SEC-01`** | Default deny for commands, paths, tools, and outbound destinations | **FAIL** (`settings.json` open; orchestrator has `approve_pr`; `codeqlScanner` uses `execSync`) | Attempt `git`, `gh`, `az`, curl, and unauthorized path edits; all must block & log (`BLOCKED`) | Ph 1 (Policy) / Ph 3 (Gateway) | **Hybrid** |
| **`SEC-02`** | Strictly one finding and one application per remediation run | **FAIL** (`execute_batch_remediation` runs multi-finding; no single-finding run token) | Attempt multi-finding or ambiguous application input -> run creation fails closed | Ph 1 | **Local** |
| **`SEC-03`** | Zero master exports, reversible token maps, or developer credentials in agent workspace | **FAIL** (`vulnerabilities.csv`, `RawValuesJson`, `sk_live_` seeders, host Git creds present) | Automated workspace inventory & secret scan return `0` prohibited artefacts | Ph 1 (Minimize) / Ph 4 (SharePoint) | **Hybrid** |
| **`SEC-04`** | 100% of AI requests pass outbound context screening correlated to `runId` | **FAIL** (`remediationEngine.js` sends raw code to `vscode.lm` unscreened; no SWG/DLP) | Inject synthetic secrets/PII/restricted paths/oversize payload -> `vscode.lm` blocked (`100%` gateway logs); SWG/DLP logs for Copilot Chat | Ph 1 (`vscode.lm`) / Ph 4 (SWG/DLP) | **Hybrid** |
| **`SEC-05`** | Approval is authenticated, non-self, diff-bound (`SHA-256`), and expiring | **FAIL** (`isApproved=true` auto-default in MCP; `/api/approve-final` bypass; bare booleans) | Modify single byte in diff after Gate 1 -> Stage 5 apply and CI must fail | Ph 1 (Remove Bypasses) / Ph 2 (Diff Ledger) / Ph 4 (SSO) | **Hybrid** |
| **`SEC-06`** | Stage status is machine-derived from exit codes and tamper-evident | **FAIL** (`NOT EXECUTED -> PARTIAL -> Remediated`; `TestValidationAgent` fake passes; mutable logs) | Inject fake `RESULT: PASS` text or simulate missing test runner -> remains `NOT EXECUTED` / `FAILED`, never `Remediated` | Ph 1 (Fail-Closed) / Ph 2 (Hashes) / Ph 4 (WORM Ledger) | **Hybrid** |
| **`SEC-07`** | Build/test runs in isolated, credential-free, egress-restricted sandbox | **FAIL** (Runs inside developer host OS; `dotnet restore` hits public NuGet) | Attempt outbound internet call or host credential read inside build step -> fails & logs containment | Ph 1 (`--no-restore`) / Ph 3 (Sandbox) | **External Infra + Local** |
| **`SEC-08`** | Protected server-side PR review (`CODEOWNERS`, CI, SAST, stale dismissal) is mandatory | **FAIL** (Local only; `PrPublisherService` hardcodes `"PASS"`) | Attempt direct push, same-author PR approval, or unverified commit merge on protected repo -> server rejects | Ph 4 (GH Rulesets) | **External Infra** |
| **`SEC-09`** | Critical/High severity cannot be downgraded or no-actioned by AI alone | **FAIL** (Stage 1 asks LLM for `severity` and `route` freely) | Feed Critical finding + adversarial no-action prompt -> forces manual review & retains scanner Critical severity | Ph 1 | **Local** |
| **`SEC-10`** | Temporary input/workspace deletion & governed evidence retention enforced | **FAIL** (Mutable workspace artifacts remain indefinitely; `VUL-POC-003` artifacts on disk) | Verify ephemeral temp directories cleaned post-run and evidence retention matches policy | Ph 2 / Ph 4 | **Hybrid** |

---

## 4. Plan B Section 19 Go-Live Security Checklist (15-Item Readiness Split)

### Part A — Solution Engineering & Local Codebase Gates (Achievable in Phases 1–3)
| # | Go-Live Checklist Item (Plan B §19) | Phase 0 Status | Target Phase |
| :---: | :--- | :---: | :---: |
| 1 | Published SAST/DAST field allowlist and irreversible masking are implemented | **FAIL** (`GAP-03`, `GAP-13`) | Ph 1–2 |
| 2 | Orchestrator has no terminal or web-fetch capability (`remediation-orchestrator.agent.md`) | **FAIL** (`GAP-01`) | Ph 1 |
| 3 | `git`, `gh`, cloud CLIs, network tools, and package-publish commands are blocked technically | **FAIL** (`GAP-01`) | Ph 1 + Ph 3 |
| 4 | Every extension outbound AI context (`vscode.lm`) is screened and correlated to a `runId` | **FAIL** (`GAP-04`) | Ph 1 |
| 5 | Prompt-injection tests cover comments, hidden text, zero-width chars, scanner fields & logs | **FAIL** (`GAP-02`) | Ph 2 |
| 6 | Gate 1 is authenticated, non-self, diff-bound, and enforced before write | **FAIL** (`GAP-05`) | Ph 1–2 |
| 7 | Pre/post remediation scope checks block unapproved files and policy paths | **FAIL** (`GAP-07`) | Ph 1–2 |
| 8 | Stage status comes from real tool exit codes and retained evidence, not model/fallback claims | **FAIL** (`GAP-09`, `GAP-16`, `GAP-17`) | Ph 1–2 |
| 9 | AI classification cannot change authoritative severity, SLA, risk acceptance, or closure | **FAIL** (`GAP-11`) | Ph 1 |
| 10 | Temporary input & workspaces are deleted post-run; audit evidence follows retention policy | **FAIL** (`GAP-03`, `GAP-15`) | Ph 2–3 |

### Part B — Enterprise Infrastructure & Platform Owner Gates (Require External Teams in Phases 3–4)
| # | Go-Live Checklist Item (Plan B §19) | Required Platform / Owner (§16) | Phase 0 Status |
| :---: | :--- | :--- | :---: |
| 11 | Master scanner exports and reversible mappings are outside repo & agent access (SharePoint Vault) | Data Owner + Solution Eng | **FAIL** (`GAP-03`) |
| 12 | Agent definitions are signed/versioned and stored in administrator-controlled `.github-private/agents` repo | GitHub Admin | **FAIL** (`GAP-10`) |
| 13 | Build/test executes in isolated, credential-free, egress-restricted environment | Infra / Endpoint Security | **FAIL** (`GAP-08`) |
| 14 | Protected PR rules require independent `CODEOWNERS` review, CI, SAST/original-rule & evidence validation | GitHub Admin + Independent `CODEOWNER`/Security | **FAIL** (`GAP-06`) |
| 15 | Platform teams supply verified evidence for Corporate Proxy/SWG/DLP, GitHub Audit forwarding, SIEM correlation, Secret Scanning & Push Protection | Infra Security + GitHub Admin + SOC/SIEM | **FAIL** (`GAP-04`) |

---

## 5. Mandatory Phase 1 Exit Verification Checklist

Before declaring Phase 1 complete and advancing to Phase 2, **100%** of the following verification gates must execute cleanly in automated runs:

1. **Test Suite Integrity (Zero Failures / Zero Fake Passes):**
   * `npm test` executes all Extension suites cleanly (`0` failed suites; `scannerAdapters.test.js` passes using clean isolated fixtures; `reScanVerification.test.js` passes against a real non-null `RemediationEngine` + `ReScanVerifier` verifying `RESOLVED`, `STILL PRESENT`, `INCONCLUSIVE`, `NOT VERIFIED`, `REGRESSION DETECTED` under space-separated enum strings).
   * `dotnet test` executes **all** tests (including non-mocked validation tests without relying on `MockTestValidationAgent` or missing-tool fake passes) with `0` failures and `0` warnings on build.
2. **Negative Security & Containment Assertions (`Phase 1` Gate):**
   * Calling MCP `approve_pr` / `approve_remediation_pr` omitting `isApproved` returns explicit denial (`false` / error).
   * Calling `VulnerabilityDataMcp` `execute_batch_remediation` with multiple findings rejects execution (`SEC-02`).
   * Calling `POST /api/approve-final` on `preview-dashboard.js` fails (endpoint removed/disabled); calling `/api/source-code?path=../../package.json` returns `403` containment error.
   * Passing `postFixValidation.status = 'NOT EXECUTED'` or mismatched scanner ID to `remediationEngine.js` / `reScanVerifier.js` NEVER yields `finalRemediationStatus: 'Remediated'`, `'Resolved'`, or `'PASS'`.
   * Running `TestValidationAgent` when `mvn`/`dotnet` fails or 0 tests exist returns `Passed = false`.
   * Running `DotNetFixAgent` with `#pragma` ban test or unmatched code returns `Success = false` and never injects `#pragma warning disable`.
   * Invoking `llmClient.js` (`OutboundContextGate`) with synthetic `sk_live_` secret, restricted `.vscode`/`.github` file, PII, high-entropy token, or oversized payload is blocked pre-call and logged with redacted token type + `runId`.
   * Invoking Stage 1 classification with LLM output attempting to downgrade a `Critical` finding preserves authoritative `Critical` scanner severity and flags manual review (`SEC-09`).
3. **Preserved Functional Compatibility:**
   * `@vulnerability-orchestrator` chat participant commands (`/remediate-vulnerability`, `/approve`, `/final-approve`) and `launchCopilot` (`workbench.action.chat.open`) pass contract verification cleanly.
   * Webview renders accurate KPIs/trend charts/`SCAN_PROGRESS` events/`scan-history` metrics with `crypto.randomBytes` nonce and zero `'unsafe-inline'` style directive.

---

## 6. Phase 2 Exit Gate (`G2`) Status Update (2026-11-10)

- **Gate `G2` Local Codebase & Governance Decision:** **PASSED Locally** (`11/11` JS suites, `55/55` .NET tests, `0` build warnings/errors). See [`02_phase2_implementation_report.md`](./02_phase2_implementation_report.md), [`02_phase2_security_verification.md`](./02_phase2_security_verification.md), [`02_phase2_test_results.md`](./02_phase2_test_results.md), and [`02_phase2_readiness_audit.md`](./02_phase2_readiness_audit.md).
- **Phase 3 Entry Criteria (`SEC-07` Execution Isolation):**
  1. Provision credential-free, non-root container / CI sandbox consuming GCAC isolated worktree patches.
  2. Enforce network egress blocking outside approved internal package registries (`--network=none` for test verification).
  3. Complete live interactive VS Code Extension Development Host smoke test prior to release packaging.

